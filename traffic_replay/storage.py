import asyncio
import os
import json
import aiofiles
from typing import List, Optional, AsyncGenerator, Dict, Any
from collections import deque
from datetime import datetime
import gzip
import logging

from .models import RequestRecord, SessionContext

logger = logging.getLogger(__name__)


class RequestStorage:
    def __init__(
        self,
        base_dir: str = "./recordings",
        batch_size: int = 100,
        flush_interval_ms: int = 500,
        compress: bool = True,
        max_memory_mb: int = 100,
    ):
        self.base_dir = base_dir
        self.batch_size = batch_size
        self.flush_interval = flush_interval_ms / 1000.0
        self.compress = compress
        self.max_memory_bytes = max_memory_mb * 1024 * 1024

        self._buffer: deque = deque()
        self._buffer_size = 0
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._running = False
        self._current_file = None
        self._current_size = 0
        self._records_written = 0
        self._session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        self._init_dirs()

    def _init_dirs(self) -> None:
        os.makedirs(self.base_dir, exist_ok=True)
        self._session_dir = os.path.join(self.base_dir, self._session_id)
        os.makedirs(self._session_dir, exist_ok=True)
        self._current_file_path = os.path.join(
            self._session_dir,
            f"requests_0001.jsonl{'.gz' if self.compress else ''}",
        )

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info(f"Storage started, session: {self._session_id}")

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        if self._flush_task:
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        await self._flush(force=True)
        await self._write_session_metadata()
        logger.info(f"Storage stopped, {self._records_written} records written")

    async def append(self, record: RequestRecord) -> None:
        if not self._running:
            await self.start()

        record_json = record.to_json()
        record_size = len(record_json) + 1

        if self._buffer_size + record_size > self.max_memory_bytes:
            await self._flush(force=True)

        async with self._lock:
            self._buffer.append(record_json)
            self._buffer_size += record_size

        if len(self._buffer) >= self.batch_size:
            await self._flush()

    async def _flush_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.flush_interval)
                if self._buffer:
                    await self._flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Flush loop error: {e}")

    async def _flush(self, force: bool = False) -> None:
        if not self._buffer:
            return

        async with self._lock:
            batch = list(self._buffer)
            batch_size = self._buffer_size
            self._buffer.clear()
            self._buffer_size = 0

        try:
            data = "\n".join(batch) + "\n"

            if self.compress:
                data = gzip.compress(data.encode("utf-8"))
                async with aiofiles.open(self._current_file_path, "ab") as f:
                    await f.write(data)
            else:
                async with aiofiles.open(self._current_file_path, "a", encoding="utf-8") as f:
                    await f.write(data)

            self._records_written += len(batch)
            self._current_size += batch_size

            if self._current_size > 100 * 1024 * 1024:
                await self._rotate_file()

            logger.debug(f"Flushed {len(batch)} records")
        except Exception as e:
            logger.error(f"Flush error: {e}")
            async with self._lock:
                self._buffer.extendleft(reversed(batch))
                self._buffer_size += batch_size

    async def _rotate_file(self) -> None:
        file_num = int(self._current_file_path.split("_")[-1].split(".")[0])
        file_num += 1
        self._current_file_path = os.path.join(
            self._session_dir,
            f"requests_{file_num:04d}.jsonl{'.gz' if self.compress else ''}",
        )
        self._current_size = 0

    async def _write_session_metadata(self) -> None:
        metadata = {
            "session_id": self._session_id,
            "created_at": datetime.now().isoformat(),
            "total_records": self._records_written,
            "compression": self.compress,
        }
        meta_path = os.path.join(self._session_dir, "metadata.json")
        async with aiofiles.open(meta_path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(metadata, indent=2, ensure_ascii=False))

    async def load_records(
        self, session_id: Optional[str] = None, start_time: Optional[float] = None,
        end_time: Optional[float] = None, filter_tags: Optional[Dict[str, str]] = None
    ) -> AsyncGenerator[RequestRecord, None]:
        session_dir = os.path.join(self.base_dir, session_id) if session_id else self._session_dir

        if not os.path.exists(session_dir):
            raise FileNotFoundError(f"Session directory not found: {session_dir}")

        files = sorted([
            f for f in os.listdir(session_dir)
            if f.startswith("requests_") and (f.endswith(".jsonl") or f.endswith(".jsonl.gz"))
        ])

        for filename in files:
            filepath = os.path.join(session_dir, filename)
            try:
                if filename.endswith(".gz"):
                    async with aiofiles.open(filepath, "rb") as f:
                        compressed = await f.read()
                    content = gzip.decompress(compressed).decode("utf-8")
                    lines = content.split("\n")
                else:
                    async with aiofiles.open(filepath, "r", encoding="utf-8") as f:
                        lines = (await f.read()).split("\n")

                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        record = RequestRecord.from_json(line)

                        if start_time and record.timestamp < start_time:
                            continue
                        if end_time and record.timestamp > end_time:
                            continue
                        if filter_tags:
                            if not all(record.tags.get(k) == v for k, v in filter_tags.items()):
                                continue

                        yield record
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid record in {filename}: {line[:100]}")
                        continue
            except Exception as e:
                logger.error(f"Error reading {filename}: {e}")
                continue

    async def save_context(self, context: SessionContext) -> None:
        context_path = os.path.join(self._session_dir, f"context_{context.session_id}.json")
        async with aiofiles.open(context_path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(context.to_dict(), indent=2, ensure_ascii=False))

    async def load_context(self, context_id: str, session_id: Optional[str] = None) -> SessionContext:
        session_dir = os.path.join(self.base_dir, session_id) if session_id else self._session_dir
        context_path = os.path.join(session_dir, f"context_{context_id}.json")
        async with aiofiles.open(context_path, "r", encoding="utf-8") as f:
            data = json.loads(await f.read())
        return SessionContext.from_dict(data)

    def list_sessions(self) -> List[str]:
        if not os.path.exists(self.base_dir):
            return []
        return sorted([
            d for d in os.listdir(self.base_dir)
            if os.path.isdir(os.path.join(self.base_dir, d))
        ])

    async def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        meta_path = os.path.join(self.base_dir, session_id, "metadata.json")
        if not os.path.exists(meta_path):
            return None
        async with aiofiles.open(meta_path, "r", encoding="utf-8") as f:
            return json.loads(await f.read())
