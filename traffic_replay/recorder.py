import asyncio
import time
import uuid
import logging
from typing import Optional, Dict, Any, Callable, List, Tuple
from enum import Enum
from aiohttp import web, ClientSession, ClientTimeout, TCPConnector
import socket

from .models import RequestRecord
from .storage import RequestStorage
from .masking import MaskingEngine

logger = logging.getLogger(__name__)


class RecordingMode(Enum):
    TAP = "tap"
    PROXY = "proxy"
    MIDDLEWARE = "middleware"
    SIDECAR = "sidecar"


class Recorder:
    def __init__(
        self,
        target_url: str,
        storage: Optional[RequestStorage] = None,
        masking_engine: Optional[MaskingEngine] = None,
        mode: RecordingMode = RecordingMode.TAP,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        sample_rate: float = 1.0,
        capture_response: bool = True,
        max_body_size: int = 10 * 1024 * 1024,
        timeout_ms: int = 30000,
        num_workers: int = 10,
    ):
        self.target_url = target_url.rstrip("/")
        self.storage = storage or RequestStorage()
        self.masking_engine = masking_engine
        self.mode = mode
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.sample_rate = sample_rate
        self.capture_response = capture_response
        self.max_body_size = max_body_size
        self.timeout = ClientTimeout(total=timeout_ms / 1000)
        self.num_workers = num_workers

        self._app: Optional[web.Application] = None
        self._client_session: Optional[ClientSession] = None
        self._record_queue: Optional[asyncio.Queue] = None
        self._worker_tasks: List[asyncio.Task] = []
        self._running = False
        self._request_count = 0
        self._skipped_count = 0

    async def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._record_queue = asyncio.Queue(maxsize=10000)

        connector = TCPConnector(
            limit=1000,
            limit_per_host=100,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        self._client_session = ClientSession(
            connector=connector,
            timeout=self.timeout,
            auto_decompress=False,
        )

        for i in range(self.num_workers):
            task = asyncio.create_task(self._recording_worker(i))
            self._worker_tasks.append(task)

        await self.storage.start()

        self._app = web.Application(middlewares=[self._recording_middleware])
        self._app.router.add_route("*", "/{path:.*}", self._handle_request)

        runner = web.AppRunner(self._app)
        await runner.setup()
        site = web.TCPSite(runner, self.listen_host, self.listen_port)
        await site.start()

        logger.info(
            f"Recorder started in {self.mode.value} mode on "
            f"{self.listen_host}:{self.listen_port} -> {self.target_url}"
        )

    async def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        if self._client_session:
            await self._client_session.close()

        for task in self._worker_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        await self.storage.stop()

        logger.info(
            f"Recorder stopped. Recorded: {self._request_count}, "
            f"Skipped: {self._skipped_count}"
        )

    @web.middleware
    async def _recording_middleware(self, request: web.Request, handler):
        start_time = time.perf_counter()
        response = await handler(request)
        request["duration_ms"] = (time.perf_counter() - start_time) * 1000
        return response

    async def _handle_request(self, request: web.Request) -> web.Response:
        import random
        if random.random() > self.sample_rate:
            self._skipped_count += 1
            return await self._proxy_request(request)

        self._request_count += 1

        record = RequestRecord(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
            session_id=request.headers.get("X-Session-Id"),
            trace_id=request.headers.get("X-Trace-Id", request.headers.get("X-Request-Id")),
        )

        try:
            body = await request.read()
            if len(body) <= self.max_body_size:
                record.body = body
            else:
                record.tags["body_truncated"] = "true"
                record.body = body[:self.max_body_size]
        except Exception as e:
            logger.warning(f"Failed to read request body: {e}")

        return await self._proxy_request(request, record, body=record.body)

    async def _proxy_request(
        self, request: web.Request, record: Optional[RequestRecord] = None,
        body: Optional[bytes] = None,
    ) -> web.Response:
        path = request.match_info.get("path", "")
        target_url = f"{self.target_url}/{path}"

        if request.query_string:
            target_url += f"?{request.query_string}"

        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "content-length", "connection")}
        headers["Host"] = self._extract_host(self.target_url)

        if body is None and request.method in ("POST", "PUT", "PATCH"):
            try:
                body = await request.read()
            except Exception:
                body = None

        start_time = time.perf_counter()

        try:
            async with self._client_session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=body,
                timeout=self.timeout,
            ) as resp:
                resp_body = await resp.read()
                latency_ms = (time.perf_counter() - start_time) * 1000

                if record:
                    record.response_status = resp.status
                    record.response_headers = dict(resp.headers)
                    if len(resp_body) <= self.max_body_size:
                        record.response_body = resp_body
                    else:
                        record.tags["response_truncated"] = "true"
                        record.response_body = resp_body[:self.max_body_size]
                    record.upstream_latency_ms = latency_ms
                    record.duration_ms = request.get("duration_ms", latency_ms)

                    if self.masking_engine:
                        record = await self.masking_engine.mask_record(record)

                    if self._record_queue is not None:
                        if self.mode == RecordingMode.TAP and self._record_queue.full():
                            pass
                        elif not self._record_queue.full():
                            self._record_queue.put_nowait(record)
                        else:
                            asyncio.create_task(self.storage.append(record))
                    else:
                        asyncio.create_task(self.storage.append(record))

                return web.Response(
                    body=resp_body,
                    status=resp.status,
                    headers=dict(resp.headers),
                )
        except asyncio.TimeoutError:
            if record:
                record.response_status = 504
                record.tags["error"] = "timeout"
                if self._record_queue and not self._record_queue.full():
                    self._record_queue.put_nowait(record)
            return web.Response(status=504, text="Gateway Timeout")
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            if record:
                record.response_status = 502
                record.tags["error"] = str(e)
                if self._record_queue and not self._record_queue.full():
                    self._record_queue.put_nowait(record)
            return web.Response(status=502, text="Bad Gateway")

    async def _recording_worker(self, worker_id: int) -> None:
        logger.debug(f"Recording worker {worker_id} started")
        while self._running:
            try:
                record = await asyncio.wait_for(
                    self._record_queue.get(),
                    timeout=0.1,
                )
                await self.storage.append(record)
                self._record_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
        logger.debug(f"Recording worker {worker_id} stopped")

    def _extract_host(self, url: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or ""

    async def record_manual(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        response_status: int = 0,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[bytes] = None,
        session_id: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> RequestRecord:
        record = RequestRecord(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            method=method,
            url=url,
            headers=headers or {},
            body=body,
            response_status=response_status,
            response_headers=response_headers or {},
            response_body=response_body,
            session_id=session_id,
            tags=tags or {},
        )

        if self.masking_engine:
            record = await self.masking_engine.mask_record(record)

        await self.storage.append(record)
        return record

    def get_stats(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "mode": self.mode.value,
            "request_count": self._request_count,
            "skipped_count": self._skipped_count,
            "queue_size": self._record_queue.qsize() if self._record_queue else 0,
        }
