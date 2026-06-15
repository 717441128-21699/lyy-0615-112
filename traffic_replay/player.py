import asyncio
import time
import logging
import re
import statistics
from typing import Optional, Dict, Any, List, Callable, Tuple
from enum import Enum
from urllib.parse import urlparse, urlunparse
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from .models import RequestRecord, SessionContext, PlaybackReport
from .storage import RequestStorage
from .context import ContextManager
from .masking import MaskingEngine

logger = logging.getLogger(__name__)


class PlaybackMode(Enum):
    PRECISE_TIMING = "precise"
    FIXED_QPS = "fixed_qps"
    MAX_THROUGHPUT = "max_throughput"
    STRESS_TEST = "stress"


class Player:
    def __init__(
        self,
        target_url: str,
        storage: Optional[RequestStorage] = None,
        context_manager: Optional[ContextManager] = None,
        masking_engine: Optional[MaskingEngine] = None,
        mode: PlaybackMode = PlaybackMode.PRECISE_TIMING,
        speed_factor: float = 1.0,
        max_concurrent: int = 100,
        timeout_ms: int = 30000,
        retry_count: int = 0,
        retry_delay_ms: int = 1000,
        ignore_ssl: bool = False,
        request_modifier: Optional[Callable[[RequestRecord, Dict[str, Any]], RequestRecord]] = None,
        response_handler: Optional[Callable[[RequestRecord, int, Dict[str, str], bytes], None]] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.storage = storage or RequestStorage()
        self.context_manager = context_manager
        self.masking_engine = masking_engine
        self.mode = mode
        self.speed_factor = speed_factor
        self.max_concurrent = max_concurrent
        self.timeout = ClientTimeout(total=timeout_ms / 1000)
        self.retry_count = retry_count
        self.retry_delay = retry_delay_ms / 1000
        self.ignore_ssl = ignore_ssl
        self.request_modifier = request_modifier
        self.response_handler = response_handler

        self._client_session: Optional[ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._running = False
        self._results: List[Dict[str, Any]] = []
        self._errors: List[Dict[str, Any]] = []
        self._timing_deviations: List[float] = []
        self._stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "latencies": [],
        }

    async def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        connector = TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=self.max_concurrent,
            ttl_dns_cache=300,
            use_dns_cache=True,
            verify_ssl=not self.ignore_ssl,
        )
        self._client_session = ClientSession(
            connector=connector,
            timeout=self.timeout,
            auto_decompress=False,
        )

        logger.info(f"Player started in {self.mode.value} mode, target: {self.target_url}")

    async def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        if self._client_session:
            await self._client_session.close()

        logger.info(f"Player stopped. {self._stats['success']}/{self._stats['total']} requests successful")

    async def play(
        self,
        session_id: Optional[str] = None,
        records: Optional[List[RequestRecord]] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        filter_tags: Optional[Dict[str, str]] = None,
        loop_count: int = 1,
    ) -> PlaybackReport:
        await self.start()

        if records is None:
            records = []
            async for record in self.storage.load_records(
                session_id=session_id,
                start_time=start_time,
                end_time=end_time,
                filter_tags=filter_tags,
            ):
                records.append(record)

        if not records:
            logger.warning("No records to play")
            await self.stop()
            return self._generate_report([])

        records.sort(key=lambda r: r.timestamp)

        logger.info(f"Loaded {len(records)} records for playback")

        all_results = []
        for loop in range(loop_count):
            if loop_count > 1:
                logger.info(f"Starting playback loop {loop + 1}/{loop_count}")

            if self.mode == PlaybackMode.PRECISE_TIMING:
                results = await self._play_precise_timing(records)
            elif self.mode == PlaybackMode.FIXED_QPS:
                results = await self._play_fixed_qps(records)
            elif self.mode == PlaybackMode.MAX_THROUGHPUT:
                results = await self._play_max_throughput(records)
            elif self.mode == PlaybackMode.STRESS_TEST:
                results = await self._play_stress_test(records)
            else:
                results = await self._play_precise_timing(records)

            all_results.extend(results)

        await self.stop()
        return self._generate_report(all_results)

    def _build_dependency_graph(
        self, records: List[RequestRecord]
    ) -> Dict[str, List[str]]:
        if not self.context_manager:
            return {r.id: [] for r in records}

        dependencies: Dict[str, List[str]] = {}
        var_producers: Dict[str, str] = {}

        auth_header_names = {
            "authorization", "x-auth-token", "x-access-token", "x-api-key",
            "token", "authentication", "auth", "cookie", "set-cookie",
            "session", "session-id", "sessionid",
        }

        auth_related_keywords = [
            "login", "signin", "sign_in", "auth", "authenticate",
            "token", "issue_token", "gettoken", "get_token",
            "oauth", "connect/token", "authorize",
        ]

        login_producer_id: Optional[str] = None

        for record in records:
            deps = set()

            if record.body:
                try:
                    body_str = record.body.decode("utf-8") if isinstance(record.body, bytes) else record.body
                    placeholders = re.findall(r'\{\{(\w+)\}\}', body_str)
                    for var in placeholders:
                        if var in var_producers:
                            deps.add(var_producers[var])
                except (UnicodeDecodeError, AttributeError):
                    pass

            has_auth_header = False
            for h_key, h_value in record.headers.items():
                if isinstance(h_value, str):
                    placeholders = re.findall(r'\{\{(\w+)\}\}', h_value)
                    for var in placeholders:
                        if var in var_producers:
                            deps.add(var_producers[var])

                    h_lower = h_key.lower()
                    if h_lower in auth_header_names:
                        if h_value and len(h_value) > 4:
                            has_auth_header = True

            if record.url:
                placeholders = re.findall(r'\{\{(\w+)\}\}', record.url)
                for var in placeholders:
                    if var in var_producers:
                        deps.add(var_producers[var])

                from urllib.parse import urlparse
                try:
                    parsed_url = urlparse(record.url)
                    path_lower = parsed_url.path.lower()
                except Exception:
                    path_lower = record.url.split("?")[0].lower()

                is_login_request = any(kw in path_lower for kw in auth_related_keywords)
                if is_login_request and hasattr(record, 'method') and record.method != "GET":
                    login_producer_id = record.id
                elif is_login_request and record.method == "GET":
                    if not login_producer_id:
                        login_producer_id = record.id
                elif has_auth_header and login_producer_id and login_producer_id != record.id:
                    deps.add(login_producer_id)

            dependencies[record.id] = list(deps)

            for rule in self.context_manager.extraction_rules:
                var_producers[rule.variable_name] = record.id

            if self.context_manager.enable_auto_extract:
                auto_vars = [
                    "auto_token", "auto_access_token", "auto_id", "auto_uuid",
                    "auto_x_auth_token", "auto_authorization", "auto_user_id",
                ]
                for v in auto_vars:
                    var_producers[v] = record.id

        return dependencies

    async def _play_precise_timing(self, records: List[RequestRecord]) -> List[Dict[str, Any]]:
        if not records:
            return []

        base_timestamp = records[0].timestamp
        start_mono = time.monotonic()

        if self.context_manager:
            global_session_id = "playback_global_session"
            if not self.context_manager.get_context(global_session_id):
                self.context_manager.create_context(
                    session_id=global_session_id,
                    recording_env="recording",
                    playback_env="playback",
                )
            for record in records:
                if not record.session_id:
                    record.session_id = global_session_id

        dep_graph = self._build_dependency_graph(records)
        has_deps = any(deps for deps in dep_graph.values())

        if not has_deps:
            return await self._play_precise_no_deps(records, base_timestamp, start_mono)
        else:
            return await self._play_precise_with_deps(records, dep_graph, base_timestamp, start_mono)

    async def _play_precise_no_deps(
        self, records: List[RequestRecord], base_timestamp: float, start_mono: float
    ) -> List[Dict[str, Any]]:
        tasks = []
        scheduled_count = 0

        for record in records:
            if not self._running:
                break

            relative_offset = (record.timestamp - base_timestamp) / self.speed_factor
            target_mono = start_mono + relative_offset

            current_mono = time.monotonic()
            sleep_time = target_mono - current_mono

            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            actual_mono = time.monotonic()
            timing_deviation = (actual_mono - target_mono) * 1000
            self._timing_deviations.append(timing_deviation)

            task = asyncio.create_task(self._execute_request(record, timing_deviation))
            tasks.append(task)
            scheduled_count += 1

            if scheduled_count % 1000 == 0:
                logger.debug(f"Scheduled {scheduled_count}/{len(records)} requests")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _play_precise_with_deps(
        self,
        records: List[RequestRecord],
        dep_graph: Dict[str, List[str]],
        base_timestamp: float,
        start_mono: float,
    ) -> List[Dict[str, Any]]:
        results_by_id: Dict[str, Dict[str, Any]] = {}
        completed_events: Dict[str, asyncio.Event] = {
            r.id: asyncio.Event() for r in records
        }
        record_by_id: Dict[str, RequestRecord] = {r.id: r for r in records}
        tasks: Dict[str, asyncio.Task] = {}

        async def schedule_with_deps(record: RequestRecord):
            record_id = record.id
            deps = dep_graph.get(record_id, [])

            for dep_id in deps:
                if dep_id in completed_events:
                    await completed_events[dep_id].wait()

            relative_offset = (record.timestamp - base_timestamp) / self.speed_factor
            target_mono = start_mono + relative_offset

            current_mono = time.monotonic()
            sleep_time = target_mono - current_mono
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            actual_mono = time.monotonic()
            timing_deviation = (actual_mono - target_mono) * 1000
            self._timing_deviations.append(timing_deviation)

            result = await self._execute_request(record, timing_deviation)
            results_by_id[record_id] = result
            completed_events[record_id].set()
            return result

        for record in records:
            if not self._running:
                break
            task = asyncio.create_task(schedule_with_deps(record))
            tasks[record.id] = task

        await asyncio.gather(*tasks.values(), return_exceptions=True)

        results = []
        for record in records:
            if record.id in results_by_id:
                results.append(results_by_id[record.id])
        return results

    async def _play_fixed_qps(self, records: List[RequestRecord], qps: int = 100) -> List[Dict[str, Any]]:
        if not records:
            return []

        interval = 1.0 / qps
        tasks = []

        for i, record in enumerate(records):
            if not self._running:
                break

            await asyncio.sleep(interval)
            task = asyncio.create_task(self._execute_request(record, 0))
            tasks.append(task)

            if i % 1000 == 0:
                logger.debug(f"Scheduled {i}/{len(records)} requests at {qps} QPS")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _play_max_throughput(self, records: List[RequestRecord]) -> List[Dict[str, Any]]:
        if not records:
            return []

        tasks = []
        for i, record in enumerate(records):
            if not self._running:
                break

            task = asyncio.create_task(self._execute_request(record, 0))
            tasks.append(task)

            if i % 1000 == 0:
                logger.debug(f"Scheduled {i}/{len(records)} requests")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _play_stress_test(self, records: List[RequestRecord]) -> List[Dict[str, Any]]:
        if not records:
            return []

        base_timestamp = records[0].timestamp
        start_mono = time.monotonic()

        tasks = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def bounded_execute(record, timing_deviation):
            async with semaphore:
                return await self._execute_request(record, timing_deviation)

        for record in records:
            if not self._running:
                break

            relative_offset = (record.timestamp - base_timestamp) / self.speed_factor
            target_mono = start_mono + relative_offset

            current_mono = time.monotonic()
            sleep_time = target_mono - current_mono

            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            actual_mono = time.monotonic()
            timing_deviation = (actual_mono - target_mono) * 1000

            task = asyncio.create_task(bounded_execute(record, timing_deviation))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _execute_request(
        self, record: RequestRecord, timing_deviation: float
    ) -> Dict[str, Any]:
        self._stats["total"] += 1
        result = {
            "record_id": record.id,
            "timing_deviation_ms": timing_deviation,
            "start_time": time.time(),
        }

        session_context = None
        if self.context_manager and record.session_id:
            session_context = self.context_manager.get_context(record.session_id)

        try:
            request_record = record
            if self.context_manager and session_context:
                request_record = await self.context_manager.apply_context(
                    record, session_context
                )

            if self.request_modifier:
                request_record = self.request_modifier(request_record, session_context)

            url = self._rewrite_url(request_record.url)
            method = request_record.method

            headers = {
                k: v for k, v in request_record.headers.items()
                if k.lower() not in ("host", "content-length", "connection", "accept-encoding")
            }
            headers["Host"] = self._extract_host(self.target_url)

            if session_context and session_context.variables:
                for key, value in session_context.variables.items():
                    placeholder = f"{{{{{key}}}}}"
                    if isinstance(value, str):
                        for hk, hv in headers.items():
                            if placeholder in str(hv):
                                headers[hk] = hv.replace(placeholder, value)

            body = request_record.body
            if isinstance(body, bytes) and session_context and session_context.variables:
                try:
                    body_str = body.decode("utf-8")
                    for key, value in session_context.variables.items():
                        placeholder = f"{{{{{key}}}}}"
                        if isinstance(value, str) and placeholder in body_str:
                            body_str = body_str.replace(placeholder, value)
                    body = body_str.encode("utf-8")
                except Exception:
                    pass

            for attempt in range(self.retry_count + 1):
                try:
                    async with self._semaphore:
                        start_time = time.perf_counter()

                        async with self._client_session.request(
                            method=method,
                            url=url,
                            headers=headers,
                            data=body,
                            timeout=self.timeout,
                        ) as resp:
                            resp_body = await resp.read()
                            latency_ms = (time.perf_counter() - start_time) * 1000

                            result.update({
                                "status": resp.status,
                                "latency_ms": latency_ms,
                                "success": 200 <= resp.status < 500,
                                "attempt": attempt + 1,
                            })

                            if self.context_manager and session_context:
                                await self.context_manager.extract_variables(
                                    record, resp.status, dict(resp.headers), resp_body, session_context
                                )

                            if self.response_handler:
                                self.response_handler(record, resp.status, dict(resp.headers), resp_body)

                            if 200 <= resp.status < 500:
                                self._stats["success"] += 1
                                self._stats["latencies"].append(latency_ms)
                                return result
                            else:
                                if attempt < self.retry_count:
                                    await asyncio.sleep(self.retry_delay)
                                    continue
                                raise Exception(f"HTTP {resp.status}")

                except Exception as e:
                    if attempt == self.retry_count:
                        raise
                    await asyncio.sleep(self.retry_delay)

        except Exception as e:
            self._stats["failed"] += 1
            result.update({
                "success": False,
                "error": str(e),
                "latency_ms": result.get("latency_ms", 0),
            })
            self._errors.append({
                "record_id": record.id,
                "url": record.url,
                "method": record.method,
                "error": str(e),
            })
            logger.warning(f"Request failed: {record.method} {record.url} - {e}")
            return result

    def _rewrite_url(self, original_url: str) -> str:
        parsed = urlparse(original_url)
        target_parsed = urlparse(self.target_url)

        new_url = urlunparse((
            target_parsed.scheme,
            target_parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))
        return new_url

    def _extract_host(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.hostname or ""

    def _generate_report(self, results: List[Dict[str, Any]]) -> PlaybackReport:
        latencies = [r.get("latency_ms", 0) for r in results if r.get("success")]
        deviations = [r.get("timing_deviation_ms", 0) for r in results]

        if not latencies:
            latencies = [0]

        latencies.sort()
        total = len(latencies)

        return PlaybackReport(
            total_requests=self._stats["total"],
            successful_requests=self._stats["success"],
            failed_requests=self._stats["failed"],
            start_time=results[0]["start_time"] if results else 0,
            end_time=results[-1]["start_time"] + (results[-1].get("latency_ms", 0) / 1000) if results else 0,
            avg_latency_ms=statistics.mean(latencies) if latencies else 0,
            p95_latency_ms=latencies[int(total * 0.95)] if total > 0 else 0,
            p99_latency_ms=latencies[int(total * 0.99)] if total > 0 else 0,
            max_latency_ms=max(latencies) if latencies else 0,
            min_latency_ms=min(latencies) if latencies else 0,
            timing_deviation_ms=deviations,
            errors=self._errors.copy(),
        )

    async def play_single(self, record: RequestRecord) -> Dict[str, Any]:
        await self.start()
        result = await self._execute_request(record, 0)
        return result

    def get_stats(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "mode": self.mode.value,
            "total": self._stats["total"],
            "success": self._stats["success"],
            "failed": self._stats["failed"],
            "success_rate": (
                self._stats["success"] / self._stats["total"] * 100
                if self._stats["total"] > 0 else 0
            ),
        }
