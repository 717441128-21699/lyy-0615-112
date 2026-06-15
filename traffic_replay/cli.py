import asyncio
import click
import logging
import sys
import json
import time
from typing import Optional

from .config import ConfigManager
from .recorder import Recorder, RecordingMode
from .player import Player, PlaybackMode
from .storage import RequestStorage
from .masking import MaskingEngine
from .context import ContextManager


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=log_format,
    )
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)


@click.group()
@click.option("--config", "-c", default="config.yaml", help="Path to config file")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.pass_context
def cli(ctx: click.Context, config: str, verbose: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["verbose"] = verbose

    config_manager = ConfigManager(config)
    try:
        app_config = config_manager.load()
    except Exception:
        app_config = config_manager.create_default_config()
        config_manager.save()

    ctx.obj["config_manager"] = config_manager
    ctx.obj["config"] = app_config

    if verbose:
        app_config.log_level = "DEBUG"

    setup_logging(app_config.log_level, app_config.log_file)


@cli.command()
@click.option("--target", "-t", help="Target service URL to proxy to")
@click.option("--port", "-p", type=int, help="Listen port")
@click.option("--host", "-h", help="Listen host")
@click.option("--mode", type=click.Choice(["tap", "proxy", "middleware", "sidecar"]),
              help="Recording mode")
@click.option("--sample-rate", type=float, help="Sample rate (0.0-1.0)")
@click.pass_context
def record(
    ctx: click.Context,
    target: Optional[str],
    port: Optional[int],
    host: Optional[str],
    mode: Optional[str],
    sample_rate: Optional[float],
) -> None:
    app_config = ctx.obj["config"]
    config_manager = ctx.obj["config_manager"]

    if target:
        app_config.recorder.target_url = target
    if port:
        app_config.recorder.listen_port = port
    if host:
        app_config.recorder.listen_host = host
    if mode:
        app_config.recorder.mode = mode
    if sample_rate is not None:
        app_config.recorder.sample_rate = sample_rate

    mask_rules = config_manager.get_mask_rules()
    masking_engine = MaskingEngine(
        rules=mask_rules,
        preserve_structure=app_config.masking.preserve_structure,
        default_mask_char=app_config.masking.default_mask_char,
        hash_algorithm=app_config.masking.hash_algorithm,
        hash_salt=app_config.masking.hash_salt,
        locale=app_config.masking.locale,
    ) if app_config.masking.enabled else None

    storage = RequestStorage(
        base_dir=app_config.storage.base_dir,
        batch_size=app_config.storage.batch_size,
        flush_interval_ms=app_config.storage.flush_interval_ms,
        compress=app_config.storage.compress,
        max_memory_mb=app_config.storage.max_memory_mb,
    )

    recorder = Recorder(
        target_url=app_config.recorder.target_url,
        storage=storage,
        masking_engine=masking_engine,
        mode=RecordingMode(app_config.recorder.mode),
        listen_host=app_config.recorder.listen_host,
        listen_port=app_config.recorder.listen_port,
        sample_rate=app_config.recorder.sample_rate,
        capture_response=app_config.recorder.capture_response,
        max_body_size=app_config.recorder.max_body_size,
        timeout_ms=app_config.recorder.timeout_ms,
        num_workers=app_config.recorder.num_workers,
    )

    click.echo(f"Starting recorder in {app_config.recorder.mode} mode...")
    click.echo(f"Listening on {app_config.recorder.listen_host}:{app_config.recorder.listen_port}")
    click.echo(f"Proxying to {app_config.recorder.target_url}")
    click.echo("Press Ctrl+C to stop recording")

    try:
        asyncio.run(run_recorder(recorder))
    except KeyboardInterrupt:
        click.echo("\nStopping recorder...")
        asyncio.run(recorder.stop())
        click.echo("Recorder stopped")


async def run_recorder(recorder: Recorder) -> None:
    await recorder.start()
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        await recorder.stop()


@cli.command()
@click.option("--target", "-t", help="Target service URL to replay to")
@click.option("--session", "-s", help="Recording session ID to replay")
@click.option("--mode", type=click.Choice(["precise", "fixed_qps", "max_throughput", "stress"]),
              help="Playback mode")
@click.option("--speed", type=float, help="Playback speed factor")
@click.option("--concurrency", type=int, help="Max concurrent requests")
@click.option("--loop", "loop_count", type=int, default=1, help="Number of loops to replay")
@click.option("--report", is_flag=True, help="Generate detailed report")
@click.pass_context
def replay(
    ctx: click.Context,
    target: Optional[str],
    session: Optional[str],
    mode: Optional[str],
    speed: Optional[float],
    concurrency: Optional[int],
    loop_count: int,
    report: bool,
) -> None:
    app_config = ctx.obj["config"]
    config_manager = ctx.obj["config_manager"]

    if target:
        app_config.player.target_url = target
    if mode:
        app_config.player.mode = mode
    if speed:
        app_config.player.speed_factor = speed
    if concurrency:
        app_config.player.max_concurrent = concurrency

    extraction_rules = config_manager.get_extraction_rules()
    context_manager = ContextManager(
        extraction_rules=extraction_rules,
        env_mappings=app_config.context.env_mappings,
        enable_auto_extract=app_config.context.enable_auto_extract,
        variable_ttl_seconds=app_config.context.variable_ttl_seconds,
    ) if app_config.context.enabled else None

    mask_rules = config_manager.get_mask_rules()
    masking_engine = MaskingEngine(
        rules=mask_rules,
        preserve_structure=app_config.masking.preserve_structure,
    ) if app_config.masking.enabled else None

    storage = RequestStorage(
        base_dir=app_config.storage.base_dir,
    )

    if not session:
        sessions = storage.list_sessions()
        if not sessions:
            click.echo("No recording sessions found")
            return
        session = sessions[-1]
        click.echo(f"Using latest session: {session}")

    player = Player(
        target_url=app_config.player.target_url,
        storage=storage,
        context_manager=context_manager,
        masking_engine=masking_engine,
        mode=PlaybackMode(app_config.player.mode),
        speed_factor=app_config.player.speed_factor,
        max_concurrent=app_config.player.max_concurrent,
        timeout_ms=app_config.player.timeout_ms,
        retry_count=app_config.player.retry_count,
        retry_delay_ms=app_config.player.retry_delay_ms,
        ignore_ssl=app_config.player.ignore_ssl,
    )

    click.echo(f"Starting playback in {app_config.player.mode} mode...")
    click.echo(f"Target: {app_config.player.target_url}")
    click.echo(f"Session: {session}")
    click.echo(f"Speed: {app_config.player.speed_factor}x")
    click.echo(f"Concurrency: {app_config.player.max_concurrent}")

    async def run_playback():
        await player.start()
        result = await player.play(session_id=session, loop_count=loop_count)
        await player.stop()
        return result

    try:
        result = asyncio.run(run_playback())
    except KeyboardInterrupt:
        click.echo("\nPlayback interrupted")
        asyncio.run(player.stop())
        return

    click.echo("\n=== Playback Report ===")
    click.echo(f"Total requests: {result.total_requests}")
    click.echo(f"Successful: {result.successful_requests}")
    click.echo(f"Failed: {result.failed_requests}")
    success_rate = (
        result.successful_requests / result.total_requests * 100
        if result.total_requests > 0 else 0
    )
    click.echo(f"Success rate: {success_rate:.2f}%")
    click.echo(f"\nLatency (ms):")
    click.echo(f"  Avg: {result.avg_latency_ms:.2f}")
    click.echo(f"  P95: {result.p95_latency_ms:.2f}")
    click.echo(f"  P99: {result.p99_latency_ms:.2f}")
    click.echo(f"  Min: {result.min_latency_ms:.2f}")
    click.echo(f"  Max: {result.max_latency_ms:.2f}")

    if result.timing_deviation_ms:
        import statistics
        avg_deviation = statistics.mean(result.timing_deviation_ms)
        click.echo(f"\nTiming deviation (ms):")
        click.echo(f"  Avg: {avg_deviation:.2f}")

    if result.errors:
        click.echo(f"\nErrors ({len(result.errors)}):")
        for i, error in enumerate(result.errors[:10]):
            click.echo(f"  {i+1}. {error.get('method')} {error.get('url')}: {error.get('error')}")
        if len(result.errors) > 10:
            click.echo(f"  ... and {len(result.errors) - 10} more")

    if report:
        report_file = f"report_{session}_{int(time.time())}.json"
        with open(report_file, "w", encoding="utf-8") as f:
            import dataclasses
            json.dump(dataclasses.asdict(result), f, indent=2, ensure_ascii=False)
        click.echo(f"\nDetailed report saved to: {report_file}")


@cli.command("list")
@click.option("--limit", type=int, default=10, help="Limit number of sessions")
@click.pass_context
def list_sessions(ctx: click.Context, limit: int) -> None:
    app_config = ctx.obj["config"]
    storage = RequestStorage(base_dir=app_config.storage.base_dir)
    sessions = storage.list_sessions()

    if not sessions:
        click.echo("No recording sessions found")
        return

    click.echo(f"Found {len(sessions)} recording sessions:\n")
    for session in reversed(sessions[-limit:]):
        info = asyncio.run(storage.get_session_info(session))
        if info:
            click.echo(f"  {session}")
            click.echo(f"    Created: {info.get('created_at')}")
            click.echo(f"    Records: {info.get('total_records')}")
            click.echo(f"    Compressed: {info.get('compression')}")
        else:
            click.echo(f"  {session}")
        click.echo()


@cli.command()
@click.option("--force", is_flag=True, help="Overwrite existing config")
@click.pass_context
def init(ctx: click.Context, force: bool) -> None:
    config_manager = ctx.obj["config_manager"]
    config_path = ctx.obj["config_path"]

    import os
    if os.path.exists(config_path) and not force:
        click.echo(f"Config file already exists: {config_path}")
        click.echo("Use --force to overwrite")
        return

    config = config_manager.create_default_config()
    config_manager.save(config)
    click.echo(f"Default config created at: {config_path}")


@cli.command()
@click.argument("session")
@click.option("--output", "-o", help="Output file for export")
@click.option("--format", "fmt", type=click.Choice(["json", "jsonl", "har"]), default="json",
              help="Export format")
@click.pass_context
def export(ctx: click.Context, session: str, output: Optional[str], fmt: str) -> None:
    app_config = ctx.obj["config"]
    storage = RequestStorage(base_dir=app_config.storage.base_dir)

    records = []
    async def load_records():
        async for record in storage.load_records(session_id=session):
            records.append(record.to_dict())

    asyncio.run(load_records())

    if not records:
        click.echo(f"No records found for session: {session}")
        return

    output = output or f"export_{session}.{fmt}"

    if fmt == "json":
        with open(output, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)
    elif fmt == "jsonl":
        with open(output, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
    elif fmt == "har":
        entries = []
        for record in records:
            req_body = record.get("body")
            if req_body is None:
                req_body_size = 0
                req_body_b64 = ""
            elif isinstance(req_body, bytes):
                req_body_size = len(req_body)
                import base64
                req_body_b64 = base64.b64encode(req_body).decode("ascii")
            else:
                req_body_str = str(req_body)
                req_body_size = len(req_body_str.encode("utf-8"))
                import base64
                req_body_b64 = base64.b64encode(req_body_str.encode("utf-8")).decode("ascii")

            resp_body = record.get("response_body")
            if resp_body is None:
                resp_body_size = 0
                resp_body_b64 = ""
            elif isinstance(resp_body, bytes):
                resp_body_size = len(resp_body)
                import base64
                resp_body_b64 = base64.b64encode(resp_body).decode("ascii")
            else:
                resp_body_str = str(resp_body)
                resp_body_size = len(resp_body_str.encode("utf-8"))
                import base64
                resp_body_b64 = base64.b64encode(resp_body_str.encode("utf-8")).decode("ascii")

            query_list = []
            try:
                from urllib.parse import urlparse, parse_qs
                parsed_url = urlparse(record["url"])
                qs = parse_qs(parsed_url.query)
                for qk, qvs in qs.items():
                    for qv in qvs:
                        query_list.append({"name": qk, "value": qv})
            except Exception:
                pass

            try:
                from datetime import datetime
                ts = record.get("timestamp", 0)
                if isinstance(ts, (int, float)):
                    started = datetime.fromtimestamp(ts).isoformat(timespec="milliseconds") + "Z"
                else:
                    started = str(ts)
            except Exception:
                started = str(record.get("timestamp", ""))

            entry = {
                "startedDateTime": started,
                "time": float(record.get("duration_ms", 0) or 0),
                "request": {
                    "method": record["method"],
                    "url": record["url"],
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": str(v)} for k, v in record["headers"].items()],
                    "queryString": query_list,
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": req_body_size,
                },
                "response": {
                    "status": int(record.get("response_status", 0) or 0),
                    "statusText": "OK" if 200 <= int(record.get("response_status", 0) or 0) < 400 else "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": str(v)} for k, v in record.get("response_headers", {}).items()],
                    "cookies": [],
                    "content": {
                        "size": resp_body_size,
                        "mimeType": record.get("response_headers", {}).get("Content-Type", "application/octet-stream"),
                        "text": resp_body_b64,
                        "encoding": "base64",
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": resp_body_size,
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": float(record.get("upstream_latency_ms", record.get("duration_ms", 0)) or 0),
                    "receive": 0,
                },
            }
            entries.append(entry)

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "traffic-replay", "version": "0.1.0"},
                "pages": [],
                "entries": entries,
            }
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(har, f, indent=2, ensure_ascii=False)

    click.echo(f"Exported {len(records)} records to: {output}")


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    app_config = ctx.obj["config"]
    click.echo("=== Traffic Replay Configuration ===")
    click.echo(f"\nRecorder:")
    click.echo(f"  Target: {app_config.recorder.target_url}")
    click.echo(f"  Listen: {app_config.recorder.listen_host}:{app_config.recorder.listen_port}")
    click.echo(f"  Mode: {app_config.recorder.mode}")
    click.echo(f"  Sample rate: {app_config.recorder.sample_rate}")

    click.echo(f"\nPlayer:")
    click.echo(f"  Target: {app_config.player.target_url}")
    click.echo(f"  Mode: {app_config.player.mode}")
    click.echo(f"  Speed: {app_config.player.speed_factor}x")
    click.echo(f"  Concurrency: {app_config.player.max_concurrent}")

    click.echo(f"\nStorage:")
    click.echo(f"  Directory: {app_config.storage.base_dir}")
    click.echo(f"  Compression: {app_config.storage.compress}")

    click.echo(f"\nMasking: {'enabled' if app_config.masking.enabled else 'disabled'}")
    click.echo(f"Context: {'enabled' if app_config.context.enabled else 'disabled'}")


def main() -> None:
    try:
        cli(obj={})
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
