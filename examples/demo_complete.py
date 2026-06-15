#!/usr/bin/env python3
import asyncio
import sys
import os
import time
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp import web

from traffic_replay import (
    Recorder, RecordingMode,
    Player, PlaybackMode,
    RequestStorage,
    MaskingEngine,
    ContextManager,
    RequestRecord,
    ExtractionRule,
    MaskRule,
)


async def mock_target_app():
    async def login(request):
        data = await request.json()
        username = data.get("username")
        if username == "test":
            token = f"auth_token_{int(time.time())}"
            return web.json_response({
                "code": 0,
                "message": "success",
                "data": {
                    "token": token,
                    "user_id": "user_12345",
                    "phone": "13800138000",
                    "email": "test@example.com",
                }
            })
        return web.json_response({"code": 401, "message": "unauthorized"}, status=401)

    async def get_user_info(request):
        auth = request.headers.get("X-Auth-Token", "")
        if auth.startswith("auth_token_"):
            return web.json_response({
                "code": 0,
                "data": {
                    "user_id": "user_12345",
                    "username": "test",
                    "phone": "138****8000",
                    "email": "t***@example.com",
                    "last_login": "2024-01-15 10:30:00",
                }
            })
        return web.json_response({"code": 401, "message": "unauthorized"}, status=401)

    async def update_user(request):
        auth = request.headers.get("X-Auth-Token", "")
        if not auth.startswith("auth_token_"):
            return web.json_response({"code": 401, "message": "unauthorized"}, status=401)

        data = await request.json()
        user_id = data.get("user_id")
        return web.json_response({
            "code": 0,
            "message": "updated",
            "data": {
                "user_id": user_id,
                "updated_at": time.time(),
            }
        })

    async def search(request):
        await asyncio.sleep(0.1)
        return web.json_response({
            "code": 0,
            "data": {
                "total": 100,
                "items": [
                    {"id": 1, "name": "item_1"},
                    {"id": 2, "name": "item_2"},
                    {"id": 3, "name": "item_3"},
                ]
            }
        })

    app = web.Application()
    app.router.add_post("/api/login", login)
    app.router.add_get("/api/user/info", get_user_info)
    app.router.add_post("/api/user/update", update_user)
    app.router.add_get("/api/search", search)
    return app


async def start_mock_server(port: int = 9000):
    app = await mock_target_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    print(f"Mock server started on http://127.0.0.1:{port}")
    return runner


async def generate_traffic(recorder_port: int = 8080):
    import aiohttp
    session = aiohttp.ClientSession()

    try:
        print("\n=== Generating traffic for recording ===")

        print("\n1. Login request...")
        async with session.post(
            f"http://127.0.0.1:{recorder_port}/api/login",
            json={
                "username": "test",
                "password": "my_secret_password",
                "phone": "13800138000",
                "email": "test@example.com",
                "id_card": "110101199001011234",
            }
        ) as resp:
            data = await resp.json()
            token = data["data"]["token"]
            print(f"   Login successful, token: {token[:20]}...")

        await asyncio.sleep(0.5)

        print("\n2. Get user info (with token)...")
        async with session.get(
            f"http://127.0.0.1:{recorder_port}/api/user/info",
            headers={"X-Auth-Token": token}
        ) as resp:
            data = await resp.json()
            print(f"   User info: {data['data']['username']}")

        await asyncio.sleep(0.3)

        print("\n3. Search request...")
        async with session.get(
            f"http://127.0.0.1:{recorder_port}/api/search",
            params={"q": "test", "page": 1}
        ) as resp:
            data = await resp.json()
            print(f"   Search results: {data['data']['total']} items")

        await asyncio.sleep(0.2)

        print("\n4. Update user profile...")
        async with session.post(
            f"http://127.0.0.1:{recorder_port}/api/user/update",
            headers={"X-Auth-Token": token},
            json={
                "user_id": "user_12345",
                "phone": "13900139000",
                "email": "new@example.com",
                "password": "new_secret_123",
            }
        ) as resp:
            data = await resp.json()
            print(f"   Update status: {data['code']}")

        await asyncio.sleep(0.4)

        print("\n5. Multiple search requests (to show timing)...")
        for i in range(5):
            async with session.get(
                f"http://127.0.0.1:{recorder_port}/api/search",
                params={"q": f"item_{i}"}
            ) as resp:
                await resp.json()
                print(f"   Search {i+1} completed")
            await asyncio.sleep(0.1)

        print("\n=== Traffic generation completed ===")

    finally:
        await session.close()


async def demo_recording():
    print("=" * 60)
    print("DEMO 1: Low-overhead Request Recording")
    print("=" * 60)

    mock_runner = await start_mock_server(9000)

    storage = RequestStorage(
        base_dir="./demo_recordings",
        batch_size=10,
        flush_interval_ms=200,
        compress=False,
        max_memory_mb=50,
    )

    mask_rules = [
        MaskRule(
            name="mask_password",
            selector="password",
            mask_type="hash",
            preserve_length=False,
            description="Hash all password fields",
        ),
        MaskRule(
            name="mask_phone",
            selector="phone",
            mask_type="mask",
            preserve_length=True,
            description="Mask phone numbers",
        ),
        MaskRule(
            name="mask_email",
            selector="email",
            mask_type="mask",
            preserve_length=True,
            description="Mask email addresses",
        ),
        MaskRule(
            name="mask_id_card",
            selector="id_card",
            mask_type="mask",
            preserve_length=True,
            description="Mask ID card numbers",
        ),
    ]

    masking_engine = MaskingEngine(
        rules=mask_rules,
        preserve_structure=True,
        default_mask_char="*",
    )

    recorder = Recorder(
        target_url="http://127.0.0.1:9000",
        storage=storage,
        masking_engine=masking_engine,
        mode=RecordingMode.TAP,
        listen_host="127.0.0.1",
        listen_port=8080,
        sample_rate=1.0,
        num_workers=4,
    )

    print("\nStarting recorder in TAP mode...")
    await recorder.start()
    print("Recorder started on http://127.0.0.1:8080")
    print("Key features:")
    print("  - TAP mode: recording does not block request processing")
    print("  - Async queue + batch write: minimal I/O overhead")
    print("  - Sampling rate: 100% (configurable 0.0-1.0)")
    print("  - Sensitive data masking: enabled")

    await generate_traffic(8080)

    await asyncio.sleep(1)
    print("\nStopping recorder...")
    session_id = storage._session_id
    await recorder.stop()
    await mock_runner.cleanup()

    print(f"\nRecording saved to session: {session_id}")
    print(f"Total requests recorded: {storage._records_written}")

    print("\nVerifying recorded data (with masking):")
    async for record in storage.load_records(session_id=session_id):
        if record.body:
            try:
                body = record.body.decode("utf-8") if isinstance(record.body, bytes) else record.body
                if "password" in body.lower() or "phone" in body.lower():
                    print(f"\n  {record.method} {record.url.split('/')[-1]}:")
                    print(f"    Body (masked): {body[:100]}...")
            except Exception:
                pass

    return session_id


async def demo_precise_playback(session_id: str):
    print("\n" + "=" * 60)
    print("DEMO 2: Precise Timing Playback")
    print("=" * 60)

    mock_runner = await start_mock_server(9001)

    storage = RequestStorage(base_dir="./demo_recordings")

    print("\nLoading recorded requests...")
    records = []
    async for record in storage.load_records(session_id=session_id):
        records.append(record)

    print(f"Loaded {len(records)} requests")
    print("\nOriginal request timing:")
    base_ts = records[0].timestamp
    for i, record in enumerate(records):
        offset = (record.timestamp - base_ts) * 1000
        print(f"  {i+1}. {record.method} {record.url.split('/')[-1]} - offset: {offset:.1f}ms")

    extraction_rules = [
        ExtractionRule(
            name="extract_token",
            source="json_body",
            selector="$.data.token",
            variable_name="auth_token",
            description="Extract auth token from login response",
        ),
        ExtractionRule(
            name="extract_user_id",
            source="json_body",
            selector="$.data.user_id",
            variable_name="user_id",
            description="Extract user_id from response",
        ),
    ]

    context_manager = ContextManager(
        extraction_rules=extraction_rules,
        enable_auto_extract=True,
    )

    player = Player(
        target_url="http://127.0.0.1:9001",
        storage=storage,
        context_manager=context_manager,
        mode=PlaybackMode.PRECISE_TIMING,
        speed_factor=1.0,
        max_concurrent=10,
    )

    print("\nStarting playback with PRECISE_TIMING mode...")
    print("Key features:")
    print("  - Monotonic timestamp-based scheduler")
    print("  - Original inter-request intervals preserved")
    print("  - Context management: token extraction and injection")
    print("  - Timing deviation tracking")

    start_time = time.perf_counter()
    report = await player.play(session_id=session_id)
    end_time = time.perf_counter()

    print(f"\n=== Playback Report ===")
    print(f"Total requests: {report.total_requests}")
    print(f"Successful: {report.successful_requests}")
    print(f"Failed: {report.failed_requests}")
    print(f"Success rate: {report.successful_requests/report.total_requests*100:.2f}%")
    print(f"\nActual duration: {(end_time-start_time)*1000:.1f}ms")
    print(f"\nLatency statistics (ms):")
    print(f"  Avg: {report.avg_latency_ms:.2f}")
    print(f"  P95: {report.p95_latency_ms:.2f}")
    print(f"  P99: {report.p99_latency_ms:.2f}")

    if report.timing_deviation_ms:
        import statistics
        avg_dev = statistics.mean(report.timing_deviation_ms)
        max_dev = max(report.timing_deviation_ms)
        print(f"\nTiming deviation (ms):")
        print(f"  Avg: {avg_dev:.2f}")
        print(f"  Max: {max_dev:.2f}")
        print(f"  (Typically <10ms for precise timing)")

    await mock_runner.cleanup()


async def demo_stateful_playback():
    print("\n" + "=" * 60)
    print("DEMO 3: Stateful Request Handling")
    print("=" * 60)

    context_manager = ContextManager(
        enable_auto_extract=True,
        env_mappings={
            "prod.example.com": "test.example.com",
        },
    )

    context = context_manager.create_context(
        session_id="demo_session_001",
        recording_env="production",
        playback_env="test",
    )

    print("\n1. Simulating login response token extraction...")
    login_response = json.dumps({
        "code": 0,
        "data": {
            "token": "prod_token_abc123",
            "user_id": "user_12345",
        }
    }).encode("utf-8")

    login_request = RequestRecord(
        id="req_001",
        timestamp=time.time(),
        method="POST",
        url="https://prod.example.com/api/login",
        headers={},
    )

    extracted = await context_manager.extract_variables(
        login_request, 200, {}, login_response, context
    )

    print(f"   Extracted variables: {extracted}")
    print(f"   Context variables: {context.variables}")

    print("\n2. Applying context to subsequent request...")
    next_request = RequestRecord(
        id="req_002",
        timestamp=time.time() + 0.5,
        method="GET",
        url="https://prod.example.com/api/user/{{user_id}}/info",
        headers={
            "X-Auth-Token": "{{auth_token}}",
            "Host": "prod.example.com",
        },
        body=None,
    )

    modified_request = await context_manager.apply_context(next_request, context)

    print(f"   Original URL: {next_request.url}")
    print(f"   Modified URL: {modified_request.url}")
    print(f"   Original headers: {next_request.headers}")
    print(f"   Modified headers: {modified_request.headers}")

    print("\n3. Analyzing request dependencies...")
    records = [login_request, next_request]
    deps = context_manager.analyze_dependencies(records)
    print(f"   Dependencies: {deps}")

    print("\n4. Environment mapping...")
    print(f"   Original host: {next_request.headers.get('Host')}")
    print(f"   Mapped host: {modified_request.headers.get('Host')}")


async def demo_masking():
    print("\n" + "=" * 60)
    print("DEMO 4: Sensitive Data Masking")
    print("=" * 60)

    mask_rules = [
        MaskRule(
            name="password_hash",
            selector="password",
            mask_type="hash",
            preserve_length=False,
        ),
        MaskRule(
            name="phone_mask",
            selector="phone",
            mask_type="mask",
            pattern=r'1[3-9]\d{9}',
            preserve_length=True,
        ),
        MaskRule(
            name="email_mask",
            selector="email",
            mask_type="mask",
            preserve_length=True,
        ),
        MaskRule(
            name="id_mask",
            selector="id_card",
            mask_type="mask",
            preserve_length=True,
        ),
    ]

    masking_engine = MaskingEngine(
        rules=mask_rules,
        preserve_structure=True,
        default_mask_char="*",
    )

    print("\n1. JSON body masking...")
    original_body = json.dumps({
        "username": "test_user",
        "password": "my_secret_123",
        "phone": "13800138000",
        "email": "test@example.com",
        "id_card": "110101199001011234",
        "profile": {
            "phone": "13900139000",
            "backup_email": "backup@example.com",
        }
    }, ensure_ascii=False)

    masked_body = await masking_engine._mask_body(original_body)
    print(f"   Original: {original_body}")
    print(f"   Masked:   {masked_body}")

    print("\n2. Header masking...")
    original_headers = {
        "Authorization": "Bearer secret_token_12345",
        "X-Auth-Token": "another_secret_token",
        "Cookie": "session_id=abc123; user_token=xyz789",
        "Content-Type": "application/json",
    }

    masked_headers = await masking_engine._mask_headers(original_headers)
    print(f"   Original Authorization: {original_headers['Authorization']}")
    print(f"   Masked Authorization:   {masked_headers['Authorization']}")
    print(f"   Original Cookie: {original_headers['Cookie']}")
    print(f"   Masked Cookie:   {masked_headers['Cookie']}")

    print("\n3. URL query parameter masking...")
    original_url = "https://api.example.com/search?q=test&phone=13800138000&token=secret123"
    masked_url = await masking_engine._mask_url(original_url)
    print(f"   Original: {original_url}")
    print(f"   Masked:   {masked_url}")

    print("\n4. Structure validation...")
    is_valid = masking_engine.validate_masked_request(
        json.loads(original_body),
        json.loads(masked_body),
    )
    print(f"   JSON structure preserved: {is_valid}")

    print("\n5. Masking types demo...")
    test_value = "13800138000"
    print(f"   Original: {test_value}")
    print(f"   MASK:     {masking_engine._apply_mask_to_value(test_value, 'mask', True)}")
    print(f"   HASH:     {masking_engine._apply_mask_to_value(test_value, 'hash', False)}")
    print(f"   REDACT:   {masking_engine._apply_mask_to_value(test_value, 'redact', True)}")
    print(f"   TRUNCATE: {masking_engine._apply_mask_to_value(test_value, 'truncate', True)}")

    print("\n6. Built-in pattern detection...")
    test_text = """
    Contact us at support@example.com or call 13800138000.
    IP: 192.168.1.100, ID: 110101199001011234
    """
    masked_text = await masking_engine._mask_text(test_text)
    print(f"   Original: {test_text.strip()}")
    print(f"   Masked:   {masked_text.strip()}")


async def main():
    try:
        print("\n" + "=" * 60)
        print("TRAFFIC REPLAY SYSTEM - COMPLETE DEMO")
        print("=" * 60)
        print("\nThis demo showcases:")
        print("  1. Low-overhead request recording")
        print("  2. Precise timing playback")
        print("  3. Stateful request handling")
        print("  4. Sensitive data masking")
        print("\n" + "=" * 60)

        session_id = await demo_recording()
        await demo_precise_playback(session_id)
        await demo_stateful_playback()
        await demo_masking()

        print("\n" + "=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nKey takeaways:")
        print("\n1. LOW-OVERHEAD RECORDING:")
        print("   - TAP mode: recording is asynchronous, doesn't block requests")
        print("   - Batch writes: minimizes I/O operations")
        print("   - Sampling: configurable for high-traffic scenarios")
        print("   - Expected overhead: <5% CPU, <10ms latency increase")
        print("\n2. PRECISE TIMING:")
        print("   - Uses monotonic clock for accurate scheduling")
        print("   - Preserves original inter-request intervals")
        print("   - Timing deviation typically <10ms")
        print("   - Supports speed adjustment (0.5x, 2x, etc.)")
        print("\n3. STATEFUL HANDLING:")
        print("   - Context extraction: tokens, IDs, etc.")
        print("   - Variable substitution in URLs, headers, bodies")
        print("   - Environment mapping: prod->test hostnames")
        print("   - Dependency analysis for correct ordering")
        print("\n4. DATA MASKING:")
        print("   - Format-preserving: JSON/XML structure maintained")
        print("   - Multiple strategies: mask, hash, redact, etc.")
        print("   - Built-in patterns: phone, email, ID, IP, etc.")
        print("   - Custom rules via JSONPath/Regex")

    except KeyboardInterrupt:
        print("\nDemo interrupted")
    except Exception as e:
        print(f"\nDemo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
