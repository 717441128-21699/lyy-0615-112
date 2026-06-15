#!/usr/bin/env python3
import asyncio
import sys
import os
import time
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aiohttp import web
import aiohttp

from traffic_replay import (
    Recorder, RecordingMode,
    Player, PlaybackMode,
    RequestStorage,
    MaskingEngine,
    ContextManager,
    RequestRecord,
    MaskRule,
    ExtractionRule,
)


async def mock_app():
    request_log = []

    async def login(request):
        data = await request.json()
        username = data.get("username")
        await asyncio.sleep(0.2)
        request_log.append({
            "path": "/api/login",
            "time": time.time(),
            "auth": request.headers.get("X-Auth-Token", "none"),
        })
        if username == "test":
            token = f"test_token_{int(time.time()*1000)}"
            return web.json_response({
                "code": 0,
                "message": "success",
                "data": {
                    "token": token,
                    "user_id": "user_new_001",
                }
            })
        return web.json_response({"code": 401, "message": "unauthorized"}, status=401)

    async def get_user_info(request):
        auth = request.headers.get("X-Auth-Token", "")
        request_log.append({
            "path": "/api/user/info",
            "time": time.time(),
            "auth": auth[:20] if auth else "none",
        })
        if auth.startswith("test_token_"):
            return web.json_response({
                "code": 0,
                "data": {
                    "user_id": "user_new_001",
                    "username": "test",
                }
            })
        return web.json_response({"code": 401, "message": "unauthorized"}, status=401)

    async def search(request):
        await asyncio.sleep(0.05)
        phone = request.query.get("phone", "")
        token = request.query.get("token", "")
        request_log.append({
            "path": "/api/search",
            "time": time.time(),
            "phone": phone,
            "token": token[:10] if token else "",
        })
        return web.json_response({
            "code": 0,
            "data": {"total": 10, "items": []}
        })

    app = web.Application()
    app["request_log"] = request_log
    app.router.add_post("/api/login", login)
    app.router.add_get("/api/user/info", get_user_info)
    app.router.add_get("/api/search", search)
    return app


async def start_server(port: int):
    app = await mock_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner, app


async def test_1_no_duplicate_records():
    print("\n" + "="*60)
    print("TEST 1: TAP模式录制无重复记录")
    print("="*60)

    runner, app = await start_server(9100)

    storage = RequestStorage(
        base_dir="./test_recordings",
        batch_size=5,
        flush_interval_ms=100,
        compress=False,
        max_memory_mb=10,
    )

    masking = MaskingEngine(preserve_structure=True)
    recorder = Recorder(
        target_url="http://127.0.0.1:9100",
        storage=storage,
        masking_engine=masking,
        mode=RecordingMode.TAP,
        listen_host="127.0.0.1",
        listen_port=9101,
        sample_rate=1.0,
    )

    await recorder.start()
    await asyncio.sleep(0.5)

    print("\n发送 5 个请求...")
    async with aiohttp.ClientSession() as session:
        for i in range(5):
            async with session.get(f"http://127.0.0.1:9101/api/search?q={i}") as resp:
                await resp.json()
                print(f"  请求 {i+1}: 状态 {resp.status}")

    await asyncio.sleep(1)
    session_id = storage._session_id
    await recorder.stop()

    print(f"\n统计:")
    print(f"  recorder._request_count = {recorder._request_count}")
    print(f"  storage._records_written = {storage._records_written}")

    records = []
    async for record in storage.load_records(session_id=session_id):
        records.append(record)

    print(f"  加载到的记录数 = {len(records)}")

    has_duplicates = len(records) != len(set(r.id for r in records))
    print(f"\n结果: {'❌ 有重复' if has_duplicates else '✅ 无重复'}")
    print(f"  预期: 5 条, 实际: {len(records)} 条")

    if records:
        print(f"\n样例记录:")
        r = records[0]
        print(f"  id: {r.id[:8]}...")
        print(f"  method: {r.method}")
        print(f"  url: {r.url[:50]}...")
        print(f"  response_status: {r.response_status}")
        print(f"  has_body: {r.body is not None}")
        print(f"  has_response_body: {r.response_body is not None}")

    await runner.cleanup()

    success = len(records) == 5 and not has_duplicates
    return success, session_id


async def test_2_url_query_masking():
    print("\n" + "="*60)
    print("TEST 2: URL查询参数脱敏")
    print("="*60)

    runner, app = await start_server(9200)

    storage = RequestStorage(
        base_dir="./test_recordings",
        batch_size=5,
        flush_interval_ms=100,
        compress=False,
    )

    masking = MaskingEngine(preserve_structure=True)
    recorder = Recorder(
        target_url="http://127.0.0.1:9200",
        storage=storage,
        masking_engine=masking,
        mode=RecordingMode.TAP,
        listen_host="127.0.0.1",
        listen_port=9201,
    )

    await recorder.start()
    await asyncio.sleep(0.3)

    print("\n发送带敏感参数的请求...")
    async with aiohttp.ClientSession() as session:
        url = "http://127.0.0.1:9201/api/search?phone=13800138000&token=my_secret_token_123&id_card=110101199001011234&page=1"
        print(f"  原始URL: {url}")
        async with session.get(url) as resp:
            await resp.json()

    await asyncio.sleep(0.5)
    session_id = storage._session_id
    await recorder.stop()

    records = []
    async for record in storage.load_records(session_id=session_id):
        records.append(record)

    if records:
        recorded_url = records[0].url
        print(f"\n录制后的URL: {recorded_url}")

        phone_masked = "13800138000" not in recorded_url
        token_masked = "my_secret_token_123" not in recorded_url
        id_card_masked = "110101199001011234" not in recorded_url

        print(f"\n脱敏检查:")
        print(f"  手机号脱敏: {'✅' if phone_masked else '❌'} ({'已脱敏' if phone_masked else '未脱敏'})")
        print(f"  token脱敏: {'✅' if token_masked else '❌'} ({'已脱敏' if token_masked else '未脱敏'})")
        print(f"  身份证脱敏: {'✅' if id_card_masked else '❌'} ({'已脱敏' if id_card_masked else '未脱敏'})")

        success = phone_masked and token_masked and id_card_masked
    else:
        print("❌ 没有录制到记录")
        success = False

    await runner.cleanup()
    return success, session_id


async def test_3_4_stateful_dependency():
    print("\n" + "="*60)
    print("TEST 3+4: 自动会话上下文 + 依赖调度")
    print("  (登录后查详情，查询必须等登录响应回来)")
    print("="*60)

    runner, app = await start_server(9300)

    storage = RequestStorage(
        base_dir="./test_recordings",
        batch_size=10,
        flush_interval_ms=100,
        compress=False,
    )

    masking = MaskingEngine(preserve_structure=True)
    recorder = Recorder(
        target_url="http://127.0.0.1:9300",
        storage=storage,
        masking_engine=masking,
        mode=RecordingMode.TAP,
        listen_host="127.0.0.1",
        listen_port=9301,
    )

    await recorder.start()
    await asyncio.sleep(0.3)

    print("\n录制: 先登录，200ms后查详情")
    print("  (故意设置短间隔来测试依赖调度)")

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "http://127.0.0.1:9301/api/login",
            json={"username": "test", "password": "secret123"}
        ) as resp:
            data = await resp.json()
            token = data["data"]["token"]
            print(f"  登录成功, token: {token[:20]}...")

        await asyncio.sleep(0.2)

        async with session.get(
            "http://127.0.0.1:9301/api/user/info",
            headers={"X-Auth-Token": token}
        ) as resp:
            data = await resp.json()
            print(f"  查询用户信息: {data['code']}")

    await asyncio.sleep(0.5)
    session_id = storage._session_id
    await recorder.stop()

    records = []
    async for record in storage.load_records(session_id=session_id):
        records.append(record)
    records.sort(key=lambda r: r.timestamp)

    print(f"\n录制到 {len(records)} 条记录")
    for i, r in enumerate(records):
        print(f"  {i+1}. {r.method} {r.url.split('/')[-1].split('?')[0]} - status={r.response_status}")

    print("\n" + "-"*40)
    print("现在回放: 使用测试环境新token，验证依赖调度")
    print("  关键：即使查询的定时点到了，也要等登录响应回来")

    extraction_rules = [
        ExtractionRule(
            name="extract_token",
            source="json_body",
            selector="$.data.token",
            variable_name="auth_token",
        ),
        ExtractionRule(
            name="extract_user_id",
            source="json_body",
            selector="$.data.user_id",
            variable_name="user_id",
        ),
    ]

    context_mgr = ContextManager(
        extraction_rules=extraction_rules,
        enable_auto_extract=True,
    )

    player = Player(
        target_url="http://127.0.0.1:9300",
        storage=storage,
        context_manager=context_mgr,
        mode=PlaybackMode.PRECISE_TIMING,
        speed_factor=1.0,
        max_concurrent=10,
    )

    request_log = app["request_log"]
    request_log.clear()

    print("\n开始回放...")
    start_time = time.time()
    report = await player.play(session_id=session_id)
    elapsed = time.time() - start_time

    print(f"\n回放报告:")
    print(f"  总请求: {report.total_requests}")
    print(f"  成功: {report.successful_requests}")
    print(f"  失败: {report.failed_requests}")
    print(f"  成功率: {report.successful_requests/report.total_requests*100:.1f}%")
    print(f"  总耗时: {elapsed*1000:.1f}ms")

    print(f"\n服务端收到的请求顺序和时间:")
    for i, req in enumerate(request_log):
        rel_time = (req["time"] - request_log[0]["time"]) * 1000
        print(f"  {i+1}. {req['path']} - 相对时间: {rel_time:.1f}ms - auth: {req.get('auth', 'N/A')}")

    if len(request_log) >= 2:
        login_time = request_log[0]["time"]
        info_time = request_log[1]["time"]
        gap_ms = (info_time - login_time) * 1000
        print(f"\n登录→查询间隔: {gap_ms:.1f}ms")
        print(f"  (登录响应需要约200ms，所以间隔应该>200ms)")

        info_auth = request_log[1].get("auth", "")
        has_valid_token = info_auth.startswith("test_token_")

        print(f"\n验证结果:")
        print(f"  查询使用了新token: {'✅' if has_valid_token else '❌'}")
        print(f"    auth值: {info_auth}")
        print(f"  查询在登录响应之后发出: {'✅' if gap_ms > 150 else '❌'}")
        print(f"    实际间隔: {gap_ms:.1f}ms (预期 >200ms)")

        success = has_valid_token and gap_ms > 150
    else:
        print("❌ 服务端收到的请求不足")
        success = False

    await runner.cleanup()
    return success, session_id


async def main():
    print("=" * 60)
    print("4个问题修复验证测试")
    print("=" * 60)

    results = []

    try:
        success, _ = await test_1_no_duplicate_records()
        results.append(("无重复记录", success))
    except Exception as e:
        print(f"TEST 1 异常: {e}")
        import traceback
        traceback.print_exc()
        results.append(("无重复记录", False))

    try:
        success, _ = await test_2_url_query_masking()
        results.append(("URL查询脱敏", success))
    except Exception as e:
        print(f"TEST 2 异常: {e}")
        import traceback
        traceback.print_exc()
        results.append(("URL查询脱敏", False))

    try:
        success, _ = await test_3_4_stateful_dependency()
        results.append(("自动会话+依赖调度", success))
    except Exception as e:
        print(f"TEST 3+4 异常: {e}")
        import traceback
        traceback.print_exc()
        results.append(("自动会话+依赖调度", False))

    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    for name, success in results:
        status = "✅ 通过" if success else "❌ 失败"
        print(f"  {name}: {status}")

    all_pass = all(s for _, s in results)
    print(f"\n总体: {'✅ 全部通过' if all_pass else '❌ 有失败'}")

    return all_pass


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
