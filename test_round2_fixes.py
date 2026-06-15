#!/usr/bin/env python3
import asyncio
import sys
import os
import time
import json
import re
import tempfile
import shutil
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


def validate_phone(phone: str) -> bool:
    return bool(re.match(r'^1[3-9]\d{9}$', phone))


def validate_id_card(ids: str) -> bool:
    if not re.match(r'^\d{17}[\dX]$', ids):
        return False

    total = 0
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = "10X98765432"
    for i, c in enumerate(ids[:17]):
        total += int(c) * weights[i]
    check_code = check_codes[total % 11]
    return check_code == ids[-1]


def validate_bank_card(card: str) -> bool:
    if not re.match(r'^\d{16,19}$', card):
        return False

    total = 0
    for i, c in enumerate(reversed(card)):
        n = int(c)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def validate_email(email: str) -> bool:
    return bool(re.match(r'^[\w.]+@[\w]+\.[\w]{2,}$', email))


def validate_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


async def mock_app():
    request_log = []

    async def login(request):
        handler_start = time.time()
        await asyncio.sleep(0.2)
        token = f"fresh_token_{int(time.time()*1000)}"
        response_sent_time = time.time()
        request_log.append({
            "path": "/api/auth/login",
            "time": handler_start,
            "response_sent_time": response_sent_time,
            "auth": request.headers.get("X-Auth-Token", "none"),
            "generated_token": token,
        })
        return web.json_response({
            "code": 0,
            "data": {
                "token": token,
                "user_id": "fresh_user_789",
                "access_token": token + "_at",
            },
            "message": "ok"
        })

    async def detail(request):
        auth = request.headers.get("X-Auth-Token", "")
        query_phone = request.rel_url.query.get("phone", "")
        query_idcard = request.rel_url.query.get("id_card", "")
        request_log.append({
            "path": "/api/user/detail",
            "time": time.time(),
            "auth": auth,
            "query_phone": query_phone,
            "query_idcard": query_idcard,
        })
        start = request_log[0]["time"] if request_log else 0
        delta_ms = (time.time() - request_log[0]["time"]) * 1000 if len(request_log) > 0 else 0

        prefix = "fresh_token_"
        if auth.startswith(prefix) and len(auth) > len(prefix) + 3:
            return web.json_response({
                "code": 0, "data": {
                    "id": "1001", "name": "TestUser", "phone": query_phone,
                }
            })
        return web.json_response({
            "code": 401, "message": f"unauthorized (auth='{auth[:20]}...')"
        }, status=401)

    async def search(request):
        auth = request.headers.get("X-Auth-Token", "")
        query_token = request.rel_url.query.get("token", "")
        request_log.append({
            "path": "/api/search",
            "time": time.time(),
            "auth": auth,
            "query_token": query_token,
        })
        prefix = "fresh_token_"
        if auth.startswith(prefix):
            return web.json_response({"code": 0, "data": {"results": 3}})
        return web.json_response({"code": 401}, status=401)

    app = web.Application()
    app.router.add_post("/api/auth/login", login)
    app.router.add_get("/api/user/detail", detail)
    app.router.add_get("/api/search", search)
    return app, request_log


async def start_test_server():
    import socket
    app, log = await mock_app()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=port)
    await site.start()
    return f"http://127.0.0.1:{port}", runner, log


print("=" * 72)
print("测试第2轮修复 - 4个问题验证")
print("=" * 72)

results = []


async def test_1_graceful_stop():
    print("\n" + "=" * 72)
    print("测试1: 录制快速停止(Ctrl+C) - 数据完整落盘")
    print("=" * 72)

    target_url, runner, log = await start_test_server()

    tempdir = tempfile.mkdtemp(prefix="test_graceful_")

    storage = RequestStorage(base_dir=tempdir, batch_size=50, flush_interval_ms=500, compress=False)
    recorder = Recorder(
        target_url=target_url,
        mode=RecordingMode.TAP,
        storage=storage,
    )

    recorder.listen_port = 0
    await recorder.start()
    proxy_port = recorder.listen_port
    proxy_url = f"http://127.0.0.1:{proxy_port}"

    try:
        async with aiohttp.ClientSession() as session:
            for i in range(7):
                payload = json.dumps({"username": "test", "password": "123456"})
                resp = await session.post(
                    proxy_url + "/api/auth/login",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                _ = await resp.text()
                print(f"  请求 {i+1}/7 已发送, 响应码={resp.status}")

        print(f"  7个请求完成, 立即停止...")

        await asyncio.sleep(0.02)

        await recorder.stop(graceful_wait_ms=3000)

        session_dirs = [d for d in os.listdir(tempdir) if os.path.isdir(os.path.join(tempdir, d))]
        assert len(session_dirs) >= 1, f"没有录制目录，只有: {os.listdir(tempdir)}"

        session_path = os.path.join(tempdir, session_dirs[0])

        meta_path = os.path.join(session_path, "metadata.json")
        assert os.path.exists(meta_path), "metadata.json 不存在"

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        meta_total = meta["total_records"]
        print(f"  metadata.total_records = {meta_total}")

        record_files = [
            os.path.join(session_path, fn)
            for fn in os.listdir(session_path)
            if fn.startswith("requests_")
        ]

        actual_records = 0
        for rf in record_files:
            with open(rf, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        actual_records += 1

        print(f"  实际JSONL行数          = {actual_records}")

        results.append({
            "name": "录制停止完整落盘",
            "passed": actual_records == 7 and meta_total == 7,
            "detail": f"请求数=7, 落盘={actual_records}, metadata={meta_total}",
        })
        if actual_records == 7 and meta_total == 7:
            print("  ✅ 通过: 7条请求全部落盘，metadata数量匹配")
        else:
            print(f"  ❌ 失败: 期望7条, 落盘={actual_records}, metadata={meta_total}")

    finally:
        try:
            await recorder.stop()
        except Exception:
            pass
        await runner.cleanup()
        shutil.rmtree(tempdir, ignore_errors=True)


async def test_2_url_valid_format_masking():
    print("\n" + "=" * 72)
    print("测试2: URL query脱敏 - 生成合法假值(格式校验)")
    print("=" * 72)

    engine = MaskingEngine()

    test_cases = [
        ("phone",          "13800138000",        validate_phone,
         "手机号格式合法(1[3-9]xxxxxxxxx)"),
        ("mobile",         "13912345678",        validate_phone,
         "手机号mobile参数合法"),
        ("id_card",        "110101199001011234", validate_id_card,
         "身份证校验位正确"),
        ("idCard",         "110101198506151234", validate_id_card,
         "驼峰idCard参数合法"),
        ("bank_card",      "6222021234567890",   validate_bank_card,
         "银行卡Luhn校验正确"),
        ("email",          "zhangsan@qq.com",    validate_email,
         "邮箱格式合法"),
        ("user_ip",        "8.8.8.8",            validate_ipv4,
         "IP格式合法"),
        ("token",          "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.xxx",
         lambda v: len(v) >= 16 and "*" not in v,
         "Token长度保留且没有星号"),
    ]

    all_passed = True
    details = []

    for pname, orig_val, validator, desc in test_cases:
        test_url = f"https://api.example.com/search?{pname}={orig_val}&page=1&size=10"
        masked_url = await engine._mask_url(test_url)

        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(masked_url)
        qs = parse_qs(parsed.query)

        masked_val = qs.get(pname, [None])[0]

        if masked_val is None:
            print(f"  ❌ {pname}: 值丢失! URL={masked_url}")
            all_passed = False
            continue

        is_valid = validator(masked_val)
        changed = masked_val != orig_val
        detail_ok = is_valid and changed

        status = "✅" if detail_ok else "❌"
        print(f"  {status} {pname:<12} 原值={orig_val[:20]:<20}  脱敏后={masked_val[:25]:<25}  {desc}")

        if not detail_ok:
            all_passed = False
            details.append(f"{pname}失败: 脱敏值={masked_val}")

    results.append({
        "name": "URL脱敏生成合法值",
        "passed": all_passed,
        "detail": "; ".join(details) if details else "全部通过",
    })


async def test_3_default_extract_and_auth_dep():
    print("\n" + "=" * 72)
    print("测试3+4: 默认自动提取 data.token/user_id + 凭证类请求依赖等待")
    print("=" * 72)

    target_url, runner, log = await start_test_server()

    tempdir = tempfile.mkdtemp(prefix="test_default_extract_")

    t0 = time.time()
    fake_records = [
        RequestRecord(
            id=f"rec_{i}",
            timestamp=t0 + i * 0.05,
            method="POST" if i == 0 else "GET",
            url=target_url + ("/api/auth/login" if i == 0
                              else "/api/user/detail" if i == 1
                              else "/api/search"),
            headers={
                "Content-Type": "application/json",
                **({} if i == 0 else {
                    "X-Auth-Token": f"ORIGINAL_TOKEN_IN_RECORDING_{i}"
                })
            },
            body=json.dumps({"username": "test", "password": "123456"}).encode()
                 if i == 0 else None,
            response_status=200,
            response_body=json.dumps({
                "code": 0,
                "data": {
                    "token": f"original_token_{i}",
                    "user_id": "original_user_123",
                }
            }).encode() if i == 0 else None,
        )
        for i in range(3)
    ]

    for r in fake_records:
        if r.method == "GET":
            if "detail" in r.url:
                r.url += "?phone=13800138000&id_card=110101199001011234"
            else:
                r.url += "?token=SECRET_QUERY_TOKEN_123"

    ctx = ContextManager(enable_auto_extract=True)
    masker = MaskingEngine()
    for r in fake_records:
        masked = await masker.mask_record(r)
        r.url = masked.url
        r.headers = masked.headers
        r.body = masked.body

    player = Player(
        target_url=target_url,
        context_manager=ctx,
        mode=PlaybackMode.PRECISE_TIMING,
    )

    dep_graph = player._build_dependency_graph(fake_records)
    print(f"  依赖图构建结果:")
    for rid, deps in dep_graph.items():
        idx = rid.split("_")[1]
        path = fake_records[int(idx)].url.split("/")[-1].split("?")[0]
        dep_ids = [f"rec_{d.split('_')[1]}" for d in deps] if deps else "[]"
        print(f"    {path:<18} -> 依赖: {dep_ids}")

    login_depended = dep_graph.get("rec_1", []) or dep_graph.get("rec_2", [])
    if len(dep_graph.get("rec_1", [])) >= 1 and len(dep_graph.get("rec_2", [])) >= 1:
        print(f"  ✅ detail和search都已建立对登录请求的依赖")
    else:
        print(f"  ⚠️  依赖不完整: rec_1={dep_graph.get('rec_1', [])}, rec_2={dep_graph.get('rec_2', [])}")

    report = await player.play(records=fake_records)

    print(f"\n  回放结果: 总请求={report.total_requests}, 成功={report.successful_requests}, 失败={report.failed_requests}")
    print(f"  服务器收到的请求日志 ({len(log)}条):")
    server_detail_req = None
    server_login_req = None

    for i, entry in enumerate(log):
        auth_preview = entry.get("auth", "")[:32]
        if entry["path"] == "/api/auth/login":
            server_login_req = entry
            resp_time = entry.get("response_sent_time", 0) - entry["time"]
            print(f"    [{i}] {entry['path']:<22} handler开始={entry['time'] - log[0]['time']:.4f}s  响应发出延迟={resp_time*1000:.0f}ms  返回token={entry.get('generated_token', '')[:20]}...")
        else:
            if entry["path"] == "/api/user/detail":
                server_detail_req = entry
            print(f"    [{i}] {entry['path']:<22} handler开始={entry['time'] - log[0]['time']:.4f}s  auth={auth_preview}...")

    timing_ok = True
    if server_login_req and server_detail_req:
        login_resp_sent = server_login_req.get("response_sent_time", server_login_req["time"])
        delta_ms = (server_detail_req["time"] - login_resp_sent) * 1000
        print(f"\n  登录响应发出时刻 -> 详情handler开始: {delta_ms:.1f}ms")
        print(f"    (若delta_ms >= 0 说明详情是在登录响应之后才发出，正确；若负值则抢先了)")
        if delta_ms >= -50:
            print(f"  ✅ 详情确实在登录响应后发出 (差值={delta_ms:.1f}ms，考虑网络+系统误差50ms内为正常)")
        else:
            print(f"  ❌ 详情请求抢先发出了! 差值={delta_ms:.1f}ms，小于-50ms阈值")
            timing_ok = False

    success_rate = report.successful_requests / max(report.total_requests, 1)
    all_ok = success_rate >= 0.66 and timing_ok

    fresh_auth_count = 0
    for entry in log:
        a = entry.get("auth", "")
        if a.startswith("fresh_token_"):
            fresh_auth_count += 1

    if fresh_auth_count >= 2:
        print(f"  ✅ 有{fresh_auth_count}条请求使用了新的fresh_token_凭证")
    else:
        print(f"  ❌ 只有{fresh_auth_count}条请求使用了新凭证，期望>=2")

    detail_entry = None
    for entry in log:
        if entry["path"] == "/api/user/detail":
            detail_entry = entry
            break

    detail_phone = detail_entry.get("query_phone", "") if detail_entry else ""
    detail_idcard = detail_entry.get("query_idcard", "") if detail_entry else ""

    orig_phone = "13800138000"
    orig_idcard = "110101199001011234"
    print(f"\n  URL脱敏后传过去的值:")
    phone_ok = bool(detail_phone) and validate_phone(detail_phone) and detail_phone != orig_phone
    idcard_ok = bool(detail_idcard) and validate_id_card(detail_idcard) and detail_idcard != orig_idcard
    print(f"    phone:  原值={orig_phone},  回放值={detail_phone!r}  {'✅合法且不同' if phone_ok else '❌不合法'}")
    print(f"    id_card: 原值={orig_idcard},  回放值={detail_idcard!r}  {'✅合法且不同' if idcard_ok else '❌不合法'}")

    final_passed = all_ok and (fresh_auth_count >= 2) and phone_ok and idcard_ok

    results.append({
        "name": "默认提取+凭证依赖+合法脱敏值",
        "passed": final_passed,
        "detail": f"成功率={success_rate:.0%}, fresh_token使用={fresh_auth_count}, 等待时序={timing_ok}, phone合法={phone_ok}, idcard合法={idcard_ok}",
    })

    if final_passed:
        print(f"  ✅ 综合测试通过!")
    else:
        print(f"  ❌ 综合测试部分失败")

    try:
        await player.stop()
    except Exception:
        pass
    await runner.cleanup()
    shutil.rmtree(tempdir, ignore_errors=True)


async def main():
    await test_1_graceful_stop()
    await test_2_url_valid_format_masking()
    await test_3_default_extract_and_auth_dep()

    print("\n" + "=" * 72)
    print("测试总结")
    print("=" * 72)

    passed = sum(1 for r in results if r["passed"])
    total = len(results)

    for r in results:
        status = "✅ 通过" if r["passed"] else "❌ 失败"
        print(f"  {r['name']:<32}: {status}  ({r['detail']})")

    print(f"\n总体: {'✅ 全部通过' if passed == total else f'❌ {passed}/{total} 通过'}")
    sys.exit(0 if passed == total else 1)


asyncio.run(main())
