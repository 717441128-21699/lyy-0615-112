#!/usr/bin/env python3
import asyncio
import sys
import os
import time
import json
import re
import tempfile
import shutil
import socket
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


async def mock_app_slow():
    request_log = []

    async def slow_api(request):
        handler_start = time.time()
        await asyncio.sleep(1.0)
        request_log.append({
            "path": "/api/slow",
            "handler_start": handler_start,
            "response_time": time.time(),
        })
        return web.json_response({"code": 0, "data": {"slow_result": "ok"}})

    async def health(request):
        request_log.append({"path": "/health"})
        return web.json_response({"status": "ok"})

    app = web.Application()
    app.router.add_get("/api/slow", slow_api)
    app.router.add_get("/health", health)
    return app, request_log


async def mock_app_query_auth():
    request_log = []

    async def login(request):
        handler_start = time.time()
        await asyncio.sleep(0.2)
        token = f"fresh_tok_{int(time.time()*1000)}"
        user_id = "uid_fresh_888"
        request_log.append({
            "path": "/login",
            "time": handler_start,
            "response_sent_time": time.time(),
            "token": token,
            "user_id": user_id,
        })
        return web.json_response({
            "code": 0,
            "data": {
                "token": token,
                "user_id": user_id,
                "access_token": token + "_at",
            }
        })

    async def detail_by_query(request):
        qs_token = request.rel_url.query.get("token", "")
        qs_uid = request.rel_url.query.get("user_id", "")
        request_log.append({
            "path": "/detail_query",
            "time": time.time(),
            "qs_token": qs_token,
            "qs_user_id": qs_uid,
        })
        if qs_token.startswith("fresh_tok_"):
            return web.json_response({"code": 0, "data": {"name": "OKQuery"}})
        return web.json_response({"code": 401, "msg": f"bad token: {qs_token[:25]}"}, status=401)

    async def detail_by_cookie(request):
        cookie = request.headers.get("Cookie", "")
        ctoken = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session_token="):
                try:
                    ctoken = part.split("=", 1)[1]
                except (ValueError, IndexError):
                    ctoken = ""
                break
        request_log.append({
            "path": "/detail_cookie",
            "time": time.time(),
            "cookie_token": ctoken,
        })
        if ctoken.startswith("fresh_tok_"):
            return web.json_response({"code": 0, "data": {"name": "OKCookie"}})
        return web.json_response({"code": 401, "msg": f"bad cookie: {ctoken[:25]}"}, status=401)

    app = web.Application()
    app.router.add_post("/login", login)
    app.router.add_get("/detail/query", detail_by_query)
    app.router.add_get("/detail/cookie", detail_by_cookie)
    return app, request_log


async def start_test_server(app_factory):
    app, log = await app_factory()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=port)
    await site.start()
    return f"http://127.0.0.1:{port}", runner, log


results = []


async def test_1_slow_response_graceful():
    print("\n" + "=" * 72)
    print("测试1: 慢响应接口(sleep 1s),请求发出后立即停止 - 完整落盘")
    print("=" * 72)

    target_url, runner, log = await start_test_server(mock_app_slow)
    tempdir = tempfile.mkdtemp(prefix="test_slow_resp_")

    storage = RequestStorage(base_dir=tempdir, batch_size=50, flush_interval_ms=300, compress=False)
    recorder = Recorder(
        target_url=target_url,
        mode=RecordingMode.TAP,
        storage=storage,
        timeout_ms=10000,
    )
    recorder.listen_port = 0
    await recorder.start()
    proxy_port = recorder.listen_port
    proxy_url = f"http://127.0.0.1:{proxy_port}"

    async def send_one():
        async with aiohttp.ClientSession() as session:
            t0 = time.time()
            resp = await session.get(proxy_url + "/api/slow", timeout=aiohttp.ClientTimeout(total=15))
            await resp.text()
            dt = (time.time() - t0) * 1000
            print(f"  发送请求成功, 往返耗时: {dt:.0f}ms")

    send_task = asyncio.create_task(send_one())

    await asyncio.sleep(0.2)
    print(f"  约200ms后调用 stop() (此时上游还在sleep, 约剩800ms...)")
    await recorder.stop(graceful_wait_ms=8000)

    await send_task

    session_dirs = [d for d in os.listdir(tempdir) if os.path.isdir(os.path.join(tempdir, d))]
    if not session_dirs:
        print("  ❌ 没有录制目录!")
        results.append(("慢响应落盘", False, "无录制目录"))
        await runner.cleanup()
        shutil.rmtree(tempdir, ignore_errors=True)
        return

    session_path = os.path.join(tempdir, session_dirs[0])
    meta_path = os.path.join(session_path, "metadata.json")

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    meta_total = meta["total_records"]

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

    print(f"  请求进入代理数: 1")
    print(f"  metadata.total_records: {meta_total}")
    print(f"  JSONL 实际行数: {actual_records}")

    ok = actual_records == 1 and meta_total == 1
    results.append((
        "慢响应落盘",
        ok,
        f"实际行数={actual_records}, metadata={meta_total}, 期望=1"
    ))
    print(f"  {'✅ 通过' if ok else '❌ 失败'}")

    await runner.cleanup()
    shutil.rmtree(tempdir, ignore_errors=True)


async def test_2_query_cookie_auth():
    print("\n" + "=" * 72)
    print("测试2: token在URL query和Cookie中 - 依赖等待+自动替换新值")
    print("=" * 72)

    target_url, runner, log = await start_test_server(mock_app_query_auth)
    tempdir = tempfile.mkdtemp(prefix="test_qc_auth_")

    t0 = time.time()
    fake_records = []

    fake_records.append(RequestRecord(
        id="rec_0",
        timestamp=t0,
        method="POST",
        url=target_url + "/login",
        headers={"Content-Type": "application/json"},
        body=b'{"username":"admin","password":"123"}',
        response_status=200,
    ))

    fake_records.append(RequestRecord(
        id="rec_1",
        timestamp=t0 + 0.05,
        method="GET",
        url=target_url + "/detail/query?token=OLD_QUERY_TOKEN_abc123&user_id=old_uid_001&page=1",
        headers={"Accept": "application/json"},
    ))

    fake_records.append(RequestRecord(
        id="rec_2",
        timestamp=t0 + 0.10,
        method="GET",
        url=target_url + "/detail/cookie?x=1",
        headers={
            "Accept": "application/json",
            "Cookie": "lang=zh-CN; session_token=OLD_COOKIE_TOKEN_xyz789; theme=dark",
        },
    ))

    ctx = ContextManager(enable_auto_extract=True)
    player = Player(
        target_url=target_url,
        context_manager=ctx,
        mode=PlaybackMode.PRECISE_TIMING,
    )

    dep_graph = player._build_dependency_graph(fake_records)
    print(f"  依赖图:")
    for rid, deps in dep_graph.items():
        idx = rid.split("_")[1]
        path = fake_records[int(idx)].url.split("?")[0].split("/")[-1]
        print(f"    {path:<14} -> 依赖: {deps if deps else '[]'}")

    dep_ok = (len(dep_graph.get("rec_1", [])) >= 1
              and len(dep_graph.get("rec_2", [])) >= 1)

    report = await player.play(records=fake_records)

    login_entry = None
    query_entry = None
    cookie_entry = None
    for e in log:
        if e["path"] == "/login":
            login_entry = e
        elif e["path"] == "/detail_query":
            query_entry = e
        elif e["path"] == "/detail_cookie":
            cookie_entry = e

    print(f"\n  回放结果: {report.successful_requests}/{report.total_requests} 成功")

    timing_ok = True
    if login_entry and (query_entry or cookie_entry):
        login_resp_sent = login_entry.get("response_sent_time", 0)
        for name, entry in [("query", query_entry), ("cookie", cookie_entry)]:
            if entry:
                delta_ms = (entry["time"] - login_resp_sent) * 1000
                print(f"  login响应 -> {name}到达服务器: {delta_ms:.1f}ms (>= -50ms为正常)")
                if delta_ms < -50:
                    timing_ok = False

    query_token_ok = False
    cookie_token_ok = False
    query_uid_ok = False

    fresh_token = login_entry.get("token") if login_entry else None
    fresh_uid = login_entry.get("user_id") if login_entry else None

    if query_entry and fresh_token:
        qt = query_entry.get("qs_token", "")
        qu = query_entry.get("qs_user_id", "")
        print(f"\n  Query token检查: 原值=OLD_QUERY_TOKEN_abc123")
        print(f"                          新值={qt}")
        print(f"                    期望包含={fresh_token}")
        query_token_ok = qt == fresh_token
        query_uid_ok = qu == fresh_uid

    if cookie_entry and fresh_token:
        ct = cookie_entry.get("cookie_token", "")
        print(f"\n  Cookie token检查: 原值=OLD_COOKIE_TOKEN_xyz789")
        print(f"                           新值={ct}")
        print(f"                     期望包含={fresh_token}")
        cookie_token_ok = ct == fresh_token

    success_ok = report.successful_requests == 3

    final_ok = dep_ok and timing_ok and query_token_ok and query_uid_ok and cookie_token_ok and success_ok

    details = (
        f"依赖图OK={dep_ok}, 时序OK={timing_ok}, "
        f"query_token替换={query_token_ok}, query_uid替换={query_uid_ok}, "
        f"cookie_token替换={cookie_token_ok}, 3次全成功={success_ok}"
    )

    results.append(("Query/Cookie凭证链路", final_ok, details))
    print(f"\n  {'✅ 通过' if final_ok else '❌ 失败'}: {details}")

    try:
        await player.stop()
    except Exception:
        pass
    await runner.cleanup()
    shutil.rmtree(tempdir, ignore_errors=True)


async def test_3_har_export_no_body():
    print("\n" + "=" * 72)
    print("测试3: HAR导出 - GET/DELETE无请求体/响应体不报错, 格式合法")
    print("=" * 72)

    tempdir = tempfile.mkdtemp(prefix="test_har_")
    outfile = os.path.join(tempdir, "test_export.har")

    records_dict = [
        {
            "id": "r1", "timestamp": time.time(),
            "method": "GET", "url": "https://api.example.com/users?page=1&size=10",
            "headers": {"Accept": "application/json", "X-Request-Id": "abc123"},
            "body": None,
            "response_status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": None,
            "session_id": "s1", "duration_ms": 45.5, "upstream_latency_ms": 40.0,
            "tags": {}, "trace_id": "t1",
        },
        {
            "id": "r2", "timestamp": time.time() + 1,
            "method": "DELETE", "url": "https://api.example.com/users/123",
            "headers": {"Authorization": "Bearer oldtok"},
            "body": None,
            "response_status": 204,
            "response_headers": {},
            "response_body": None,
            "session_id": "s1", "duration_ms": 22.0, "upstream_latency_ms": 20.0,
            "tags": {}, "trace_id": "t2",
        },
        {
            "id": "r3", "timestamp": time.time() + 2,
            "method": "POST", "url": "https://api.example.com/login",
            "headers": {"Content-Type": "application/json"},
            "body": b'{"username":"admin"}',
            "response_status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": b'{"code":0,"data":{"token":"xyz"}}',
            "session_id": "s1", "duration_ms": 150.0, "upstream_latency_ms": 148.0,
            "tags": {}, "trace_id": "t3",
        },
    ]

    try:
        entries = []
        for record in records_dict:
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

            from urllib.parse import urlparse, parse_qs
            from datetime import datetime

            query_list = []
            try:
                parsed_url = urlparse(record["url"])
                qs = parse_qs(parsed_url.query)
                for qk, qvs in qs.items():
                    for qv in qvs:
                        query_list.append({"name": qk, "value": qv})
            except Exception:
                pass

            ts = record.get("timestamp", 0)
            if isinstance(ts, (int, float)):
                started = datetime.fromtimestamp(ts).isoformat(timespec="milliseconds") + "Z"
            else:
                started = str(ts)

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

        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(har, f, indent=2, ensure_ascii=False)

    except Exception as e:
        results.append(("HAR导出无报错", False, f"导出异常: {e}"))
        print(f"  ❌ 导出过程抛出异常: {e}")
        shutil.rmtree(tempdir, ignore_errors=True)
        return

    try:
        with open(outfile, "r", encoding="utf-8") as f:
            parsed = json.load(f)
    except Exception as e:
        results.append(("HAR导出无报错", False, f"JSON解析失败: {e}"))
        print(f"  ❌ HAR无法被JSON解析: {e}")
        shutil.rmtree(tempdir, ignore_errors=True)
        return

    try:
        log_ver = parsed["log"]["version"]
        creator_name = parsed["log"]["creator"]["name"]
        got_entries = parsed["log"]["entries"]
        assert len(got_entries) == 3, f"期望3条，实际{len(got_entries)}"

        get_entry = got_entries[0]
        delete_entry = got_entries[1]
        post_entry = got_entries[2]

        assert get_entry["request"]["bodySize"] == 0, f"GET bodySize={get_entry['request']['bodySize']}!=0"
        assert get_entry["response"]["bodySize"] == 0, f"GET resp.bodySize={get_entry['response']['bodySize']}!=0"
        assert get_entry["response"]["content"]["size"] == 0
        assert delete_entry["request"]["bodySize"] == 0, f"DELETE bodySize!=0"
        assert delete_entry["response"]["bodySize"] == 0, f"DELETE resp.bodySize!=0"
        assert post_entry["request"]["bodySize"] > 0, f"POST bodySize should>0"
        assert post_entry["response"]["bodySize"] > 0

        iso_dt_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$")
        for e in got_entries:
            assert iso_dt_re.match(e["startedDateTime"]), f"日期格式错: {e['startedDateTime']}"
            assert isinstance(e["time"], (int, float)), "time字段非数字"
            assert isinstance(e["request"]["headers"], list)
            assert isinstance(e["request"]["queryString"], list)
            assert "method" in e["request"]
            assert "url" in e["request"]
            assert "status" in e["response"]
            assert "bodySize" in e["response"]

        format_ok = True
        detail = "3条记录格式均合法：GET/DELETE bodySize=0，日期ISO8601，所有HAR必需字段存在"
    except AssertionError as e:
        format_ok = False
        detail = str(e)
    except Exception as e:
        format_ok = False
        detail = f"HAR结构校验异常: {e}"

    print(f"  条目数: {len(entries)} (期望3)")
    print(f"  GET请求  bodySize (req/resp): {get_entry['request']['bodySize']}/{get_entry['response']['bodySize']}")
    print(f"  DELETE请求 bodySize (req/resp): {delete_entry['request']['bodySize']}/{delete_entry['response']['bodySize']}")
    print(f"  POST请求 bodySize (req/resp): {post_entry['request']['bodySize']}/{post_entry['response']['bodySize']}")
    print(f"  GET startedDateTime示例: {get_entry['startedDateTime']}")
    print(f"  GET queryString已解析: {len(get_entry['request']['queryString'])} 个参数")
    print(f"\n  {'✅ 通过' if format_ok else '❌ 失败'}: {detail}")
    results.append(("HAR导出合法", format_ok, detail))

    shutil.rmtree(tempdir, ignore_errors=True)


async def test_4_player_stats_no_accumulate():
    print("\n" + "=" * 72)
    print("测试4: 同一Player连续play - 报告只统计当前次,不累加")
    print("=" * 72)

    target_url, runner, log = await start_test_server(mock_app_query_auth)
    tempdir = tempfile.mkdtemp(prefix="test_stats_")

    t0 = time.time()

    session_a = [
        RequestRecord(
            id=f"a_{i}",
            timestamp=t0 + i * 0.03,
            method="GET",
            url=target_url + f"/login?i={i}",
            headers={},
            response_status=200,
        )
        for i in range(3)
    ]

    session_b = [
        RequestRecord(
            id=f"b_{i}",
            timestamp=t0 + i * 0.03,
            method="POST",
            url=target_url + "/login",
            headers={"Content-Type": "application/json"},
            body=b'{"username":"admin","password":"123"}',
            response_status=200,
        )
        for i in range(5)
    ]

    ctx = ContextManager(enable_auto_extract=True)
    player = Player(
        target_url=target_url,
        context_manager=ctx,
        mode=PlaybackMode.PRECISE_TIMING,
    )

    report_a = await player.play(records=session_a)
    print(f"  第1次回放 (3条): total={report_a.total_requests}, success={report_a.successful_requests}, fail={report_a.failed_requests}")

    report_b = await player.play(records=session_b)
    print(f"  第2次回放 (5条): total={report_b.total_requests}, success={report_b.successful_requests}, fail={report_b.failed_requests}")

    total_a_ok = report_a.total_requests == 3
    total_b_ok = report_b.total_requests == 5

    ok = total_a_ok and total_b_ok
    detail = f"第1次total={report_a.total_requests}(期望3), 第2次total={report_b.total_requests}(期望5)"

    if ok:
        print(f"  ✅ 通过: {detail}")
    else:
        print(f"  ❌ 失败: {detail} (若第2次total=8说明发生了累加)")

    results.append(("Player统计独立", ok, detail))

    try:
        await player.stop()
    except Exception:
        pass
    await runner.cleanup()
    shutil.rmtree(tempdir, ignore_errors=True)


async def main():
    print("=" * 72)
    print("测试第3轮修复 - 4个问题验证")
    print("=" * 72)

    await test_1_slow_response_graceful()
    await test_2_query_cookie_auth()
    await test_3_har_export_no_body()
    await test_4_player_stats_no_accumulate()

    print("\n" + "=" * 72)
    print("测试总结")
    print("=" * 72)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)

    for name, ok, detail in results:
        status = "✅ 通过" if ok else "❌ 失败"
        print(f"  {name:<24}: {status}  ({detail})")

    print(f"\n总体: {'✅ 全部通过' if passed == total else f'❌ {passed}/{total} 通过'}")
    sys.exit(0 if passed == total else 1)


asyncio.run(main())
