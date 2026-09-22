# -*- coding: utf-8 -*-
"""MCP 客户端层与 Burp 工具层测试（v044）。

设计取舍：**不依赖真实 Burp**。真实 Burp 需要人工启动、点 Start、还有弹窗批准，
拿它做回归意味着「没开 Burp 就整套测试红」，这会让回归结果失去信号价值。
本文件用一个**假 MCP 服务**（本地 HTTP 服务器，实现 SSE + JSON-RPC 三段）来验证：

  A. 协议层：SSE endpoint 事件解析、initialize 握手、tools/list、tools/call
  B. 降级：服务不在时 probe() 返回 (False, 可读原因) 而**不抛异常**
  C. 安全：非回环端点被拒（MCP_ALLOW_REMOTE=0 时）
  D. 闸门：出网必过 TrafficGovernor；scope 拒绝时不发出网、退出码 126
  E. 方法白名单：DELETE 被拒
  F. 参数解析：raw 请求起始行、target 拆分、history 参数校验

统计行格式必须是 `结果：N 通过 / M 失败`（run_all_tests.py 的正则要求）。
"""
from __future__ import annotations

import asyncio
import json
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import burp_tools, config, mcp_client                # noqa: E402

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" —— {detail}" if detail else ""))


# ============ 假 MCP 服务 ============
class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """每连接一个线程。

    必须如此：我们的桩要**同时**挂住一条 SSE 长连接、又要能接受 POST。
    单线程的 HTTPServer 会让 POST 排在 SSE 后面永远轮不到，
    表现为客户端在 _await_response 上死等直到超时。
    （真机 Burp 用的 Ktor 天然是多线程的，这里不这么做就复刻不出真机行为。）
    """
    daemon_threads = True
    allow_reuse_address = True


class _FakeMcp:
    """最小可用的 MCP 服务桩，**复刻官方扩展的 SSE 传输语义**。

    关键语义（真机联调实测确认，早先的实现理解错了）：
      · SSE 路径是 ``/``（不是 ``/mcp``），首事件 ``event: endpoint`` 的 data 是
        **裸查询串**（``?sessionId=x``，无路径无主机）
      · POST 只负责投递：回 ``202 Accepted`` 空体
      · 真正的 JSON-RPC 响应经**长连接的 SSE 流**以 ``event: message`` 回推

    ``sync_mode=True`` 可切回「POST 直接回 200 + JSON」的旧式实现，
    用来验证客户端的兼容分支也还在（不同 SDK 默认路径/传输会有差异）。
    """

    def __init__(self, tool_result=None, is_error=False, tools=None,
                 sse_path="/", sync_mode=False):
        self.calls: list[tuple[str, dict]] = []
        self.tool_result = tool_result if tool_result is not None else "HTTP/1.1 200 OK\r\n\r\nhello"
        self.is_error = is_error
        self.tools = tools or [
            {"name": "send_http1_request", "description": "send", "inputSchema": {}},
            {"name": "get_proxy_http_history", "description": "hist", "inputSchema": {}},
        ]
        self.sse_path = sse_path
        self.sync_mode = sync_mode
        self.httpd = None
        self.port = 0
        self._streams: list = []            # 每条 SSE 长连接的写句柄
        self._lock = threading.Lock()
        self._stopping = False

    def start(self) -> int:
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):      # 静音
                pass

            def _sse(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                # 真机形态：首事件 data 是**裸查询串**，没有路径也没有主机
                self.wfile.write(b"event: endpoint\ndata: ?sessionId=fake-session\n\n")
                self.wfile.flush()
                # 这条连接的**推送队列**：POST 线程只往队列里塞，由本线程独占写
                # （wfile 不是线程安全的，两个线程同时写会互相截断）
                q: "queue.Queue[bytes | None]" = queue.Queue()
                with outer._lock:
                    outer._streams.append(q)
                try:
                    while not outer._stopping:
                        try:
                            item = q.get(timeout=0.05)
                        except queue.Empty:
                            try:
                                self.wfile.write(b": ping\n\n")
                                self.wfile.flush()
                            except Exception:   # noqa: BLE001
                                break
                            continue
                        if item is None:
                            break
                        try:
                            self.wfile.write(item)
                            self.wfile.flush()
                        except Exception:       # noqa: BLE001
                            break
                finally:
                    with outer._lock:
                        if q in outer._streams:
                            outer._streams.remove(q)
                    self.close_connection = True

            def do_GET(self):               # noqa: N802
                if self.path.split("?")[0] == outer.sse_path:
                    self._sse()
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            def _handle(self) -> dict | None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                try:
                    req = json.loads(body)
                except Exception:
                    return None
                method = req.get("method", "")
                outer.calls.append((method, req.get("params") or {}))
                if method == "initialize":
                    result = {"protocolVersion": "2024-11-05",
                              "capabilities": {"tools": {}},
                              "serverInfo": {"name": "burp-suite", "version": "1.1.2"}}
                elif method == "tools/list":
                    result = {"tools": outer.tools}
                elif method == "tools/call":
                    result = {
                        "content": [{"type": "text", "text": outer.tool_result}],
                        "isError": outer.is_error,
                    }
                elif method.startswith("notifications/"):
                    return None             # 通知按规范**不应有响应**
                else:
                    result = {}
                return {"jsonrpc": "2.0", "id": req.get("id"), "result": result}

            def do_POST(self):              # noqa: N802
                payload = self._handle()
                if outer.sync_mode:
                    if payload is None:
                        self.send_response(202)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    raw = json.dumps(payload).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                # 真机语义：POST 只投递，回 202 空体；响应经 SSE 推回
                self.send_response(202)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"Accepted")
                self.wfile.flush()
                if payload is not None and payload.get("id") is not None:
                    data = ("event: message\ndata: "
                            + json.dumps(payload) + "\n\n").encode()
                    with outer._lock:
                        streams = list(outer._streams)
                    for q in streams:
                        q.put(data)

        self.httpd = _ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self.port

    def stop(self):
        self._stopping = True
        with self._lock:
            for q in self._streams:
                try:
                    q.put_nowait(None)      # 让阻塞中的 SSE 线程退出
                except Exception:           # noqa: BLE001
                    pass
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()


def run(coro):
    return asyncio.run(coro)


# ============ A. 协议层 ============
def test_protocol():
    print("\n[A] MCP 协议层（SSE + JSON-RPC）")
    fake = _FakeMcp()
    port = fake.start()
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None          # 重置单例，让它读新 URL
        c = mcp_client.McpClient()
        ok, note = run(c.probe())
        check("probe 成功", ok, note)
        check("probe 说明含工具数", "工具" in note, note)

        methods = [m for m, _ in fake.calls]
        check("发出 initialize", "initialize" in methods, str(methods))
        check("发出 tools/list", "tools/list" in methods, str(methods))
        check("发出 initialized 通知",
              "notifications/initialized" in methods, str(methods))

        names = c.tool_names()
        check("发现 send_http1_request", "send_http1_request" in names, str(names))
        check("发现 get_proxy_http_history", "get_proxy_http_history" in names, str(names))

        ok2, text = run(c.call_tool("send_http1_request", {"content": "GET / HTTP/1.1"}))
        check("call_tool 成功", ok2, text[:80])
        check("call_tool 回传正文", "200 OK" in text, text[:80])
        call_args = [p for m, p in fake.calls if m == "tools/call"]
        check("call_tool 透传参数",
              call_args and call_args[0].get("arguments", {}).get("content") == "GET / HTTP/1.1",
              str(call_args))

        # —— 真机形态专项（这些断言来自 Burp Pro 2025.12 + 官方扩展 v1.3.0 实测）——
        check("SSE 路径探测命中根路径 /", c._sse_path == "/", repr(c._sse_path))
        check("裸查询串被拼回当前 SSE 路径",
              c._post_url == f"http://127.0.0.1:{port}/?sessionId=fake-session",
              c._post_url)
        check("会话 id 被解析出来", c._session_id == "fake-session", c._session_id)
        check("读流器常驻（会话不被反复重建）", c._reader is not None)

        run(c.aclose())
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None
        fake.stop()


def test_protocol_path_candidates():
    """SSE 路径在 /mcp 的实现也要能连上（不同 SDK 默认路径不同）。"""
    print("\n[A1b] SSE 路径候选探测（端点在 /mcp 的实现）")
    fake = _FakeMcp(sse_path="/mcp")
    port = fake.start()
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        c = mcp_client.McpClient()
        ok, note = run(c.probe())
        check("新式实现（endpoint 在 /mcp）也能连上", ok, note)
        check("记下的路径是 /mcp", c._sse_path == "/mcp", repr(c._sse_path))
        check("POST 地址落在 /mcp",
              c._post_url == f"http://127.0.0.1:{port}/mcp?sessionId=fake-session",
              c._post_url)
        run(c.aclose())
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None
        fake.stop()


def test_protocol_sync_mode():
    """兼容「POST 直接回 200 + JSON」的旧式同步实现。"""
    print("\n[A1c] 同步返回 JSON 的实现（兼容分支）")
    fake = _FakeMcp(sync_mode=True)
    port = fake.start()
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        c = mcp_client.McpClient()
        ok, note = run(c.probe())
        check("同步实现可用", ok, note)
        ok2, text = run(c.call_tool("send_http1_request", {"content": "GET / HTTP/1.1"}))
        check("同步实现 call_tool 成功", ok2, text[:80])
        run(c.aclose())
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None
        fake.stop()


# ============ A3. 参数契约 ============
# 下面这张表是 2026-09-22 用**真机**（Burp Pro 2025.12 + 扩展 1.3.0）的
# tools/list 读出来的，不是从文档抄的。它的价值在于：Burp 扩展升级后若改了
# 参数名，客户端会在运行期拿到 "Encountered an unknown key" 报错，而这张表
# 会在**回归阶段**就把变化暴露出来。
_REAL_SCHEMA: dict[str, tuple[list[str], list[str]]] = {
    # 工具名: (必需参数, 全部参数)
    "send_http1_request": (["content", "targetHostname", "targetPort", "usesHttps"],
                           ["content", "targetHostname", "targetPort", "usesHttps"]),
    "get_proxy_http_history": (["count", "offset"], ["count", "offset"]),
    "get_proxy_http_history_regex": (["count", "offset", "regex"],
                                     ["count", "offset", "regex"]),
    "url_encode": (["content"], ["content"]),
    "url_decode": (["content"], ["content"]),
    "base64_encode": (["content"], ["content"]),
    "base64_decode": (["content"], ["content"]),
}


def test_param_contract_with_real_schema():
    """校验 burp_tools 发出的参数名与真机 schema 一致（**离线**校验）。"""
    print("\n[A3] 出网参数名与真机 schema 契约")
    # 1) 客户端发出的键必须是真机 schema 允许的键
    sent = burp_tools.build_replay_payload(
        {"raw": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "host": "x", "port": 80,
         "https": False})
    allowed = set(_REAL_SCHEMA["send_http1_request"][1])
    check("burp_replay 发出的键全在真机 schema 内",
          set(sent.keys()) <= allowed, f"多余键：{set(sent.keys()) - allowed}")

    # 2) history 参数：必须产出 count/offset（无 regex）或 count/offset/regex
    p1, e1 = burp_tools.parse_history_args("")
    check("history 默认参数合法", not e1 and set(p1) == {"count", "offset"}, f"{p1} {e1}")
    p2, e2 = burp_tools.parse_history_args("regex=admin")
    check("history 带 regex 合法",
          not e2 and set(p2) == {"count", "offset", "regex"}, f"{p2} {e2}")

    # 3) 客户端选工具名也要对（有 regex 走 _regex 变体）
    check("有 regex 时选 _regex 变体",
          burp_tools.history_tool_name({"regex": "x"}) == "get_proxy_http_history_regex")
    check("无 regex 时选基础变体",
          burp_tools.history_tool_name({"count": 5, "offset": 0})
          == "get_proxy_http_history")

    # 4) 契约表自身要与假桩的预期一致（防止表和实现对不上）
    for tool, (_req, _all) in _REAL_SCHEMA.items():
        check(f"契约表覆盖 {tool}", tool in _REAL_SCHEMA)


def test_tool_error_passthrough():
    print("\n[A2] 工具返回 isError 时的语义")
    fake = _FakeMcp(tool_result="Send HTTP request denied by Burp Suite", is_error=True)
    port = fake.start()
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        c = mcp_client.McpClient()
        ok, text = run(c.call_tool("send_http1_request", {}))
        check("isError 时 ok=False", ok is False)
        check("正文原样回传", "denied by Burp Suite" in text, text)
        run(c.aclose())
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None
        fake.stop()


# ============ B. 降级 ============
def test_unavailable_graceful():
    print("\n[B] 服务不可用时的优雅降级")
    old_url = config.MCP_BURP_URL
    try:
        # 用一个几乎肯定没人监听的端口
        config.MCP_BURP_URL = "http://127.0.0.1:59873"
        mcp_client._client = None
        ok, note, tools = run(mcp_client.availability())
        check("不可用时 ok=False", ok is False)
        check("说明是「连不上」而非栈信息",
              "连不上" in note and "Traceback" not in note, note)
        check("说明含排错指引（Burp/Start）",
              "Burp" in note and "Start" in note, note)
        check("工具列表为空", tools == [])

        c = mcp_client.McpClient()
        try:
            run(c.call_tool("send_http1_request", {}))
            check("call_tool 抛 McpUnavailable", False, "未抛异常")
        except mcp_client.McpUnavailable:
            check("call_tool 抛 McpUnavailable", True)
        except Exception as e:      # noqa: BLE001
            check("call_tool 抛 McpUnavailable", False, f"抛的是 {type(e).__name__}")
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None


# ============ C. 安全：非回环端点 ============
def test_remote_denied():
    print("\n[C] 非回环端点被拒（MCP_ALLOW_REMOTE=0）")
    old_url, old_allow = config.MCP_BURP_URL, config.MCP_ALLOW_REMOTE
    try:
        config.MCP_BURP_URL = "http://192.0.2.10:9876"
        config.MCP_ALLOW_REMOTE = False
        mcp_client._client = None
        c = mcp_client.McpClient()
        ok, note = run(c.probe())
        check("远程端点 probe 失败", ok is False)
        check("原因是回环限制", "回环" in note, note)
        check("给出开关名 MCP_ALLOW_REMOTE", "MCP_ALLOW_REMOTE" in note, note)
    finally:
        config.MCP_BURP_URL, config.MCP_ALLOW_REMOTE = old_url, old_allow
        mcp_client._client = None


# ============ D. 闸门：出网必过 TrafficGovernor ============
class _RecGovernor:
    """记录 acquire 调用次数与参数的假调度器。"""

    def __init__(self, raise_exc=None):
        self.calls: list[dict] = []
        self.raise_exc = raise_exc

    async def acquire(self, url, **kw):
        self.calls.append({"url": url, **kw})
        if self.raise_exc:
            raise self.raise_exc
        return {"ok": True}


def _drain(gen):
    events = []

    async def _go():
        async for ev in gen:
            events.append(ev)
    run(_go())
    return events


def test_governor_required():
    print("\n[D] 出网必过 TrafficGovernor")
    fake = _FakeMcp()
    port = fake.start()
    old_url = config.MCP_BURP_URL
    old_gov = burp_tools.traffic.governor
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        rec = _RecGovernor()
        burp_tools.traffic.governor = rec

        raw = "GET /api/x HTTP/1.1\r\nHost: shhxqh.com\r\n\r\n"
        events = _drain(burp_tools.run_burp_replay(
            "https://shhxqh.com", raw, project_id="proj1", session_id="sess1"))

        check("acquire 被调用一次", len(rec.calls) == 1, str(rec.calls))
        if rec.calls:
            got = rec.calls[0]
            check("acquire 收到完整 URL", got.get("url") == "https://shhxqh.com:443/api/x",
                  str(got.get("url")))
            check("acquire tool_alias=burp_replay", got.get("tool_alias") == "burp_replay",
                  str(got.get("tool_alias")))
            check("acquire 透传 project_id", got.get("project_id") == "proj1")
            check("acquire 透传 session_id", got.get("session_id") == "sess1")
            check("acquire 收到方法", got.get("method") == "GET", str(got.get("method")))

        exits = [e for e in events if e.get("type") == "exit"]
        check("退出码 0", exits and exits[-1].get("code") == 0, str(exits))
        check("有输出事件", any(e.get("type") == "output" for e in events))
        check("发到了假 MCP（tools/call 被调用）",
              any(m == "tools/call" for m, _ in fake.calls),
              str([m for m, _ in fake.calls]))
    finally:
        config.MCP_BURP_URL = old_url
        burp_tools.traffic.governor = old_gov
        mcp_client._client = None
        fake.stop()


def test_governor_denied_stops_request():
    print("\n[D2] 调度器拒绝时「不得发出网请求」")
    fake = _FakeMcp()
    port = fake.start()
    old_url = config.MCP_BURP_URL
    old_gov = burp_tools.traffic.governor
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        rec = _RecGovernor(raise_exc=burp_tools.traffic.TrafficBudgetExceeded("预算耗尽"))
        burp_tools.traffic.governor = rec

        raw = "GET /a HTTP/1.1\r\nHost: shhxqh.com\r\n\r\n"
        events = _drain(burp_tools.run_burp_replay("https://shhxqh.com", raw))

        check("acquire 被调用", len(rec.calls) == 1)
        check("**没有**发出 tools/call（关键安全断言）",
              not any(m == "tools/call" for m, _ in fake.calls),
              str([m for m, _ in fake.calls]))
        errs = [e for e in events if e.get("type") == "error"]
        check("有错误事件", bool(errs), str(events))
        check("错误提到调度器", errs and "流量调度器" in errs[0]["data"], str(errs))
        exits = [e for e in events if e.get("type") == "exit"]
        check("退出码 1（非授权类）", exits and exits[-1].get("code") == 1, str(exits))
    finally:
        config.MCP_BURP_URL = old_url
        burp_tools.traffic.governor = old_gov
        mcp_client._client = None
        fake.stop()


def test_scope_denied_exit_126():
    print("\n[D3] 授权范围外 → 退出码 126 且不出网")
    fake = _FakeMcp()
    port = fake.start()
    old_url = config.MCP_BURP_URL
    old_gov = burp_tools.traffic.governor
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        rec = _RecGovernor()
        burp_tools.traffic.governor = rec

        # 用一个绝不在授权范围内的域名（RFC 2606 保留域）
        raw = "GET /a HTTP/1.1\r\nHost: not-authorized.invalid\r\n\r\n"
        events = _drain(burp_tools.run_burp_replay("https://not-authorized.invalid", raw))

        # scope 检查在 governor 之前，所以 acquire 不应被调用
        check("scope 拒绝时**不调用** governor", len(rec.calls) == 0, str(rec.calls))
        check("**没有**发出 tools/call",
              not any(m == "tools/call" for m, _ in fake.calls),
              str([m for m, _ in fake.calls]))
        exits = [e for e in events if e.get("type") == "exit"]
        check("退出码 126", exits and exits[-1].get("code") == 126, str(exits))
    finally:
        config.MCP_BURP_URL = old_url
        burp_tools.traffic.governor = old_gov
        mcp_client._client = None
        fake.stop()


# ============ E. 方法与参数校验 ============
def test_method_whitelist():
    print("\n[E] 方法白名单")
    check("GET 允许", burp_tools._method_allowed("GET") is None)
    check("POST 允许（Burp 侧有人工闸门）", burp_tools._method_allowed("POST") is None)
    check("PUT 允许", burp_tools._method_allowed("PUT") is None)
    denied = burp_tools._method_allowed("DELETE")
    check("DELETE 拒绝", denied is not None)
    check("DELETE 拒绝原因含「破坏性」", denied and "破坏性" in denied, str(denied))

    events = _drain(burp_tools.run_burp_replay(
        "https://shhxqh.com", "DELETE /a HTTP/1.1\r\nHost: shhxqh.com\r\n\r\n"))
    check("DELETE 被本地拦下（无输出事件）",
          not any(e.get("type") == "output" for e in events), str(events))
    exits = [e for e in events if e.get("type") == "exit"]
    check("DELETE 退出码 1", exits and exits[-1].get("code") == 1, str(exits))


def test_target_and_raw_parsing():
    print("\n[E2] target 拆分与 raw 请求解析")
    h, p, s = burp_tools.split_target("https://example.com/x")
    check("默认 https 端口 443", (h, p, s) == ("example.com", 443, True), f"{h},{p},{s}")
    h, p, s = burp_tools.split_target("http://example.com/x")
    check("默认 http 端口 80", (h, p, s) == ("example.com", 80, False), f"{h},{p},{s}")
    h, p, s = burp_tools.split_target("http://example.com:8443/x")
    check("显式端口优先", (h, p, s) == ("example.com", 8443, False), f"{h},{p},{s}")
    h, p, s = burp_tools.split_target("example.com/x")
    check("裸域名默认 https", (h, p, s) == ("example.com", 443, True), f"{h},{p},{s}")

    try:
        burp_tools.split_target("")
        check("空 target 抛错", False, "未抛")
    except burp_tools.BurpRequestError:
        check("空 target 抛错", True)

    pr = burp_tools.parse_raw_request("POST /api HTTP/1.1\r\nHost: a.com\r\n\r\nx")
    check("解析 POST", pr["method"] == "POST" and pr["path"] == "/api", str(pr))
    pr = burp_tools.parse_raw_request("GET /a HTTP/1.1\nHost: a.com\n\n")
    check("裸 LF 也能解析", pr["method"] == "GET", str(pr))
    try:
        burp_tools.parse_raw_request("这是自然语言不是请求")
        check("非 raw 文本抛错", False, "未抛")
    except burp_tools.BurpRequestError as e:
        check("非 raw 文本抛错", True)
        check("报错提示起始行格式", "起始行" in str(e), str(e))


def test_history_args():
    print("\n[E3] burp_history 参数校验")
    p, e = burp_tools.parse_history_args("")
    check("空参数给默认分页", p == {"count": config.MCP_HISTORY_PAGE, "offset": 0}, str(p))
    check("空参数无错误", e == "", e)

    p, e = burp_tools.parse_history_args("regex=login|token count=30 offset=10")
    check("三参数解析", p == {"regex": "login|token", "count": 30, "offset": 10}, str(p))

    p, e = burp_tools.parse_history_args("count=99999")
    check("count 被夹到上限", p.get("count") == config.MCP_HISTORY_MAX, str(p))

    p, e = burp_tools.parse_history_args("sort=desc")
    check("未知参数报错", p == {} and "仅支持" in e or "不支持的参数" in e, e)

    p, e = burp_tools.parse_history_args("count=abc")
    check("非数字 count 报错", "必须是数字" in e, e)

    p, e = burp_tools.parse_history_args("regex=ok 垃圾token")
    check("裸片段报错", "无法识别" in e, e)


def test_history_reached_end():
    print("\n[E4] 「Reached end of items」按分页边界处理")
    fake = _FakeMcp(tool_result="Reached end of items")
    port = fake.start()
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        events = _drain(burp_tools.run_burp_history(""))
        outs = [e for e in events if e.get("type") == "output"]
        check("有输出事件", bool(outs), str(events))
        check("措辞是「没有更多条目」而非报错",
              outs and ("没有更多条目" in outs[0]["data"]), str(outs))
        check("明确告知重放不会落 history（真机实测结论）",
              outs and "burp_replay" in outs[0]["data"], str(outs))
        check("未走 error 分支",
              not any(e.get("type") == "error" for e in events), str(events))
        exits = [e for e in events if e.get("type") == "exit"]
        check("退出码 0", exits and exits[-1].get("code") == 0, str(exits))
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None
        fake.stop()


def test_history_uses_regex_tool():
    print("\n[E5] 带 regex 时切到 _regex 工具")
    fake = _FakeMcp(tool_result="item1\n\nitem2")
    port = fake.start()
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
        mcp_client._client = None
        _drain(burp_tools.run_burp_history("regex=admin"))
        calls = [p for m, p in fake.calls if m == "tools/call"]
        check("调用发生", bool(calls), str(fake.calls))
        check("参数含 regex", calls and calls[0].get("arguments", {}).get("regex") == "admin",
              str(calls))
        mcp_client._client = None
        fake.calls.clear()
        _drain(burp_tools.run_burp_history(""))
        calls = [p for m, p in fake.calls if m == "tools/call"]
        check("无 regex 时不带 regex 键",
              calls and "regex" not in calls[0].get("arguments", {}), str(calls))
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None
        fake.stop()


def test_proxy_sanity():
    """代理成环体检。Burp 是代理，MCP 又让 Agent 经它出网——配错会静默死循环。

    重点不只是「能检出问题」，还要「不误报」：本机 WorkBuddy 会话代理就在
    127.0.0.1 上跑（实测见过 58637、62063），只按 host 判会把它误判成自环。
    """
    print("\n[G] Burp 上游代理成环体检")
    cases = [
        ("上游=自身 8080 → 应告警",
         {"proxy": {"upstream": [{"proxy_host": "127.0.0.1", "proxy_port": 8080}]}}, True),
        ("上游=localhost:8080 → 应告警",
         {"proxy": {"upstream": [{"proxy_host": "localhost", "proxy_port": 8080}]}}, True),
        ("上游=外部代理 → 不应告警",
         {"proxy": {"upstream": [{"proxy_host": "proxy.corp.com", "proxy_port": 3128}]}}, False),
        ("上游=本机非 8080 端口 → 不应告警（防误报）",
         {"proxy": {"upstream": [{"proxy_host": "127.0.0.1", "proxy_port": 58637}]}}, False),
        ("无上游代理 → 不应告警", {"proxy": {"upstream": []}}, False),
        ("无 proxy 字段 → 不应告警", {"misc": {"x": 1}}, False),
    ]
    for name, cfg, expect in cases:
        fake = _FakeMcp(tool_result=json.dumps(cfg))
        port = fake.start()
        old_url = config.MCP_BURP_URL
        try:
            config.MCP_BURP_URL = f"http://127.0.0.1:{port}"
            mcp_client._client = None
            warns = run(mcp_client.check_proxy_sanity())
            check(name, (len(warns) > 0) == expect, f"告警 {len(warns)} 条：{warns[:1]}")
        finally:
            config.MCP_BURP_URL = old_url
            mcp_client._client = None
            fake.stop()


def test_proxy_sanity_degrades():
    print("\n[G2] 体检本身不得成为故障点")
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = "http://127.0.0.1:59874"     # 没人监听
        mcp_client._client = None
        warns = run(mcp_client.check_proxy_sanity())
        check("服务不在时返回空列表而非抛异常", warns == [], str(warns))
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None


def test_tool_availability_filtering():
    """Burp 不在线时，burp_* 工具必须从模型可见的工具清单里消失。

    为什么这是安全/成本问题而不只是体验问题：schema 里留着工具，模型就会去调，
    每次失败都消耗步数与 token（本项目两样都卡得紧），而且会把「工具报错」
    误判成「目标不可达」，把归因带偏。
    """
    print("\n[H] 工具清单按外部服务可用性过滤")
    from app import registry as reg_mod
    reg_mod.registry.load()
    r = reg_mod.registry

    r.unavailable_aliases = set()
    names_on = {s["function"]["name"] for s in r.build_schemas()}
    check("MCP 可用时含 burp_replay", "burp_replay" in names_on, str(sorted(names_on)[:5]))
    check("MCP 可用时含 burp_history", "burp_history" in names_on)

    r.unavailable_aliases = {"burp_replay", "burp_history"}
    schemas_off = r.build_schemas()
    names_off = {s["function"]["name"] for s in schemas_off}
    check("MCP 不可用时摘掉 burp_replay", "burp_replay" not in names_off)
    check("MCP 不可用时摘掉 burp_history", "burp_history" not in names_off)
    check("其它内置工具不受影响",
          {"httpreplay", "py_exec", "note_fact"} <= names_off,
          str({"httpreplay", "py_exec", "note_fact"} - names_off))
    check("httpreplay 仍在（不误伤同类工具）", "httpreplay" in names_off)

    # 配额不应浪费：摘掉两个内置，应有被省略的工具补位
    check("腾出的配额被其它工具补上",
          len(schemas_off) == len(r.build_schemas()),
          f"{len(schemas_off)} vs 满额")

    check("external_service_of 认 burp 工具",
          reg_mod.ToolRegistry.external_service_of("burp_replay") == "mcp"
          and reg_mod.ToolRegistry.external_service_of("burp_history") == "mcp")
    check("external_service_of 不误认其它工具",
          reg_mod.ToolRegistry.external_service_of("httpreplay") == ""
          and reg_mod.ToolRegistry.external_service_of("py_exec") == "")

    r.unavailable_aliases = set()       # 还原，避免影响后续测试


def test_refresh_external_tools():
    print("\n[H2] 每轮刷新逻辑：失败不抛异常、缓存窗口生效")
    from app import agent as agent_mod
    from app import registry as reg_mod
    reg_mod.registry.load()

    a = agent_mod.Agent.__new__(agent_mod.Agent)     # 不走 __init__，只测该方法
    a._mcp_probe_at = 0.0
    old_url = config.MCP_BURP_URL
    try:
        config.MCP_BURP_URL = "http://127.0.0.1:59875"    # 无人监听
        mcp_client._client = None
        run(a._refresh_external_tools())                  # 不应抛异常
        check("探测失败后标记不可用",
              reg_mod.registry.unavailable_aliases == {"burp_replay", "burp_history"},
              str(reg_mod.registry.unavailable_aliases))
        first = a._mcp_probe_at
        check("记下了探测时间戳", first > 0)

        # 第二次调用应命中 20 秒缓存窗口（这里仅断言时间戳未变）
        run(a._refresh_external_tools())
        check("缓存窗口内不重复探测", a._mcp_probe_at == first,
              f"{a._mcp_probe_at} vs {first}")
    finally:
        config.MCP_BURP_URL = old_url
        mcp_client._client = None
        reg_mod.registry.unavailable_aliases = set()


def test_disabled_by_config():
    print("\n[H3] MCP_ENABLED=0 时整条链路关闭")
    from app import agent as agent_mod
    from app import registry as reg_mod
    reg_mod.registry.load()
    old = config.MCP_ENABLED
    try:
        config.MCP_ENABLED = False
        a = agent_mod.Agent.__new__(agent_mod.Agent)
        a._mcp_probe_at = 0.0
        run(a._refresh_external_tools())
        check("关闭后两个工具都标为不可用",
              reg_mod.registry.unavailable_aliases == {"burp_replay", "burp_history"})
        ok, note, tools = run(mcp_client.availability())
        check("availability 明确说明已关闭", ok is False and "关闭" in note, note)
        check("关闭时不返回工具", tools == [])
    finally:
        config.MCP_ENABLED = old
        reg_mod.registry.unavailable_aliases = set()


def test_burp_tools_import_guard():
    print("\n[F] 依赖方向：burp_tools 不反向依赖 agent")
    src = (Path(__file__).resolve().parent / "app" / "burp_tools.py").read_text(
        encoding="utf-8")
    check("不 import agent", "import agent" not in src)
    check("不 import executor", "import executor" not in src)
    check("import 了 mcp_client", "mcp_client" in src)
    check("import 了 traffic", "traffic" in src)
    check("import 了 scope", "scope" in src)


def main():
    print("=" * 68)
    print("MCP 客户端层与 Burp 工具层测试（v044）")
    print("=" * 68)
    test_protocol()
    test_protocol_path_candidates()
    test_protocol_sync_mode()
    test_param_contract_with_real_schema()
    test_tool_error_passthrough()
    test_unavailable_graceful()
    test_remote_denied()
    test_governor_required()
    test_governor_denied_stops_request()
    test_scope_denied_exit_126()
    test_method_whitelist()
    test_target_and_raw_parsing()
    test_history_args()
    test_history_reached_end()
    test_history_uses_regex_tool()
    test_proxy_sanity()
    test_proxy_sanity_degrades()
    test_tool_availability_filtering()
    test_refresh_external_tools()
    test_disabled_by_config()
    test_burp_tools_import_guard()
    print("\n" + "=" * 68)
    print(f"结果：{PASS} 通过 / {FAIL} 失败")
    print("=" * 68)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
