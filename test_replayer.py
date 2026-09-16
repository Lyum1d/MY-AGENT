# -*- coding: utf-8 -*-
"""HTTP 重放器回归测试（安全相关：这是唯一能对单个 URL 精确发请求的工具）。

    python test_replayer.py

安全边界：
- **不碰任何真实目标**。唯一真发请求的一节打的是本机临时 HTTP 服务（127.0.0.1），
  白名单临时写成 127.0.0.1，跑完即恢复。
- 其余全是纯字符串/参数解析判定。

重点测三类越权：非 http 协议（SSRF）、未授权域名、写方法（POST/PUT/DELETE）。
"""
import asyncio
import json
import sys
import tempfile
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_replay_test_"))
_ORIG = {"SCOPE_FILE": config.SCOPE_FILE,
         "REPLAY_MIN_INTERVAL": config.REPLAY_MIN_INTERVAL,
         "REPLAY_MAX_BODY": config.REPLAY_MAX_BODY}
config.SCOPE_FILE = _TMP / "scope.json"
config.REPLAY_MIN_INTERVAL = 0.0      # 测试里不等限速
config.SCOPE_FILE.write_text(
    json.dumps({"domains": ["example.com", "127.0.0.1"]}, ensure_ascii=False),
    encoding="utf-8")

from app import replayer                                  # noqa: E402
from app.executor import _host_in_scope                   # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


class _BlockedClient:
    """哨兵替代 httpx.AsyncClient：越权请求会撞到它，而不是真的发出去。

    为什么需要：这些测试全靠"授权校验先拦下"才成立。一旦校验被改坏，
    代码就会照常发请求——测试环境里能不能解析域名、有没有网，都不该成为安全保证。
    """

    def __init__(self, *a, **k):
        raise RuntimeError("NET-BLOCKED：授权校验失效，请求不该被发出")


_REAL_HTTPX = replayer.httpx


def block_network():
    replayer.httpx = types.SimpleNamespace(AsyncClient=_BlockedClient)


def allow_network():
    replayer.httpx = _REAL_HTTPX


def run(url, args="") -> list[dict]:
    async def _go():
        return [e async for e in replayer.run_replay(url, args)]
    return asyncio.run(_go())


def err_text(ev) -> str:
    return " ".join(str(e.get("data")) for e in ev if e.get("type") == "error")


def set_scope(domains) -> None:
    if domains == "BROKEN":
        config.SCOPE_FILE.write_text("{ not json", encoding="utf-8")
    elif domains is None:
        config.SCOPE_FILE.unlink(missing_ok=True)
    else:
        config.SCOPE_FILE.write_text(json.dumps({"domains": domains}, ensure_ascii=False),
                                     encoding="utf-8")


# ---------------------------------------------------------------------------
print("=== 1. 白名单判定：与 executor 必须一致（两份实现不能漂移）===")
scope = ["example.com", "10.0.0.5"]
for host, expect in [("example.com", True), ("a.b.example.com", True), ("10.0.0.5", True),
                     ("evil-example.com", False), ("example.com.evil.com", False),
                     ("other.org", False), ("", False)]:
    a = replayer._host_allowed(host, scope)
    b = _host_in_scope(host, scope)
    check(f"{host or '(空)'} 两份实现判定一致（{expect}）",
          a == b == expect, f"replayer={a} executor={b}")

block_network()   # 第 2~5 节不发任何请求；校验若失效会撞上哨兵而不是真的出去

print("=== 2. 协议与 SSRF ===")
ev = run("file:///etc/passwd")
check("file:// 被拒（不是 http/https）", "必须是完整 URL" in err_text(ev))
ev = run("gopher://127.0.0.1:6379/_INFO")
check("gopher:// 被拒", "必须是完整 URL" in err_text(ev))
ev = run("example.com/path")
check("缺少协议被拒", "必须是完整 URL" in err_text(ev))
# userinfo 伪装：urlparse 会取 @ 之后的真实主机，应拦下 evil.com
ev = run("http://example.com@evil.com/")
check("userinfo 伪装 http://example.com@evil.com 被拒（真实主机是 evil.com）",
      "不在授权白名单" in err_text(ev) and "evil.com" in err_text(ev))

print("=== 3. 未授权域名被拒（前缀/后缀伪装）===")
for u in ["http://evil-example.com/", "http://example.com.evil.com/",
          "http://notexample.com/", "http://evil.com/"]:
    ev = run(u)
    check(f"{u} 被拒", "不在授权白名单" in err_text(ev), err_text(ev)[:40])
    # command 事件是在"发请求之前"发的：没有它就说明确实没出去
    check(f"{u} 没有发出任何请求", not any(e.get("type") == "command" for e in ev))

print("=== 4. 写方法被硬禁用（重放器只读）===")
for m in ["POST", "PUT", "DELETE", "PATCH"]:
    ev = run("http://example.com/", f"-X {m}")
    check(f"{m} 被禁用", "已禁用" in err_text(ev), err_text(ev)[:40])
ev = run("http://example.com/", "-Xpost")
check("小写 -Xpost 同样被禁用（大小写不敏感）", "已禁用" in err_text(ev))
ev = run("http://example.com/", "-XPOST")
check("粘连写法 -XPOST 被解析为 POST 并禁用", "已禁用" in err_text(ev))
# 这些写法此前全都解析不出来 → method 静默保持默认的 GET。GET 本身是允许的，
# 所以不报任何错，模型以为在测 POST 型接口、实际发的是 GET，直接造成假阴性。
ev = run("http://example.com/", "--request POST")
check("--request POST 被识别（不再静默降级为 GET）", "已禁用" in err_text(ev), err_text(ev)[:40])
ev = run("http://example.com/", "-X=POST")
check("-X=POST 被识别（不再静默降级为 GET）", "已禁用" in err_text(ev), err_text(ev)[:40])
ev = run("http://example.com/", "-X delete")
check("小写方法名 -X delete 被识别并禁用", "已禁用" in err_text(ev), err_text(ev)[:40])
for m in ["GET", "HEAD", "OPTIONS"]:
    # 只读方法不应触发"已禁用"（后面会真的发一次 GET/HEAD）
    args = "" if m == "GET" else f"-X {m}"
    ev = run("http://example.com/", args)
    check(f"{m} 未被禁用", "已禁用" not in err_text(ev))

print("=== 5. 参数解析 ===")
m, q, h, t, e = replayer._parse_args("-X GET -H 'X-A: 1' -d 'a=b' --timeout 999")
check("解析出 method", m == "GET", m)
check("解析出 header", h.get("X-A") == "1", h)
check("解析出 query", q == [("a", "b")], q)
check("timeout 上限被夹到 20", t == 20, t)
_, _, _, t2, _ = replayer._parse_args("--timeout 1")
check("timeout 下限被夹到 2", t2 == 2, t2)
_, _, _, _, e3 = replayer._parse_args("-X 'GET")
check("引号不匹配时报错而不是崩溃", isinstance(e3, str), e3)
_, _, _, _, e4 = replayer._parse_args("--unknown-flag 123")
check("未知旗标被忽略（模型偶尔臆造）", e4 is None)
# 方法解析的完整矩阵：任一写法都必须落到真实方法上，不能悄悄退回默认 GET
for args, want in [("-X GET", "GET"), ("-X POST", "POST"), ("-XPOST", "POST"),
                   ("-Xpost", "POST"), ("--request PUT", "PUT"), ("--method DELETE", "DELETE"),
                   ("-X=PATCH", "PATCH"), ("", "GET")]:
    got = replayer._parse_args(args)[0]
    check(f"_parse_args({args!r}) → {want}", got == want, got)

print("=== 6. 白名单读取的兜底 ===")
set_scope(None)
_scope = replayer._load_scope()
# 原断言是「缺失时兜底写 example.com 并放行」——那是重放器早期自带的第二套实现，
# 与 app/scope.py 明确写下的设计取舍（fail-closed、不擅自创建默认文件）互相矛盾，
# 也与 test_scope.py 第 4 节的断言冲突。现统一按 fail-closed 语义修正：
# 缺配置 = 没有任何授权目标 = 一律拒绝，且**不得**替用户"顺手"配好白名单
# （否则使用者会误以为「授权已经配好了」）。
check("白名单文件不存在时返回空列表 → 一律拒绝（不放行）", _scope == [], _scope)
check("白名单文件不存在时不得擅自创建默认白名单（防「误以为已配好授权」）",
      not config.SCOPE_FILE.exists(), str(config.SCOPE_FILE))
set_scope("BROKEN")
_scope = replayer._load_scope()
check("白名单解析失败时返回空列表 → 一律拒绝（不放行）", _scope == [])
set_scope(["example.com", "127.0.0.1"])

print("=== 7. 真发一次请求（打本机临时服务，不是任何目标）===")
allow_network()   # 只有这一节允许真发请求，且只打 127.0.0.1


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"hello":"world"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Powered-By", "test")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "17")
        self.end_headers()

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"

ev = run(f"{base}/x?a=1")
out = "\n".join(str(e.get("data")) for e in ev if e.get("type") == "output")
check("拿到状态行", "HTTP 200" in out, out.splitlines()[0] if out else "")
check("回传了 Server/Content-Type 等头", "Content-Type" in out)
check("回传了 x-powered-by（指纹相关头）", "x-powered-by" in out.lower())
check("响应体被带回", "world" in out)
check("正常请求退出码 0", any(e.get("type") == "exit" and e.get("code") == 0 for e in ev))

ev = run(f"{base}/x", "-X HEAD")
check("HEAD 请求可用", any(e.get("type") == "exit" and e.get("code") == 0 for e in ev))

# 4xx/5xx 是测试结果，不是执行失败：退出码仍应为 0
import urllib.request  # noqa: E402
with urllib.request.urlopen(base + "/x", timeout=5):
    pass
config.REPLAY_MAX_BODY = 10
ev = run(f"{base}/x")
out = "\n".join(str(e.get("data")) for e in ev if e.get("type") == "output")
check("响应体超长时截断并说明总长度", "已截断" in out)
config.REPLAY_MAX_BODY = _ORIG["REPLAY_MAX_BODY"]

srv.shutdown()

config.SCOPE_FILE = _ORIG["SCOPE_FILE"]
config.REPLAY_MIN_INTERVAL = _ORIG["REPLAY_MIN_INTERVAL"]
config.REPLAY_MAX_BODY = _ORIG["REPLAY_MAX_BODY"]

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
