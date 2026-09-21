# -*- coding: utf-8 -*-
"""v023.3 回归：网络层 WAF 检测与状态机。

    python test_waf.py

网络：只访问 127.0.0.1 随机端口夹具（scope 白名单含 127.0.0.1）。
夹具覆盖计划 16.2 的清单 + 「本机断网」对照场景。
"""
import asyncio
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_waf_"))
config.SCOPE_FILE = _TMP / "scope_v0233.json"
config.SCOPE_FILE.write_text(
    '{"targets": [{"host": "127.0.0.1"}], "domains": ["127.0.0.1", "blocked-x.com",'
    ' "sibling.test", "recover-test.com", "plain403.com", "dns-broken.com",'
    ' "waf-test.com", "refuse-test.com", "timeout-test.com", "rate-test.com",'
    ' "other-clean.com"]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.TRAFFIC_MAX_REQUESTS = 500
config.TRAFFIC_BURST = 500

from app import store, traffic, wafsignal                # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


gov = traffic.governor


def fresh():
    gov.reset()
    return gov


print("== A. 信号分类器 ==")
check("429 → HTTP_429", wafsignal.classify_http(429, {}, "") == wafsignal.SIG_HTTP_429)
check("Retry-After 头 → HTTP_RETRY_AFTER",
      wafsignal.classify_http(503, {"Retry-After": "120"}, "") == wafsignal.SIG_HTTP_RETRY_AFTER)
check("挑战页文本 → CHALLENGE",
      wafsignal.classify_http(200, {}, "请完成验证码后继续") == wafsignal.SIG_HTTP_CHALLENGE)
check("WAF 页面文本 → WAF_PAGE",
      wafsignal.classify_http(403, {}, "您的 IP 已被封禁，访问频繁") == wafsignal.SIG_HTTP_WAF_PAGE)
check("普通 403 → 无信号（不误判）", wafsignal.classify_http(403, {}, "Forbidden") == wafsignal.SIG_NONE)
check("普通 200 → 无信号", wafsignal.classify_http(200, {}, "ok") == wafsignal.SIG_NONE)
sig, code = wafsignal.classify_network(ConnectionResetError(10054, "reset"))
check("RST 异常 → NET_RST + 10054", sig == wafsignal.SIG_NET_RST and code == 10054, (sig, code))
sig2, code2 = wafsignal.classify_network(ConnectionRefusedError(10061, "refused"))
check("连接拒绝 → NET_REFUSED + 10061", sig2 == wafsignal.SIG_NET_REFUSED, (sig2, code2))
sig3, _ = wafsignal.classify_network(TimeoutError("timed out"))
check("超时 → NET_TIMEOUT", sig3 == wafsignal.SIG_NET_TIMEOUT)
sig4, _ = wafsignal.classify_network(socket.gaierror(-2, "name or service not known"))
check("DNS 失败 → NET_DNS", sig4 == wafsignal.SIG_NET_DNS)
check("工具输出文本识别 10054", wafsignal.classify_text("err: ConnectionResetError WinError 10054") == wafsignal.SIG_NET_RST)
check("工具输出文本识别 connection refused",
      wafsignal.classify_text("Max retries exceeded: Connection refused") == wafsignal.SIG_NET_REFUSED)

print("== B. 状态机：CAUTION → COOLDOWN → BLOCKED ==")
g = fresh()
st = g.note_signal("waf-test.com", wafsignal.SIG_NET_RST, detail="首次 RST")
check("单次 RST → CAUTION（降速，不判封禁）", st["state"] == traffic.ST_CAUTION, st["state"])
lim_c = g._limits("waf-test.com")
lim_n = g._limits("other-clean.com")
check("CAUTION 时预算减半", lim_c["max_requests"] < lim_n["max_requests"],
      (lim_c["max_requests"], lim_n["max_requests"]))
check("CAUTION 时并发降为 1", lim_c["host_conc"] == 1 and lim_c["burst"] == 1)
st = g.note_signal("waf-test.com", wafsignal.SIG_NET_RST, detail="第二次 RST")
check("窗口内 2×RST → COOLDOWN", st["state"] == traffic.ST_COOLDOWN, st["state"])
st = g.note_signal("waf-test.com", wafsignal.SIG_NET_RST, detail="第三次 RST")
check("COOLDOWN 中再 RST → BLOCKED", st["state"] == traffic.ST_BLOCKED, st["state"])

# v040 修正：ConnectRefused（10061）= TCP 层没建链（端口未监听 / 协议选错），
# **不再触发熔断**。旧实现「2 次即 BLOCKED」曾导致一次协议选错就熔断整个根域名
# （lsnu 第三轮实测：对两个未开 HTTPS 的子域各打一次 https，其余 7 个子域全被误伤）。
g2 = fresh()
g2.note_signal("refuse-test.com", wafsignal.SIG_NET_REFUSED, os_error_code=10061)
st2 = g2.note_signal("refuse-test.com", wafsignal.SIG_NET_REFUSED, os_error_code=10061)
check("2×连接拒绝不再熔断（v040：与「被封禁」语义区分）",
      st2["state"] != traffic.ST_BLOCKED, st2["state"])
st2b = g2.note_signal("refuse-test.com", wafsignal.SIG_NET_REFUSED, os_error_code=10061)
check("多次连接拒绝仍不熔断（最多 CAUTION）",
      st2b["state"] in (traffic.ST_NORMAL, traffic.ST_CAUTION), st2b["state"])

g3 = fresh()
for i in range(3):
    st3 = g3.note_signal("timeout-test.com", wafsignal.SIG_NET_TIMEOUT)
check("窗口内 3×超时 → BLOCKED", st3["state"] == traffic.ST_BLOCKED, st3["state"])

g4 = fresh()
st4 = g4.note_signal("rate-test.com", wafsignal.SIG_HTTP_429, status_code=429)
check("HTTP 429 → 直接 COOLDOWN", st4["state"] == traffic.ST_COOLDOWN, st4["state"])

print("== C. 状态拒绝自动请求 / 重启不清除 ==")
fresh()
# v040：用**超时**（封禁的典型特征）构造 BLOCKED；REFUSED 已不再触发熔断
for _ in range(3):
    gov.note_signal("blocked-x.com", wafsignal.SIG_NET_TIMEOUT)
check("BLOCKED 状态已落库",
      (store.get_traffic_state("blocked-x.com") or {}).get("state") == traffic.ST_BLOCKED)
gov.reset()          # 模拟重启
try:
    asyncio.run(gov.acquire("https://blocked-x.com/api", tool_alias="t"))
    check("重启后仍拒绝自动请求", False)
except traffic.TrafficPaused:
    check("重启后仍拒绝自动请求（封禁状态持久化）", True)
check("状态与原因可读", gov.state_of("blocked-x.com")["state"] == traffic.ST_BLOCKED)

print("== D. 同 IP 聚合暂停 ==")
fresh()
# 两个兄弟主机都解析到 127.0.0.1（模拟同 IP 多 vhost）
gov.resolve_ip("127.0.0.1")
gov._load_state("127.0.0.1", "")
# 先给兄弟主机写一条带 resolved_ip 的状态
store.upsert_traffic_state("", {"root_domain": "sibling.test", "state": "NORMAL",
                                "reason": "", "resolved_ip": "127.0.0.1"})
gov._load_state("sibling.test", "")
# v040：用**超时**构造 BLOCKED（REFUSED 不再触发熔断）
for _ in range(3):
    st_peer = gov.note_signal("127.0.0.1", wafsignal.SIG_NET_TIMEOUT)
check("主目标进入 BLOCKED", st_peer["state"] == traffic.ST_BLOCKED, st_peer["state"])
peer = gov.state_of("sibling.test")
check("同 IP 兄弟主机一并暂停", peer["state"] == traffic.ST_BLOCKED, peer.get("state"))

print("== E. 手动恢复探测（单次只读） ==")


class Fixture(BaseHTTPRequestHandler):
    mode = "ok"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if Fixture.mode == "blocked":
            body = "您的 IP 已被封禁".encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

fresh()
# v040：用**超时**构造 BLOCKED（REFUSED 不再触发熔断）
for _ in range(3):
    gov.note_signal("127.0.0.1", wafsignal.SIG_NET_TIMEOUT)
check("前置：目标已 BLOCKED", gov.state_of("127.0.0.1")["state"] == traffic.ST_BLOCKED)

Fixture.mode = "blocked"
r1 = asyncio.run(gov.manual_probe("127.0.0.1", f"{BASE}/health"))
check("探测仍被拦截 → BLOCKED（不连续重试）",
      r1["ok"] is False and r1["state"] == traffic.ST_BLOCKED, r1)

Fixture.mode = "ok"
r2 = asyncio.run(gov.manual_probe("127.0.0.1", f"{BASE}/health"))
check("探测成功 → RECOVERED（未自动恢复）",
      r2["ok"] is True and r2["state"] == traffic.ST_RECOVERED, r2)
try:
    asyncio.run(gov.acquire(f"{BASE}/api", tool_alias="t"))
    check("RECOVERED 未确认前仍不发自动请求", False)
except traffic.TrafficPaused:
    check("RECOVERED 未确认前仍不发自动请求", True)
st_c = gov.confirm_resume("127.0.0.1")
check("确认后回 NORMAL", st_c["state"] == traffic.ST_NORMAL, st_c["state"])
check("确认后可正常取许可",
      bool(asyncio.run(gov.acquire(f"{BASE}/api", tool_alias="t"))))

print("== F. 成功响应让 CAUTION 自动恢复 ==")
fresh()
gov.note_signal("recover-test.com", wafsignal.SIG_NET_TIMEOUT)
check("超时 → CAUTION", gov.state_of("recover-test.com")["state"] == traffic.ST_CAUTION)
gov.note_success("recover-test.com")
check("后续成功 → 回 NORMAL", gov.state_of("recover-test.com")["state"] == traffic.ST_NORMAL)

print("== G. 不误判：普通 403 / 本机断网 ==")
fresh()
st_g = gov.note_signal("plain403.com", wafsignal.SIG_NONE)   # 普通 403 无信号
check("普通 403 不产生信号（状态不变）", st_g["state"] == traffic.ST_NORMAL, st_g["state"])
# 本机断网：DNS 失败 → 只标 CAUTION 级别信号，不直接 BLOCKED
st_dns = gov.note_signal("dns-broken.com", wafsignal.SIG_NET_DNS)
check("DNS 失败 → 不直接判封禁（无状态升级）",
      st_dns["state"] in (traffic.ST_NORMAL, traffic.ST_CAUTION), st_dns["state"])

print("== H. 状态接口字段 ==")
s = gov.stats("127.0.0.1")
for key in ("state", "resolved_ip", "recent_signals", "last_error_label", "signal_count"):
    check(f"stats 含 {key}", key in s, list(s.keys())[:8])

srv.shutdown()

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
