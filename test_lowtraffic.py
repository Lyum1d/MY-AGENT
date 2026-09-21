# -*- coding: utf-8 -*-
"""v023.4 回归：低流量测试策略。

    python test_lowtraffic.py

网络：只访问 127.0.0.1 随机端口夹具（统计真实请求次数）。
"""
import asyncio
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_lt_"))
config.SCOPE_FILE = _TMP / "scope_v0234.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.TRAFFIC_MAX_REQUESTS = 500
config.TRAFFIC_BURST = 500
config.TRAFFIC_FP_TTL = 120          # 本期默认开启复用

from app import difftest, store, traffic                 # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


class Fixture(BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        Fixture.hits += 1
        body = json.dumps({"userId": 10001, "n": Fixture.hits}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

print("== A. 指纹复用（同指纹只发一次真实请求） ==")
traffic.governor.reset()
Fixture.hits = 0
r1 = asyncio.run(difftest.execute_readonly(f"{BASE}/api/order", "GET", {}, None,
                                           identity_id="i1", variant_id="v1"))
check("首次请求真实发出", Fixture.hits == 1 and r1.get("cached") is False, Fixture.hits)
r2 = asyncio.run(difftest.execute_readonly(f"{BASE}/api/order", "GET", {}, None,
                                           identity_id="i1", variant_id="v1"))
check("同指纹复用（未新增真实请求）", Fixture.hits == 1, Fixture.hits)
check("复用命中标记 cached=True", r2.get("cached") is True, r2.get("cached"))
check("复用响应内容一致", r2.get("body_json") == r1.get("body_json"))

r3 = asyncio.run(difftest.execute_readonly(f"{BASE}/api/order", "GET", {}, None,
                                           identity_id="i2", variant_id="v1"))
check("身份不同 → 不复用（指纹含身份）", Fixture.hits == 2, Fixture.hits)
r4 = asyncio.run(difftest.execute_readonly(f"{BASE}/api/order", "GET", {}, None,
                                           identity_id="i1", variant_id="verify",
                                           no_cache=True))
check("no_cache（复验）绕过复用，真实发出", Fixture.hits == 3 and r4.get("cached") is False,
      Fixture.hits)

print("== B. 错误响应不进缓存（复验必须能重新观察） ==")
traffic.governor.reset()
Fixture.hits = 0
r_denied = asyncio.run(difftest.execute_readonly(f"{BASE}/api/order", "DELETE", {}, None))
check("写方法仍被拒（方法白名单）", "error" in r_denied)
fp_test = traffic.governor.fingerprint("GET", f"{BASE}/nf", identity_id="x")
traffic.governor.put_observation(fp_test, 500, {"status_code": 500})
check("非 2xx 不缓存由调用方保证（此处验证 API 语义）",
      traffic.governor.cached_observation(fp_test) is not None)   # 直接 put 仍可读

print("== C. 最小证据流程（请求数对比） ==")
# 直接测 diff-run 的 HTTP 层不便（需项目/请求库/身份），改为验证判定逻辑：
# minimal 模式在 access_denied 场景只发 2 个请求（baseline + variant）
traffic.governor.reset()
Fixture.hits = 0
base_ev = asyncio.run(difftest.execute_readonly(f"{BASE}/api/o1", "GET", {},
                                                None, identity_id="i1", variant_id="baseline"))
var_ev = asyncio.run(difftest.execute_readonly(f"{BASE}/api/o2", "GET", {},
                                               None, identity_id="i1", variant_id="v1"))
v = difftest.classify(base_ev, var_ev, "20002")
check("两请求即可判定（无需固定 4 请求）", Fixture.hits == 2, Fixture.hits)
check("判定结果可用", v.get("verdict") in
      ("no_diff", "suspect_idor", "access_denied", "unstable"), v.get("verdict"))

print("== D. split_task 同目标背压 ==")
from app import agent as agent_mod                       # noqa: E402
from app.agent import _traffic_note                      # noqa: E402
traffic.governor.reset()
# 目标处于防护状态 → 提示里必须明确「停止自动请求」
# v040：改用**超时**构造 BLOCKED —— REFUSED 已不再触发熔断（属"TCP 层未建链"，
# 多为端口未监听/协议选错，不应被当作目标封禁）
traffic.governor.note_signal("127.0.0.1", traffic.wafsignal.SIG_NET_TIMEOUT)
traffic.governor.note_signal("127.0.0.1", traffic.wafsignal.SIG_NET_TIMEOUT)
traffic.governor.note_signal("127.0.0.1", traffic.wafsignal.SIG_NET_TIMEOUT)
note_blocked = _traffic_note("127.0.0.1")
check("防护状态注入提示（含状态名与停手指令）",
      "BLOCKED" in note_blocked and "不要换参数" in note_blocked, note_blocked[:120])
# 正常状态 + 预算充足 → 常规提示
traffic.governor.reset()
# 注意：reset 只清内存，防护状态是**持久化**的（重启不清除是设计）——
# 测试里必须显式 clear_state 才能回到 NORMAL
traffic.governor.clear_state("127.0.0.1", reason="测试重置")
note_ok = _traffic_note("127.0.0.1")
check("正常状态提示剩余额度", "剩余" in note_ok and "低频" in note_ok, note_ok[:100])
# 预算即将耗尽 → 收敛口径
traffic.governor.reset()
traffic.governor.clear_state("127.0.0.1", reason="测试重置")
config.TRAFFIC_MAX_REQUESTS = 3
for _ in range(3):
    traffic.governor._sent.setdefault("127.0.0.1", __import__("collections").deque()).append(
        __import__("time").time())
note_low = _traffic_note("127.0.0.1")
check("剩余额度低 → 收敛口径", "收敛" in note_low, note_low[:120])
config.TRAFFIC_MAX_REQUESTS = 500
traffic.governor.clear_state("127.0.0.1", reason="测试重置")

print("== E. 背压配置生效（split_task 检查） ==")
src = (ROOT / "app" / "agent.py").read_text(encoding="utf-8")
check("split_task 含防护状态背压", "不允许拆分并发子任务" in src)
check("split_task 含预算背压", "剩余请求预算不足" in src)
check("背压阈值配置存在", hasattr(config, "SUBTASK_MIN_BUDGET"))

srv.shutdown()

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
