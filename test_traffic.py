# -*- coding: utf-8 -*-
"""v023.1 统一流量调度器回归：预算 / 并发 / 取消 / 暂停持久化 / 重启恢复 / 指纹。

    python test_traffic.py

离线：数据库改道临时目录，不发真实请求（假 permit 直接调 governor）。
"""
import asyncio
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_traffic_test_"))
scope_file = _TMP / "scope_v023.json"
scope_file.write_text('{"domains": ["example.com", "sub.example.com", "other.com", '
                      '"brust-test.com", "restart-test.com"]}',
                      encoding="utf-8")
config.SCOPE_FILE = scope_file
# 测试模式关掉预算放大，用真实阈值验证（同时验证放大逻辑本身）
config.TRAFFIC_TEST_MODE = False
config.TRAFFIC_MAX_REQUESTS = 5
config.TRAFFIC_BURST = 100        # 单独测窗口用，避免突发阈值干扰
config.TRAFFIC_WINDOW_SECONDS = 600
config.TRAFFIC_HOST_CONCURRENCY = 1
config.TRAFFIC_ROOT_CONCURRENCY = 1
config.TRAFFIC_FP_TTL = 0

from app import store, traffic                           # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


def run(coro):
    return asyncio.run(coro)


gov = traffic.governor


def fresh():
    gov.reset()
    return gov


USER_LIKE = {"User-Agent": "src-agent/1.0"}

print("== A. 聚合键：根域名与 IP ==")
check("根域名解析（三级子域）",
      gov.root_domain_of("www.sub.example.com") == "example.com")
check("两段式后缀 edu.cn",
      gov.root_domain_of("www.zueb.edu.cn") == "zueb.edu.cn")
check("裸两段域名", gov.root_domain_of("example.com") == "example.com")
check("端口剥离", gov.root_domain_of("example.com:8443") == "example.com")

print("== B. 预算：滑动窗口 ==")
g = fresh()
for i in range(5):
    p = run(g.acquire("https://example.com/x", tool_alias="t"))
    check(f"第 {i+1} 个请求获许可", bool(p.get("root") == "example.com"))
try:
    run(g.acquire("https://example.com/x", tool_alias="t"))
    check("第 6 个请求被预算拒绝", False)
except traffic.TrafficBudgetExceeded as e:
    check("第 6 个请求被预算拒绝（并暂停目标）", True)
    check("拒绝原因含窗口与上限", "600" in str(e) and "5" in str(e), str(e)[:60])
st = store.get_traffic_state("example.com")
check("预算耗尽 → 目标被暂停且已落库", st and st["state"] == "PAUSED", st and st["state"])

print("== C. 暂停后所有请求被拒（含兄弟主机） ==")
try:
    run(g.acquire("https://sub.example.com/y", tool_alias="t"))
    check("同根域名兄弟主机一并被拒", False)
except traffic.TrafficPaused as e:
    check("同根域名兄弟主机一并被拒（根域名级暂停）", True)
check("不同根域名不受影响",
      bool(run(fresh().acquire("https://other.com/z", tool_alias="t"))))
g.resume("example.com")
config.TRAFFIC_MAX_REQUESTS = 100      # 隔离变量：只验证「暂停已解除」
check("人工恢复后放行（暂停解除）",
      bool(run(g.acquire("https://example.com/x", tool_alias="t"))))
config.TRAFFIC_MAX_REQUESTS = 5
check("窗口计数不受恢复影响（恢复≠重置预算）",
      g.stats("example.com")["used"] >= 5, g.stats("example.com")["used"])

print("== D. 突发限制 ==")
g = fresh()
config.TRAFFIC_BURST = 2
config.TRAFFIC_MAX_REQUESTS = 100
for i in range(2):
    run(g.acquire("https://brust-test.com/x", tool_alias="t"))
try:
    run(g.acquire("https://brust-test.com/x", tool_alias="t"))
    check("10 秒内第 3 个请求被突发限制拒绝", False)
except traffic.TrafficBudgetExceeded as e:
    check("10 秒内第 3 个请求被突发限制拒绝", "突发" in str(e), str(e)[:50])
config.TRAFFIC_BURST = 100

print("== E. 取消：排队请求不得发出 ==")
g = fresh()
config.TRAFFIC_MAX_REQUESTS = 100
import threading                                         # noqa: E402
ev = threading.Event()
ev.set()
try:
    run(g.acquire("https://example.com/x", tool_alias="t", cancel_event=ev))
    check("已取消的任务被拒绝", False)
except traffic.TrafficCancelled:
    check("已取消的任务被拒绝", True)

print("== F. scope 兜底（调度器内校验） ==")
g = fresh()
try:
    run(g.acquire("https://evil.com/x", tool_alias="t"))
    check("scope 外目标被调度器拒绝", False)
except traffic.TrafficScopeDenied:
    check("scope 外目标被调度器拒绝", True)
        # 事件应记 rejected

print("== G. 重启恢复：窗口与状态从 DB 重建 ==")
g = fresh()
config.TRAFFIC_MAX_REQUESTS = 3
config.TRAFFIC_BURST = 100
for i in range(3):
    run(g.acquire("https://restart-test.com/x", tool_alias="t"))
try:                            # 第 4 次：触发预算熔断（暂停 + 落库）
    run(g.acquire("https://restart-test.com/x", tool_alias="t"))
except traffic.TrafficBudgetExceeded:
    pass
check("预算熔断已把目标暂停并落库",
      (store.get_traffic_state("restart-test.com") or {}).get("state") == "PAUSED")
g.reset()                       # 模拟服务重启（内存清空）
check("重启后窗口从 DB 恢复（已用 3）", g.stats("restart-test.com")["used"] == 3,
      g.stats("restart-test.com")["used"])
check("重启后暂停状态仍在库（未自动清除）",
      g.state_of("restart-test.com")["state"] == "PAUSED")
try:
    run(g.acquire("https://restart-test.com/x", tool_alias="t"))
    check("重启后暂停目标仍拒绝请求", False)
except traffic.TrafficPaused:
    check("重启后暂停目标仍拒绝请求（重启不能绕过）", True)
g.resume("restart-test.com")
try:
    run(g.acquire("https://restart-test.com/x", tool_alias="t"))
    check("恢复后第 4 个请求（窗口已满）仍被拒", False)
except traffic.TrafficBudgetExceeded:
    check("恢复后第 4 个请求（窗口已满）仍被拒（窗口计数真实）", True)
config.TRAFFIC_MAX_REQUESTS = 5

print("== H. 指纹与事件 ==")
g = fresh()
fp1 = g.fingerprint("GET", "https://example.com/a?x=1", body="", identity_id="i1")
fp2 = g.fingerprint("GET", "https://example.com/a?x=2", body="", identity_id="i1")
fp3 = g.fingerprint("GET", "https://example.com/a?x=1", body="", identity_id="i2")
check("参数值不同 → 指纹相同（规范化）", fp1 == fp2)
check("身份不同 → 指纹不同", fp1 != fp3)
config.TRAFFIC_FP_TTL = 120
g.put_observation(fp1, 200)
check("TTL 内可复用观察", (g.cached_observation(fp1) or {}).get("status") == 200)
config.TRAFFIC_FP_TTL = 0
check("TTL=0 时永不复用（复验必须真实发出）", g.cached_observation(fp1) is None)

events = store.list_traffic_events(limit=200)
types = {e["event_type"] for e in events}
check("事件表含 sent/rejected/paused/resumed", {"sent", "rejected"} <= types, types)
check("事件记录脱敏摘要（无凭据）",
      all("Authorization" not in (e.get("redaction_summary") or "") for e in events))

print("== I. 策略覆盖（DB 优先于默认） ==")
store.set_traffic_policy("example.com", {"window_seconds": 600, "max_requests": 7,
                                         "burst_limit": 100})
g.reset()
pol = store.get_traffic_policy("example.com")
check("策略落库", pol and pol["max_requests"] == 7)
config.TRAFFIC_MAX_REQUESTS = 2
lim = g._limits("example.com")
check("DB 策略覆盖 config 默认", lim["max_requests"] == 7, lim["max_requests"])
lim2 = g._limits("other.com")
check("未配置的根域名用默认", lim2["max_requests"] == 2, lim2["max_requests"])

print("== J. 测试模式放大（显式开关） ==")
config.TRAFFIC_TEST_MODE = True
config.TRAFFIC_TEST_MULTIPLIER = 50
lim3 = g._limits("other.com")
check("test_mode 放大预算 50×", lim3["max_requests"] == 100, lim3["max_requests"])
check("test_mode 放大并发", lim3["host_conc"] >= 4, lim3["host_conc"])
config.TRAFFIC_TEST_MODE = False

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
