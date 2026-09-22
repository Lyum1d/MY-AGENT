# -*- coding: utf-8 -*-
"""v040 回归：ConnectRefused 不再误熔断 + 多子域测绘的协议预筛。

    python test_040_fixes.py

现场（lsnu 第三轮）：Agent 对两个**未开 HTTPS** 的子域各打了一次 `https://`，两次都是
`ConnectRefused(10061)` —— 这本该被读作「**TCP 层没建链**（端口未监听/协议选错）」，
但当时 `REFUSED_TO_BLOCK = 2` 让它直接升级为 **BLOCKED**，把**整个根域名 campus.test 熔断**，
**连累其余 7 个子域（含最有价值的 jwgl）全部无法测绘**，本轮 4 个测绘目标只完成 1 个。

语义区分（本次修正的核心）：
  · RST(10054) / 静默丢包(timeout) → 「能连上但被打断」= **封禁的典型特征**（保留熔断）
  · ConnectionRefused(10061)       → 「TCP 层根本没建链」= **协议/端口选错**（降级为提示）

覆盖：
A. **行为测试：连续 REFUSED 只到 CAUTION，绝不 BLOCKED**
B. RST / 超时 的封禁判定仍然有效（不能误伤既有防护）
C. 源码层回归：REFUSED 分支不再指向 ST_BLOCKED
D. 提示词含「协议预筛」硬规则
E. 指纹索引已补高校/政企业务系统 + 指纹名→小节 映射
F. py_exec 补 final_url / location
"""
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_040_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.DATA_DIR = _TMP / "data"
config.DATA_DIR.mkdir(parents=True, exist_ok=True)
config.TRAFFIC_TEST_MODE = False

from app import traffic, wafsignal                        # noqa: E402
from app import agent as agent_mod                        # noqa: E402
import app.store as store                                 # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


print("=" * 68)
print("A. 行为测试：连续 REFUSED 不得熔断（复现本轮故障）")
print("=" * 68)
g = traffic.governor
ROOT_A = "test-refused.example.com"
g._signals.pop(ROOT_A, None)
try:
    g.clear_state(ROOT_A)
except Exception:
    pass

states = []
for i in range(4):
    st = g.note_signal(ROOT_A, wafsignal.SIG_NET_REFUSED, os_error_code=10061,
                       url=f"https://{ROOT_A}/", project_id="p040",
                       detail="ConnectError")
    states.append(st.get("state"))
check("A1 第 1 次 REFUSED 后不是 BLOCKED", states[0] != traffic.ST_BLOCKED, states[0])
check("A2 第 2 次 REFUSED 后不是 BLOCKED（**旧实现此处会熔断**）",
      states[1] != traffic.ST_BLOCKED, states[1])
check("A3 连续 4 次 REFUSED 仍不是 BLOCKED", all(s != traffic.ST_BLOCKED for s in states),
      str(states))
check("A4 最多只到 CAUTION（提示，不阻断）",
      all(s in (traffic.ST_NORMAL, traffic.ST_CAUTION) for s in states), str(states))
# 从库里的状态记录复核最终落库状态（不依赖对象私有方法）
row = g._load_state(ROOT_A, "p040")
check("A5 落库状态也不是阻断态",
      row.get("state") not in (traffic.ST_BLOCKED, traffic.ST_COOLDOWN,
                               traffic.ST_PAUSED, traffic.ST_MANUAL_PROBE),
      str(row.get("state")))
try:
    g.clear_state(ROOT_A)
except Exception:
    pass

print()
print("B. RST / 超时的封禁判定仍然有效（不误伤既有防护）")
print("=" * 68)
ROOT_B = "test-rst.example.com"
try:
    g.clear_state(ROOT_B)
except Exception:
    pass
s1 = g.note_signal(ROOT_B, wafsignal.SIG_NET_RST, os_error_code=10054,
                   url=f"https://{ROOT_B}/", project_id="p040", detail="RST")
s2 = g.note_signal(ROOT_B, wafsignal.SIG_NET_RST, os_error_code=10054,
                   url=f"https://{ROOT_B}/", project_id="p040", detail="RST")
check("B1 2 次 RST → COOLDOWN（封禁判定保留）",
      s2.get("state") in (traffic.ST_COOLDOWN, traffic.ST_BLOCKED), s2.get("state"))

ROOT_C = "test-timeout.example.com"
try:
    g.clear_state(ROOT_C)
except Exception:
    pass
tc = None
for _ in range(3):
    tc = g.note_signal(ROOT_C, wafsignal.SIG_NET_TIMEOUT, url=f"https://{ROOT_C}/",
                       project_id="p040", detail="timeout")
check("B2 3 次超时 → BLOCKED（封禁判定保留）",
      tc.get("state") == traffic.ST_BLOCKED, tc.get("state"))
for r in (ROOT_B, ROOT_C):
    try:
        g.clear_state(r)
    except Exception:
        pass

print()
print("C. 源码层回归：REFUSED 分支不再指向 ST_BLOCKED")
print("=" * 68)
tr_src = Path(traffic.__file__).read_text(encoding="utf-8")
check("C1 不再有「REFUSED 且计数达阈值 → BLOCKED」的判定",
      "SIG_NET_REFUSED and counts.get(sig, 0) >= REFUSED_TO_BLOCK" not in tr_src)
check("C2 REFUSED 分支存在且注释点明语义",
      "SIG_NET_REFUSED:" in tr_src and "TCP 层根本没建链" in tr_src)
check("C3 文档字符串说明了 v040 修正",
      "ConnectRefused（10061）不再升级到任何阻断态" in tr_src)

print()
print("D. 提示词含「协议预筛」硬规则")
print("=" * 68)
SYS = agent_mod.SYSTEM_PROMPT
check("D1 要求优先用首页 href 的原始协议", "原始协议" in SYS)
check("D2 指出 ConnectRefused 不是封禁",
      "ConnectRefused" in SYS and "不是" in SYS)
check("D3 要求换协议重试一次", "换协议重试一次" in SYS)
check("D4 要求批量脚本用 try/except 包住每个目标",
      "try/except 包住每个目标" in SYS)

print()
print("E. 指纹索引补齐高校/政企业务系统")
print("=" * 68)
idx = ROOT / "data" / "kb" / "product-fingerprint-index.md"
doc = idx.read_text(encoding="utf-8")
for label, key in [("E1 强智教务", "强智"), ("E2 正方教务", "正方"), ("E3 金智教务", "金智"),
                   ("E4 泛微 OA", "泛微"), ("E5 致远 OA", "致远"), ("E6 蓝凌 OA", "蓝凌")]:
    check(f"{label} 在表内", key in doc)
check("E7 含「指纹名 → 小节」机械映射表", "机械映射" in doc)
check("E8 映射含 Kodcloud → KodExplorer",
      "Kodcloud-System" in doc and "KodExplorer" in doc)
check("E9 映射含 VAppServer → TRS", "VAppServer" in doc)
check("E10 小节编号连续（一~六）",
      all(f"## {c}、" in doc for c in "一二三四五六"))

print()
print("F. py_exec 响应补跳转字段")
print("=" * 68)
br = Path(__import__("app.pyexec_bridge", fromlist=["x"]).__file__).read_text(encoding="utf-8")
check("F1 提供 final_url", '"final_url"' in br)
check("F2 提供 location（响应头 Location）", '"location"' in br)
check("F3 文档/注释说明为何补它", "v040" in br and "AttributeError" in br)

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
