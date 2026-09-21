# -*- coding: utf-8 -*-
"""v041 回归：token 预算预警与收尾 + 请求消耗回显 + 编排脚本续跑修复。

    python test_041_fixes.py

现场（lsnu 第三轮）：任务因 **token 预算耗尽（811,983 / 上限 800,000）** 被平台主动停止，
**一句最终结论都没输出** —— 测绘做完了大半，报告只能靠人工从事实库回捞，属交付层面的缺口。

复盘出三个问题（本次全部落地）：
  ① `_budget_note` **只按「步数」预警**，token 仅在**超限瞬间**硬熔断 → 「步数还有余、token 先超」
     时预警根本不触发（本轮 17/30 步、token 却到了 101%）；
  ② 模型**不知道自己花了多少次目标请求**（自述"贴近上限是估的"），而目标流量是合规纪律里
     最敏感的额度，应当给确数；
  ③ 编排脚本 `--sid= --rerun` 组合**读到上一轮历史 `done` 就退出**（实测 elapsed 1.4s），
     新任务等于没跑。

覆盖：
A. token 预算默认 250 万 + 预警比例 0.8
B. **行为测试：token 达预警比例即触发「必须立刻收敛」**（低占用时不触发）
C. **行为测试：上下文里给出「已发目标请求数」确数**
D. 编排脚本用「事件基线」游标续跑（源码断言）
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                     # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_041_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False

from app import agent as agent_mod                         # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


print("=" * 68)
print("A. token 预算默认值与预警比例")
print("=" * 68)
check("A1 RUN_TOKEN_BUDGET 默认 250 万",
      config.RUN_TOKEN_BUDGET == 2_500_000, f"{config.RUN_TOKEN_BUDGET:,}")
check("A2 预警比例默认 0.8", abs(config.TOKEN_BUDGET_WARN_RATIO - 0.8) < 1e-9,
      str(config.TOKEN_BUDGET_WARN_RATIO))

print()
print("B. 行为测试：token 达预警比例即要求收敛")
print("=" * 68)
base = {"step_no": 6, "total": 30, "elapsed": 300,
        "token_budget": config.RUN_TOKEN_BUDGET}

n_low = agent_mod._budget_note({**base, "tokens": int(config.RUN_TOKEN_BUDGET * 0.5)})
check("B1 token 用掉 50% → 仍提示「预算充足」", "预算充足" in n_low, n_low[-60:])

n_warn = agent_mod._budget_note({**base, "tokens": int(config.RUN_TOKEN_BUDGET * 0.85)})
check("B2 token 用掉 85% → 触发「必须立刻收敛」",
      "必须立刻收敛" in n_warn, n_warn[-80:])
check("B3 且点明是 token 口径（不是步数）", "token" in n_warn, n_warn[-80:])
check("B4 收敛提示要求先出结论", "整理成结论" in n_warn or "给结论" in n_warn)

# 步数预警仍然有效（原有能力不能被改坏）
n_step = agent_mod._budget_note({"step_no": 29, "total": 30, "elapsed": 10,
                                 "tokens": 1000, "token_budget": config.RUN_TOKEN_BUDGET})
check("B5 步数预警仍然有效（原有能力保留）", "必须立刻收敛" in n_step, n_step[-60:])

print()
print("C. 行为测试：给出「已发目标请求数」确数")
print("=" * 68)
n_req = agent_mod._budget_note({**base, "tokens": 1000, "requests": 42})
check("C1 上下文中出现请求次数", "42" in n_req, n_req)
check("C2 措辞明确是「目标请求」", "目标请求" in n_req, n_req)
n_noreq = agent_mod._budget_note({**base, "tokens": 1000})
check("C3 无该字段时不报错、不显示（兼容旧调用）",
      "目标请求" not in n_noreq, n_noreq)

print()
print("D. 编排脚本：续跑用「事件基线」游标")
print("=" * 68)
runner = Path(r"C:\Users\Lianaxber\WorkBuddy\2026-09-21-10-32-43\.workbuddy\tools_run_lsnu.py")
check("D1 脚本存在", runner.exists(), str(runner))
if runner.exists():
    src = runner.read_text(encoding="utf-8")
    check("D2 引入 rerun_baseline", "rerun_baseline" in src)
    check("D3 探测当前最大 _seq", '"last_event_id": 0' in src and "_seq" in src)
    check("D4 消费游标优先用基线",
          "if rerun_baseline:" in src and "last_seq = rerun_baseline" in src)
    check("D5 注释说明了「读到历史 done 提前退出」的原因",
          "历史" in src and "done" in src)

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
