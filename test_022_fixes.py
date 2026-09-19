# -*- coding: utf-8 -*-
"""v022 整改报告修复回归：P1-2 token 回传 / P2-4 超时 emit / P2-5 省略清单。

    python test_022_fixes.py

离线。三组检查对应 021 整改报告的三个适用缺陷。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


print("== A. P2-5：schema 截断省略清单 ==")
from app import config, registry                     # noqa: E402
reg = registry.ToolRegistry()
reg.loaded = True
# 造 10 个假工具（L1 命令行），配额 3 → 应省略 7 个
from app.registry import Tool                        # noqa: E402
for i in range(10):
    reg._by_alias[f"tool{i}"] = Tool(
        name=f"工具{i}", alias=f"tool{i}", category="测试", type="命令行",
        rel_path=f"tools/t{i}.exe", description=f"test tool {i}",
        risk_level="L1", risk_reason="测试", scriptable=True,
        executable=f"builtin://x{i}")
reg.tools = list(reg._by_alias.values())
schemas = reg.build_schemas(max_tools=3)
check("配额 3 → schema 数 3", len(schemas) == 3, len(schemas))
check("last_omitted_aliases 记录省略 7 个", len(reg.last_omitted_aliases) == 7,
      reg.last_omitted_aliases)
check("省略的都在低优先端", "tool9" in reg.last_omitted_aliases and
      "tool0" not in reg.last_omitted_aliases)

print("== B. P1-2：state 接口 pending 含 token（源码断言） ==")
main_src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
check("session_state 回传 token", '"token": pend.get("token", "")' in main_src)
check("session_state 回传 second", '"second": bool(pend.get("double_confirm"))' in main_src)
appjs = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
check("前端刷新恢复透传 token", "d.pending_confirm.token" in appjs)

print("== C. P2-4：确认超时 emit 事件（源码断言） ==")
agent_src = (ROOT / "app" / "agent.py").read_text(encoding="utf-8")
check("超时分支有 emit（特征串）",
      "确认超时（{config.CONFIRM_TIMEOUT}s）：已按拒绝处理" in agent_src)

print("== D. 报告结论澄清（主线从未有过 C-1/H-1/M-1，属测试组本地修复） ==")
llm_src = (ROOT / "app" / "llm.py").read_text(encoding="utf-8")
check("确认 C-1 不在主线（需测试组提交 changes 包）", "_PROVIDER_DEAD_STATUS" not in llm_src)
check("确认 H-1 不在主线（需测试组提交 changes 包）", "_SIGNAL_RE" not in agent_src)
store_src = (ROOT / "app" / "store.py").read_text(encoding="utf-8")
check("确认 M-1 不在主线（需测试组提交 changes 包）", "_tokenize" not in store_src)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
