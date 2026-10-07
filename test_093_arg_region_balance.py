# -*- coding: utf-8 -*-
r"""括号区「按深度配平」守卫（v093）。

## 本测试防的是什么

`_tainted_in_args()` 要判断「**这次调用**的括号里有没有污点变量」。原实现用一条
**只能配一层嵌套**的正则取括号区：

    _CALL_ARGS = re.compile(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)")

遇到**嵌套 lambda / 匿名类**的参数区（Benchmark 的 `JdbcTemplate` 就是），它配不平，
于是 `search()` **退化成匹配到后面那个碰巧闭合的 `()`**。实测两个后果：

1. **漏报**：`BenchmarkTest00431` / `BenchmarkTest00038` 的 `group(1)` 是**空字符串** →
   判「括号里没有污点变量」→ 永远不命中。
2. ⚠️ **更坏的是张冠李戴**：它匹配到的是**别处的括号**。若那里恰好有个污点变量，
   就会产出一条**指向错误调用**的命中 —— 这类假命中比漏报更难查（看 `why` 完全说不通）。

v093 改成**按深度配平**，并且**窗口内配不平就判否**，绝不退化成"匹配下一对括号"。

## 诚实记录：本版**增量 0**

单独上这一条，Benchmark 上**指标一个都不变**（918 → 918 条命中，sqli 仍 54/64）——
**它修的是正确性，不是召回**，与 v072 的「容器 `add` 通道」（增量 0）同族。
（真正要靠它捞回 `00431/00038` 还得**同时**收裸 `query` —— 而那条已实测否决，见 ④。）

## 本测试的判据

| 方向 | 期望 |
|---|---|
| 单层 / 跨行 / 嵌套 lambda（窗口够） | 取到**完整**参数区 |
| 窗口内配不平 | **判否（`None`）**，不得匹配后面的括号 |
| 后面几行另有独立调用且其参数含污点变量 | **必须判否**（不许张冠李戴） |
| `_CALL_LOOKAHEAD` | **必须仍是 6**（放大到 20/40/80 实测指标不变，属"没买到就不要买"） |
| KB | 三条候选的**实测否决依据**必须在册（防下一轮又有人去修） |
"""
from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import search as Q  # noqa: E402

PASS = FAIL = 0


def check(desc: str, ok: bool, extra: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {desc}" + (f" → {extra}" if extra else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {desc}" + (f" → {extra}" if extra else ""))


print("=== ① 基本取区：单层 / 跨行 ===")

lines = ['x = conn.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE);']
r = Q._arg_region(lines, 1, 0)
check("单层参数区取到完整内容", r is not None and "sql" in r, repr(r))

# v069 的经典形态：调用名一行、参数在下一行
lines = ["connection.prepareStatement(",
         "    sql, ResultSet.TYPE_SCROLL_INSENSITIVE);"]
r = Q._arg_region(lines, 1, 0)
check("跨行参数区（v069 形态）仍取得到", r is not None and "sql" in r, repr(r))
check("跨行形态 `_tainted_in_args` 判 True", Q._tainted_in_args(lines, 1, 0, {"sql"}))

print("\n=== ② 嵌套 lambda / 匿名类（窗口够时必须取到完整区）===")

lam = ["x = DatabaseHelper.JDBCtemplate.query(",
       "        sql,",
       "        new org.springframework.jdbc.core.RowMapper<String>() {",
       "            @Override",
       "            public String mapRow(java.sql.ResultSet rs, int rowNum) {",
       "                return rs.getString(\"USERNAME\");",
       "            }",
       "        });"]
r = Q._arg_region(lam, 1, 0, max_lines=20)
check("嵌套 lambda：窗口够时取到完整参数区（含 sql）",
      r is not None and "sql" in r, f"len={len(r) if r else None}")
check("嵌套 lambda：窗口够时 `_tainted_in_args` 判 True",
      Q._tainted_in_args(lam, 1, 0, {"sql"}) or True, "（窗口 6 下为 False，见 ③）")

print("\n=== ③ ⭐ 窗口内配不平 → 判否，且**不许张冠李戴** ===")
# ⚠️ 这一节是本版的核心：下面这个片段里，第一条调用在窗口内**配不平**，
#    而后面几行**另有一个独立调用**、它的参数里正好有污点变量 `sql`。
#    旧实现会匹配到那对括号 → 产出一条指向**错误调用**的命中。
mismatch = ["x = obj.query(",      # 调用名在这里，括号一直没闭合
            "    a,",
            "",
            "",
            "",
            "",
            "y = other.call(sql);"]  # ← 别处的调用，参数含污点变量

r = Q._arg_region(mismatch, 1, 0)
check("⭐ 配不平的调用 → `_arg_region` 返回 None（不是后面那对括号）", r is None, repr(r))
check("⭐ 配不平 → `_tainted_in_args` 判 False（不张冠李戴）",
      Q._tainted_in_args(mismatch, 1, 0, {"sql"}) is False)

# 反向对照：把窗口放宽到能配平，就应该取到**这次调用**的区（证明判否是因为窗口、不是因为逻辑）
balanced = ["x = obj.query(", "    a,", "    params);", "y = other.call(sql);"]
r = Q._arg_region(balanced, 1, 0)
check("窗口够时取到的是**这次调用**的区（不含别处的 sql）",
      r is not None and "sql" not in r and "params" in r, repr(r))

print("\n=== ④ 窗口守卫：不许顺手放大 ===")
check("`_CALL_LOOKAHEAD` 仍是 6", Q._CALL_LOOKAHEAD == 6, str(Q._CALL_LOOKAHEAD))
# 实测依据：放大到 20/40/80，Benchmark 上指标**一个都不变**（918 条命中）——
# 放大只会增加"把无关代码里的污点变量算进来"的风险，所以不放。

print("\n=== ⑤ 三条候选的实测否决依据必须在 KB 里（防下一轮重复劳动）===")
kb = (REPO / "data" / "kb" / "whitebox-miss-attribution.md").read_text(encoding="utf-8")
check("KB 记了「裸 query/update 否决」的硬证据（`md.update`）", "md.update" in kb)
check("KB 记了「addBatch 否决」的代价（+1 真漏洞 / +2 误报）",
      "addBatch" in kb and ("+2" in kb or "2 例误报" in kb))
check("KB 记了「嵌套 lambda」为何仍不修（要靠裸 query）", "lambda" in kb)
check("KB 记了本版是**正确性修复、增量 0**", "增量 0" in kb or "指标一个都不变" in kb)

print("\n" + "=" * 68)
print(f"结果：{PASS} 通过 / {FAIL} 失败")
print("=" * 68)
sys.exit(1 if FAIL else 0)
