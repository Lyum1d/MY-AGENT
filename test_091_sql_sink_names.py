# -*- coding: utf-8 -*-
r"""java sqli 规则「sink 调用名覆盖」守卫（v091）。

## 本测试防的是什么

`java.sqli.concat` 的跨行通道（`call_pattern`）原来只认 JDBC/JPA 的
`executeQuery` / `executeUpdate` / `execute` / `prepareStatement` / `prepareCall` /
`nativeSQL` / `createQuery` / `createNativeQuery`。

实测（OWASP BenchmarkJava v1.2，2026-10-07）：sqli 的 **34 例漏报里 21 例（62%）**
走 **Spring `JdbcTemplate`** 家族 —— 那些调用名**一个都不在白名单里**：

    JDBCtemplate.queryForObject(sql, Long.class);   // BenchmarkTest00025
    JDBCtemplate.batchUpdate(sql);                  // BenchmarkTest00194
    JDBCtemplate.query(sql, rowMapper);             // BenchmarkTest00431

⚠️ 这不是「多行调用」问题（调用侧 v069 已修），是**sink 调用名没覆盖**。

## 本测试的判据（比断言本身更重要）

| 方向 | 期望 | 理由 |
|---|---|---|
| 新调用名 + **污点**变量 → 出 `@taint` 命中 | 必须命中 | 这就是要修的漏报 |
| 新调用名 + **干净**变量 → **不**命中 | 必须不命中 | 通道仍须"括号里有污点"这一条，**不是**见到名字就报 |
| 裸 `query` / `update` → **不**命中 | 必须不命中 | **有意不收**：v091 实测收进来召回与误报**一个都没变** |
| 行级 `pattern` 里**不得**出现新名字 | 必须不出现 | 两个通道证据强度不同，混在一起就分不清（见下） |

⚠️ **最后两行是回归护栏**：
- 若实现图省事把新名字也塞进行级 `pattern`，前两行**仍然全过** —— 只有第 4 行能抓到；
- 若有人"顺手放宽"成裸 `query|update`，只有第 3 行能抓到。

## 实测净收益（项目自带 harness，分母 = 标注 ∩ 检出，kind 级）

| 口径 | v090 | v091 |
|---|---|---|
| sqli 召回 | 37/64 = 57.8% | **54/64 = 84.4%** |
| 小计（5 类） | 157/212 = 74.1% | **174/212 = 82.1%** |
| 精确性（kind） | sqli 63.8% / 小计 67.1% | sqli **66.7%** / 小计 **67.7%** |
| sqli 误报 | 25/43 | 30/43（**+5**，新增 24 例命中里 6 例是 Benchmark 安全用例） |

按 rule_id 拆开：`java.sqli.concat@taint` 85 → **119**；新增命中的用例里
`BenchmarkTest00104/00200/00336/00338/00432/00511` 六个是**标注为安全**的
（它们的 SQL 同样是 `+ bar +` 拼接，只是 `bar` 走了 `else`/集合取值分支）——
**这是本版明确接受的代价**，不是意外（v090 已先把 `else` 清除污点那条 bug 修掉，
所以这 6 例是"污点判断正确、分支语义判不出"导致的，属 KB §五 的"有意不修"边界）。

剩余 10 例漏报 = **9 例 `switch` 分支**（KB §五，需常量折叠）+ **1 例 helper 间接取值**
（`scr.getTheParameter(...)`，属于"收宽必误报"的 source 边界）。
即 **84.4% 是不做常量折叠时的实际上限**。
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import index as I          # noqa: E402
from app.codebase import search as Q         # noqa: E402
from app.codebase import sink_rules as S     # noqa: E402
from codebase_testkit import temp_codebase   # noqa: E402

PASS = FAIL = 0


def check(desc: str, ok: bool, extra: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {desc}" + (f" → {extra}" if extra else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {desc}" + (f" → {extra}" if extra else ""))


#: v091 新增的调用名（Spring JdbcTemplate 家族 + JDBC 批处理）
NEW_NAMES = ["queryForObject", "queryForList", "queryForMap", "queryForRowSet",
             "queryForLong", "queryForInt", "batchUpdate", "executeBatch"]

#: 旧有的调用名（回归护栏：不能因为本次改动而丢）
OLD_NAMES = ["executeQuery", "executeUpdate", "execute", "prepareStatement",
             "prepareCall", "nativeSQL", "createQuery", "createNativeQuery"]


def _java(pairs: list[tuple[str, str]], class_name: str) -> str:
    """造一个 Java 夹具：`pairs` 是 (调用表达式, sql 变量右值) 列表。"""
    lines = [f"class {class_name} {{",
             "  void go(javax.servlet.http.HttpServletRequest request) throws Exception {",
             '    String param = request.getParameter("x");']
    for i, (call_expr, rhs) in enumerate(pairs):
        lines.append(f"    String sql{i} = {rhs};")
        lines.append(f"    {call_expr};")
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


TAINTED_RHS = '"SELECT * FROM USERS WHERE PASSWORD=\'" + param + "\'"'
CLEAN_RHS = '"SELECT * FROM USERS WHERE PASSWORD=\'x\'"'

files = {
    # ① 新名字 + 污点变量 → 应命中
    "SpringNamesTainted.java": _java(
        [(f"org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.{n}(sql{i})", TAINTED_RHS)
         for i, n in enumerate(NEW_NAMES)], "SpringNamesTainted"),
    # ② 旧名字 + 污点变量 → 照旧命中（回归）
    "JdbcNamesTainted.java": _java(
        [(f"stmt.{n}(sql{i})", TAINTED_RHS) for i, n in enumerate(OLD_NAMES)],
        "JdbcNamesTainted"),
    # ③ 新名字 + **干净**变量 → 不得命中
    "SpringNamesClean.java": _java(
        [(f"org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.{n}(sql{i})", CLEAN_RHS)
         for i, n in enumerate(NEW_NAMES)], "SpringNamesClean"),
    # ④ 裸 query / update + 污点变量 → **有意不收**，不得命中
    "BareQueryUpdate.java": _java(
        [("org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.query(sql0)", TAINTED_RHS),
         ("org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.update(sql1)", TAINTED_RHS)],
        "BareQueryUpdate"),
}

print("=== ① 规则文本事实（守卫：两个通道必须分开）===")

_r = S.by_id("java.sqli.concat")
check("规则存在", _r is not None)
if _r is not None:
    for n in NEW_NAMES:
        check(f"`{n}` 在跨行 `call_pattern` 里", n in _r.call_pattern)
    _leaked = [n for n in NEW_NAMES if n in _r.pattern]
    check("⭐ 新名字**没有**混进行级 `pattern`（两个通道证据强度不同，必须分得开）",
          not _leaked, f"泄漏={_leaked}")
    for n in OLD_NAMES:
        check(f"旧名 `{n}` 仍在跨行通道里（回归）", n in _r.call_pattern)
    for n in ("query", "update"):
        # 裸 query/update 刻意不收：实测收进来召回与误报一个都没变
        check(f"裸 `.{n}(` 仍**不**在跨行通道里（有意不收，实测无收益）",
              re.search(r"\|" + n + r"\|", _r.call_pattern) is None
              and not _r.call_pattern.startswith("\\." + n),
              _r.call_pattern[:70])

print("\n=== ② 端到端（检索层）：新名字 + 污点 → `@taint` 命中 ===")

with temp_codebase(files=files) as cb:
    I.build(cb)
    hits = Q.search_sinks(cb, limit=500)

    def _sqli(stem: str):
        return [h for h in hits
                if pathlib.Path(h.file).stem == stem and h.kind == "sqli"]

    tainted = _sqli("SpringNamesTainted")
    texts = "\n".join(h.text for h in tainted)
    missing = [n for n in NEW_NAMES if n not in texts]
    check("8 个新调用名**逐名**都产出了 sqli 命中", not missing, f"未命中={missing}")
    check("新名字的命中都是 `@taint` 通道（不是行级 `lexical`）",
          bool(tainted) and all("taint" in h.extractor for h in tainted),
          str(sorted({(h.rule_id, h.extractor) for h in tainted})[:3]))

    old = _sqli("JdbcNamesTainted")
    check("8 个旧调用名照旧命中（回归护栏）", len(old) >= len(OLD_NAMES),
          f"命中 {len(old)} 条")

    clean = _sqli("SpringNamesClean")
    check("⭐ 新名字 + **干净**变量 → **不**命中（仍须「括号里有污点」）",
          not clean, str([(h.rule_id, h.text.strip()[:40]) for h in clean]))

    bare = _sqli("BareQueryUpdate")
    check("⭐ 裸 `query`/`update` + 污点 → **不**命中（有意不收）", not bare,
          str([(h.rule_id, h.text.strip()[:40]) for h in bare]))

print("\n=== ③ 逐字回归钉：行级模式与规则条数不得漂移 ===")
# 本版**只**该动跨行通道。行级 `pattern` 必须与 v090 逐字相同 ——
# 否则「同行拼接」与「变量来自别处」两种证据就被混在了一起（见模块 docstring 判据表）。
_V090_PATTERN = (r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|prepareCall"
                 r"|nativeSQL|createQuery|createNativeQuery)\s*\([^;]{0,120}?\+")
check("`java.sqli.concat` 的行级 pattern 与 v090 **逐字一致**",
      _r is not None and _r.pattern == _V090_PATTERN,
      repr(_r.pattern) if _r else "规则缺失")
_java_rules = S.rules_for("java")
# ⚠️ `rules_for(lang)` 会**连通用规则（`*`）一起返回** —— 实测 13 条 java 自有 + 3 条通用 = 16。
# （本测试第一版按"13 条"断言，是这个口径没查清，不是代码错。）
_own = [r for r in _java_rules if r.id.startswith("java.")]
check("java **自有**规则条数未变（13 条；另有 3 条 `*` 通用规则，合计 16）",
      len(_own) == 13 and len(_java_rules) == 16,
      f"自有 {len(_own)} / 合计 {len(_java_rules)}")
check("java 规则全部可编译（新旧 pattern 都没写坏正则）",
      all(r.regex() and (r.call_regex() is not None or not r.call_pattern)
          for r in _java_rules))

print("\n" + "=" * 68)
print(f"结果：{PASS} 通过 / {FAIL} 失败")
print("=" * 68)
sys.exit(1 if FAIL else 0)
