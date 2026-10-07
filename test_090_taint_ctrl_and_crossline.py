# -*- coding: utf-8 -*-
r"""taint 层「控制流前缀清除污点」与「跨行赋值」两处修复的守卫（v090）。

## 本测试防的是什么

v086 把**带控制流前缀的赋值**接进了污点分析（`if (values != null) param = values[0];`），
并定下一条**刻意不对称**的判据：**右值脏 → 标脏；右值安全 → 不清除**
（分支"执行与否"词法层判不出，清除 = 制造**不可恢复的漏报**）。

v090 实测发现这条判据**被绕过了**，而且是两个不同的漏洞：

### ① 控制流前缀被 `_ASSIGN` 当成左值 → 走「覆盖即净化」

`_ASSIGN` 的「带类型声明」分支字符类是 `[A-Za-z_][\w.<>\[\],\s]*?` —— **不含括号**。于是：

    if ((500 / 42) + num > 200) bar = param;     ← 条件里有括号 → `_ASSIGN` 匹配失败
                                                    → 落到 `_PREFIXED_ASSIGN`（v086 的判据）✓
    else bar = "This should never happen";       ← 没有括号 → **被 `_ASSIGN` 吞下**
                                                    → 抠出的左值是 `else bar` → 走「覆盖即净化」✗

实测（OWASP BenchmarkJava v1.2）：`BenchmarkTest00606` 因此漏报 ——
第二行把第一行刚标好的脏**清掉**，于是 `sql` 不脏、`statement.executeUpdate(sql)`
连 `@taint` 都产不出来。

### ② 跨行赋值：`bar =` 后换行，右值看不见

`_ASSIGN` 的右值要求 `.+?`（至少一个字符），所以

    bar =
        new String(Base64.decodeBase64(Base64.encodeBase64(param.getBytes())));

第一行**整行匹配失败** → 续行里的污点变量看不见 → `bar` 从未被判脏
（实测 `BenchmarkTest00604` 漏报）。

⚠️ 这与「跨行**调用**」是两件事，后者 v069 已修（`search.py:_tainted_in_args`）。
**同一个"跨行"盲区在赋值侧又犯了一次** —— 与 v072「修一处后要问：同类判据还有几处」同族。

## 修复后的实测净收益（项目自带 harness，OWASP BenchmarkJava v1.2，分母 = 标注 ∩ 检出）

| 口径 | 修复前 | 修复后 |
|---|---|---|
| sqli kind 级召回 | 30/64 = 46.9% | **37/64 = 57.8%** |
| sqli kind 级精确性 | 58.8% | **63.8%** |
| 小计（5 类） | 150/212 = 70.8% | **157/212 = 74.1%** |
| 其余四类（cmdi/crypto/hash/pathtraver） | — | **Δ=0（一文未动）** |

⚠️ **误报零新增**（sqli 文件级 25/43 不变、kind 级 21 不变）—— 新增的 7 例全是真漏洞。
按 rule_id 拆开：`java.sqli.concat@taint` 51→85、`java.path.file@taint` 27→39，**丢失 0 例**。

## 本测试的**判据**（比断言本身更重要）

| 方向 | 期望 | 理由 |
|---|---|---|
| `else bar = <脏>` | 标脏 | 不能因为"前缀"就把该传的污点丢掉 |
| `else bar = <安全>` | **不清除** | ①要修的就是这个（v086 的判据） |
| `bar =` + 续行含脏 | 标脏 | ②要修的 |
| **无前缀** `bar = <安全>` | **必须清除** | 直线代码无分支歧义，v090 **不能**破坏它 |
| **跨行** `bar =` + 续行**安全** | **必须清除** | 跨行不是"不清除"的借口 —— 否则会奖励错误实现 |

⚠️ **最后两行是回归护栏**：若实现图省事写成「安全赋值一律不清除」（或"带前缀的行整个忽略"），
前面几行**仍然全过** —— 只有它们能抓到。
⭐ v090 测量时第一版就是"整个忽略前缀行"，结果**误报与召回同时下降**；
而"只加污点"不可能让误报下降 —— **这个矛盾当场暴露了它是用一个回归换来的假收益**。
"""
from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import index as I          # noqa: E402
from app.codebase import search as Q         # noqa: E402
from app.codebase import taint as T          # noqa: E402
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


def names_at(lines: list[str], line_no: int, lang: str = "java") -> set[str]:
    """第 line_no 行处理完后的污点集合。"""
    return T.analyze(lines, lang).at(line_no)


SRC = 'String p = request.getParameter("a");'

print("=== ① 控制流前缀（`else`）不得清除已标脏的变量 ===")
# ⚠️ 这一节就是 `BenchmarkTest00606` 的形态。

r = names_at([SRC, 'bar = p;', 'else bar = "This should never happen";'], 3)
check("`else bar = \"安全值\";` → bar **仍**保持污点（v090 核心修复）",
      "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'bar = p;', 'else bar = "a" + "b";'], 3)
check("`else bar = <纯常量拼接>;` → bar **仍**保持污点", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'else bar = p;'], 2)
check("`else bar = <污点变量>;` → bar 标脏（脏方向不能丢）", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'else bar = request.getParameter("q");'], 2)
check("`else bar = <取值 API>;` → bar 标脏", "bar" in r, f"t={sorted(r)}")

# `default:` / `case` 前缀属于 **switch 分支**，是 KB 里明确的「有意不修」边界
# （需常量折叠，取并集会同时捞回真漏洞与误报，净收益近零 —— 见 KB 召回篇 §五）。
# 这里只钉住**保守方向**：不许因为看见 `default:` 就把已有的脏清掉。
r = names_at([SRC, 'bar = p;', 'default: bar = "safe_value";'], 3)
check("`default: bar = <安全值>;` → bar **不**被清除（保守方向）", "bar" in r, f"t={sorted(r)}")

print("\n=== ② 跨行赋值（`bar =` + 续行）必须接上污点 ===")

r = names_at([SRC, 'bar =', '    p;'], 3)
check("`bar =` + 续行含污点变量 → bar 标脏", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'String sql =', '    "x" + p;'], 3)
check("`String sql =` + 续行拼接 → sql 标脏", "sql" in r, f"t={sorted(r)}")

r = names_at([SRC, 'bar =', '    request.getParameter("q");'], 3)
check("`bar =` + 续行是**取值 API** → bar 标脏", "bar" in r, f"t={sorted(r)}")

# 三层续行（Base64 链的真实形态，BenchmarkTest00604）
_r604 = [
    SRC,
    'String bar = "";',
    'if (p != null) {',
    '  bar =',
    '      new String(',
    '          org.apache.commons.codec.binary.Base64.decodeBase64(',
    '              org.apache.commons.codec.binary.Base64.encodeBase64(',
    '                  p.getBytes())));',
    '}',
    'String sql = "SELECT * FROM USERS WHERE PASSWORD=\'" + bar + "\'";',
]
_t = T.analyze(_r604, "java")
check("端到端：00604 形态 → bar 在续行结束后标脏", "bar" in _t.at(9), f"t={sorted(_t.at(9))}")
check("端到端：00604 形态 → sql（第 10 行）标脏", "sql" in _t.at(10), f"t={sorted(_t.at(10))}")

# 00606 形态端到端：else 清除 bug 的直接复现
_r606 = [
    SRC,
    'String bar;',
    'int num = 196;',
    'if ((500 / 42) + num > 200) bar = p;',
    'else bar = "This should never happen";',
    'String sql = "INSERT INTO users VALUES (\'" + bar + "\')";',
]
_t = T.analyze(_r606, "java")
check("端到端：00606 形态 → bar 在第 5 行（else）之后**仍**标脏",
      "bar" in _t.at(5), f"t={sorted(_t.at(5))}")
check("端到端：00606 形态 → sql 第 6 行标脏", "sql" in _t.at(6), f"t={sorted(_t.at(6))}")

print("\n=== ③ ⭐ 回归护栏：直线代码仍须「覆盖即净化」 ===")
# ⚠️ 这两节是**最关键**的：若实现写成「安全赋值一律不清除」，
#    ①② 两节仍然全过 —— 只有这里能抓到那个错误实现。

r = names_at([SRC, 'bar = p;', 'bar = "definitely_safe";'], 3)
check("`bar = \"safe\";`（无前缀）→ bar **必须**被清除", "bar" not in r, f"t={sorted(r)}")

r = names_at([SRC, 'bar = p;', 'bar =', '    "safe_value";'], 4)
check("**跨行**赋值右值安全 → bar **必须**被清除（跨行不是免责理由）",
      "bar" not in r, f"t={sorted(r)}")

r = names_at([SRC, 'else bar = p;', 'bar = "safe";'], 3)
check("前缀标脏后接无前缀安全赋值 → **仍**清除", "bar" not in r, f"t={sorted(r)}")

print("\n=== ④ 不破坏既有能力（v069 / v071 / v072 / v086）===")

r = names_at([SRC, 'bar = p;'], 2)
check("v069 无前缀赋值传播仍工作", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'String q = "x" + p + "y";'], 2)
check("v069 拼接传播仍工作", "q" in r, f"t={sorted(r)}")

_r = T.analyze(['Runtime r = Runtime.getRuntime();', 'Process pr = r.exec(p);'], "java")
check("v071 执行器变量仍工作", "r" in _r.runners_at(2), f"runners={sorted(_r.runners_at(2))}")

_r = T.analyze([SRC, 'argList.add("echo " + p);', 'pb.command(argList);'], "java")
check("v072 容器追加仍工作", "argList" in _r.at(2), f"t={sorted(_r.at(2))}")

r = names_at([SRC, 'if (values != null) bar = p;'], 2)
check("v086 控制流前缀（含括号条件）仍工作", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'if (values != null) p2 = "safe";'], 2)
check("v086 前缀安全赋值仍**不**清除", "p" in r, f"t={sorted(r)}")

print("\n=== ⑤ 不许凭空造污点 / 不许崩 ===")

r = names_at(['String x = "const";', 'else bar = z;'], 2)
check("`else bar = <全无污点成分>;` → bar **不**标脏", "bar" not in r, f"t={sorted(r)}")

r = names_at(['String x = "const";', 'bar =', '    "only_const";'], 3)
check("跨行赋值右值全无污点成分 → bar **不**标脏", "bar" not in r, f"t={sorted(r)}")

r = names_at([SRC, 'bar ='], 2)
check("`bar =` 无续行（文件到此为止）→ 不抛异常、bar 不标脏", "bar" not in r, f"t={sorted(r)}")

r = names_at([SRC, 'bar = p;', 'else bar = p;', 'else bar = "safe";'], 4)
check("连续 else 前缀交替赋值 → 脏不被清掉", "bar" in r, f"t={sorted(r)}")

print("\n=== ⑥ 端到端（检索层）：形态真的产出 `@taint` 命中 ===")
# 纯 taint 层断言不足以证明"规则真的会报" —— 这里走真实 入库→索引→检索。

_JAVA_606 = "\n".join([
    "class ElseCleared606 {",
    "  void go(javax.servlet.http.HttpServletRequest request) throws Exception {",
    '    String param = request.getParameter("x");',
    "    String bar;",
    "    int num = 196;",
    "    if ((500 / 42) + num > 200) bar = param;",
    '    else bar = "This should never happen";',
    '    String sql = "INSERT INTO users VALUES (\'" + bar + "\')";',
    "    java.sql.Statement statement =",
    "        org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();",
    "    int count = statement.executeUpdate(sql);",
    "  }",
    "}",
]) + "\n"

_JAVA_604 = "\n".join([
    "class CrosslineAssign604 {",
    "  void go(javax.servlet.http.HttpServletRequest request) throws Exception {",
    '    String param = request.getParameter("x");',
    '    String bar = "";',
    "    if (param != null) {",
    "      bar =",
    "          new String(",
    "              org.apache.commons.codec.binary.Base64.decodeBase64(",
    "                  org.apache.commons.codec.binary.Base64.encodeBase64(",
    "                      param.getBytes())));",
    "    }",
    '    String sql = "SELECT * FROM USERS WHERE PASSWORD=\'" + bar + "\'";',
    "    java.sql.Statement statement =",
    "        org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();",
    "    java.sql.ResultSet rs = statement.executeQuery(sql);",
    "  }",
    "}",
]) + "\n"

# 负例：bar 全程安全 → 不许产出 sqli 命中（防"给所有变量都标脏"式实现）
_JAVA_SAFE = "\n".join([
    "class SafeConstant {",
    "  void go(javax.servlet.http.HttpServletRequest request) throws Exception {",
    '    String bar = "safe_value";',
    '    String sql = "SELECT * FROM USERS WHERE PASSWORD=\'" + bar + "\'";',
    "    java.sql.Statement statement =",
    "        org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();",
    "    int count = statement.executeUpdate(sql);",
    "  }",
    "}",
]) + "\n"

idx_inside = None
with temp_codebase(files={
    "ElseCleared606.java": _JAVA_606,
    "CrosslineAssign604.java": _JAVA_604,
    "SafeConstant.java": _JAVA_SAFE,
}) as cb:
    I.build(cb)
    idx_inside = I.INDEX_DIR / f"{cb}.json"
    check("索引文件在 `with` 内已落盘（下面才能验证它被清掉）", idx_inside.exists(),
          str(idx_inside))
    hits = Q.search_sinks(cb, limit=500)

    def _sqli_taint(stem: str):
        return [h for h in hits
                if pathlib.Path(h.file).stem == stem and "taint" in h.extractor]

    h606 = _sqli_taint("ElseCleared606")
    check("00606 形态（else 清除 bug）→ 产出 `@taint` 命中", bool(h606),
          str([(h.rule_id, h.extractor) for h in hits][:6]))
    if h606:
        check("00606 命中的 rule_id 带 `@taint`",
              all(h.rule_id.endswith("@taint") for h in h606),
              str([h.rule_id for h in h606]))

    h604 = _sqli_taint("CrosslineAssign604")
    check("00604 形态（跨行赋值）→ 产出 `@taint` 命中", bool(h604),
          str([(h.rule_id, h.extractor) for h in hits][:6]))

    hsafe = _sqli_taint("SafeConstant")
    check("负例：bar 全程安全 → **不**产出 sqli 命中（防凭空标脏）", not hsafe,
          str([(h.rule_id, h.extractor) for h in hsafe]))

# ---- ⑥b：索引文件必须被清理（v090 修的同族漏点，防复发）----
check("`with` 退出后索引文件已被清理（v090 测试kit 修复）",
      idx_inside is not None and not idx_inside.exists(), str(idx_inside))

print("\n" + "=" * 68)
print(f"结果：{PASS} 通过 / {FAIL} 失败")
print("=" * 68)
sys.exit(1 if FAIL else 0)
