# -*- coding: utf-8 -*-
r"""taint 层「带控制流前缀的赋值」守卫（v086）。

## 本测试防的是什么

`_ASSIGN` 锚在 `^\s*` 上，于是**任何带控制流前缀的赋值整行匹配失败**：

    if (values != null) param = values[0];     // ← 整行看不见
    if (param == null) param = "";             // ← 同样看不见
    } else { bar = param;                      // ← 同样看不见

后果是变量**永远不进污点集**，下游 sink 判「不脏」→ **不可恢复的漏报**。

实测（OWASP BenchmarkJava v1.2，官方 expectedresults-1.2.csv，本机有源码的 107 个 sqli 用例）：
**43 个漏报真漏洞里 24 个（56%）** 是这个形态 —— 当时**最大的单一漏报根因**。

## 本测试的**判据**（比断言本身更重要）

⚠️ v086 的修法是**不对称**的，所以测试也必须**分别**把两个方向钉住：

| 方向 | 期望 | 理由 |
|---|---|---|
| 分支里右值**脏** → 标脏 | 必须传播 | 这就是要修的漏报 |
| 分支里右值**安全** → **不清除** | 必须**保持**污点 | 条件「执行与否」词法层判不出，清除=制造漏报 |
| **无前缀**赋值右值安全 → 清除 | 必须**仍然**清除 | 直线代码无分支歧义，v086 **不能**破坏它 |

⚠️ **第三行是回归护栏**：如果实现时图省事写成「所有安全赋值都不清除」，
第 1、2 行仍然会过 —— 只有第 3 行能抓到。**缺了它，这个测试会奖励错误的实现。**
"""
from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import taint as T  # noqa: E402

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

print("=== ① 正向：带控制流前缀的赋值**必须**传播污点 ===")

# 1) if 前缀 + 右值含污点变量（BenchmarkTest00032 的核心形态）
r = names_at([SRC, 'if (values != null) bar = p;'], 2)
check("`if (..) bar = <污点变量>;` → bar 标脏", "bar" in r, f"t={sorted(r)}")

# 2) if 前缀 + 右值含外部输入起点（直接取值）
r = names_at(['if (x != null) bar = request.getParameter("q");'], 1)
check("`if (..) bar = <取值 API>;` → bar 标脏", "bar" in r, f"t={sorted(r)}")

# 3) if 前缀 + 数组下标取值（原以为是「数组传播」缺口，实际是这一条）
r = names_at([SRC, 'String[] values = request.getParameterValues("q");',
              'if (values != null) param = values[0];'], 3)
check("`if (..) param = values[0];`（下标）→ param 标脏", "param" in r, f"t={sorted(r)}")

# 4) else 分支前缀
r = names_at([SRC, '} else { bar = p;'], 2)
check("`} else { bar = <污点变量>;` → bar 标脏", "bar" in r, f"t={sorted(r)}")

# 5) while 前缀
r = names_at([SRC, 'while (it.hasNext()) bar = p;'], 2)
check("`while (..) bar = <污点变量>;` → bar 标脏", "bar" in r, f"t={sorted(r)}")

# 5b) ⚠️ **条件里带嵌套括号** —— `test_086` 第一版就是被这条抓到的：
#     原正则条件部分写 `\([^)]*\)`，只吃到第一个 `)`，于是
#     `while (it.hasNext())` 整行匹配失败。**与本版要修的 `_ASSIGN` 锚点问题是同一类错误，
#     只是发生在我新写的正则里** —— 留这条防复发。
r = names_at([SRC, 'while (it.hasNext()) bar = p;'], 2)
check("`while (it.hasNext())`（嵌套括号）→ bar 标脏", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'if (map.isEmpty() == false) bar = p;'], 2)
check("`if (map.isEmpty() == false)`（嵌套括号）→ bar 标脏", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'if ((500 / 42) + num > 200) bar = p;'], 2)
check("`if ((500 / 42) + num > 200)`（嵌套括号）→ bar 标脏", "bar" in r, f"t={sorted(r)}")

# 6) 端到端：BenchmarkTest00032 形态一路传到 sql
_r32 = [
    'java.util.Map<String, String[]> map = request.getParameterMap();',
    'String param = "";',
    'if (!map.isEmpty()) {',
    '  String[] values = map.get("x");',
    '  if (values != null) param = values[0];',
    '}',
    'String sql = "SELECT * FROM USERS WHERE PASSWORD=\'" + param + "\'";',
    'stmt.execute(sql);',
]
_t = T.analyze(_r32, "java")
check("端到端：00032 形态 → param 第 5 行后标脏", "param" in _t.at(5))
check("端到端：00032 形态 → sql 第 7 行后标脏", "sql" in _t.at(7))

print("\n=== ② 反向：分支里右值**安全**时**不得**清除（不对称判据）===")

r = names_at([SRC, 'if (x != null) p = "safe_value";'], 2)
check("`if (..) p = \"safe\";` → p **仍**保持污点（刻意保守）",
      "p" in r, f"t={sorted(r)}")

r = names_at([SRC, '} else { p = "safe_value";'], 2)
check("`} else { p = \"safe\";` → p **仍**保持污点", "p" in r, f"t={sorted(r)}")

r = names_at([SRC, 'if (x != null) p = "a" + "b";'], 2)
check("`if (..) p = <纯常量拼接>;` → p **仍**保持污点", "p" in r, f"t={sorted(r)}")

print("\n=== ③ ⭐ 回归护栏：**无前缀**赋值仍须「覆盖即净化」 ===")
# ⚠️ 这一节是**最关键**的：若实现图省事写成「安全赋值一律不清除」，
#    ①② 两节仍然全过 —— 只有这里能抓到那个错误实现。

r = names_at([SRC, 'p = "definitely_safe";'], 2)
check("`p = \"safe\";`（无前缀，直线代码）→ p **必须**被清除",
      "p" not in r, f"t={sorted(r)}")

r = names_at([SRC, 'p = "a" + "b";'], 2)
check("`p = <纯常量拼接>;`（无前缀）→ p **必须**被清除",
      "p" not in r, f"t={sorted(r)}")

# 分支播脏之后再走一条直线安全赋值 → 仍应清除
r = names_at([SRC, 'if (values != null) p = values[0];', 'p = "safe";'], 3)
check("分支标脏 → 后续**无前缀**安全赋值仍清除",
      "p" not in r, f"t={sorted(r)}")

print("\n=== ④ 不破坏既有能力（v069 / v071 / v072 通道）===")

r = names_at([SRC, 'bar = p;'], 2)
check("v069 无前缀赋值传播仍工作", "bar" in r, f"t={sorted(r)}")

r = names_at([SRC, 'String q = "x" + p + "y";'], 2)
check("v069 拼接传播仍工作", "q" in r, f"t={sorted(r)}")

_r = T.analyze(['Runtime r = Runtime.getRuntime();', 'Process pr = r.exec(p);'], "java")
check("v071 执行器变量仍工作", "r" in _r.runners_at(2), f"runners={sorted(_r.runners_at(2))}")

_r = T.analyze([SRC, 'argList.add("echo " + p);', 'pb.command(argList);'], "java")
check("v072 容器追加仍工作", "argList" in _r.at(2), f"t={sorted(_r.at(2))}")

print("\n=== ⑤ 前缀赋值不含污点时不得凭空造污点 ===")

r = names_at(['String x = "const";', 'if (cond) y = z;'], 2)
check("`if (..) y = <全无污点成分>;` → y **不**标脏", "y" not in r, f"t={sorted(r)}")

r = names_at(['if (cond) i = 0;'], 1)
check("`if (..) i = 0;` → i 不标脏", "i" not in r, f"t={sorted(r)}")

print("\n" + "=" * 68)
print(f"结果：{PASS} 通过 / {FAIL} 失败")
print("=" * 68)
sys.exit(1 if FAIL else 0)
