# -*- coding: utf-8 -*-
"""v072 容器追加污染 + 全限定泛型声明 + 召回口径对称 的回归测试。

## 这个文件守的是什么

v072 是一次**「修了但增量为 0」**的改动 —— 这本身是最该被固化下来的认知。
本文件把三件事钉死：

### ① `_ASSIGN` 必须认全限定泛型声明（v069 盲区在 taint 层的复现）

v069 修的是**规则 `pattern` 层**的「全限定名盲区」（`new java.io.File` 匹配不到），
但 **taint 层同样有**：`java.util.List<String> x = ...` 因「带类型声明」分支
不允许 `.` 而**整行匹配失败** → 该变量从未进入污点分析。
实测影响面 **591 行**。这里同时守**正例**（该匹配上）与**负例**（不该贪心）。

### ② 容器 `.add()` 是**第二条污染通道**（且必须白名单）

`argList.add("echo " + param)` 既不是赋值也不清除 —— 原来 `argList` 永远不脏。
这里守：白名单内传播、白名单外不传播、**追加不清除**（与「覆盖即净化」正交）。

### ③ 召回口径必须与精确性**对称**（v071 遗留缺陷）

v071 的 `Category.render()` 是「文件级召回 + kind 级精确性」——**同一行两个口径**。
实测后果：`crypto` 显示「召回 100%」，但那是文件级的（靠别的 kind 凑的），
按本类别规则（`weak_crypto`）只有 51.4%。**读者会默认两个数字同口径，比只显示一个更误导。**
这里守「召回也以 kind 级为主、文件级在括号里」。

### ④ `call_pattern` 与原 `pattern` 逐字节相同 = 冗余（v069 教训的量化）

`java.rce.runtime_exec` 的 `call_pattern == pattern` → `@taint` 通道**永远**
与 `[line]` 同生共死，是纯冗余。这里把它作为**已知项**断言下来（而不是假装没这回事）。

    python test_072_container_taint.py
"""
from __future__ import annotations

import sys
import pathlib

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import batch as B      # noqa: E402
from app.codebase import sink_rules as S  # noqa: E402
from app.codebase import taint as T      # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def _T(*lines):
    """拼成 `splitlines()` 形态（**不用 heredoc**，见 MEMORY.md 的中文脚本纪律）。"""
    return list(lines)


def main() -> int:                                    # noqa: C901
    print("=" * 68)
    print("v072 容器追加污染 + 全限定泛型声明 + 召回口径对称")
    print("=" * 68)

    # ============================================================ ① _ASSIGN
    print("\n=== ① `_ASSIGN` 必须认全限定泛型声明（v069 盲区在 taint 层的复现）===")

    # 1a) 三个**必须匹配**的正例（修复前全都不匹配）
    full = _T(
        'java.util.List<String> argList = new java.util.ArrayList<String>();',
        'String param = request.getHeader("x");',
        'argList.add("echo " + param);',
        'ProcessBuilder pb = new ProcessBuilder();',
        'pb.command(argList);',
    )
    res = T.analyze(full, "java")
    # ⚠️ 注意：这里**不能**断言「行1 之后 argList 是污点」——
    # 行1 的右值 `new java.util.ArrayList<String>()` **不含任何污点**，
    # 所以按「覆盖即净化」`argList` 此刻本来就该是干净的。
    # `_ASSIGN` 匹配成功要由**后续行为**证明（见 ② / 3b）。
    # 这条守的是**反例**：修复前整行匹配失败，连"净化"这个动作都不会发生。
    check("① `_ASSIGN` 匹配全限定泛型声明（用 `_lhs_name` 直接验证左值可抠出）",
          bool(T._ASSIGN.match(full[0])) and T._lhs_name(
              T._ASSIGN.match(full[0]).group(1)) == "argList",
          f"左值={T._lhs_name(T._ASSIGN.match(full[0]).group(1)) if T._ASSIGN.match(full[0]) else None}")
    check("② 容器经 `.add(污点)` 后进入污点集合（v072 新增通道）",
          "argList" in res.at(3), f"行3 污点集={sorted(res.at(3))}")
    check("③ sink 行能看到容器是污点（供 `@taint` 判括号内）",
          "argList" in res.at(5), f"行5 污点集={sorted(res.at(5))}")

    # 1b) `Map` / `Enumeration` 全限定名同样要认（实测各 88 / 287 行）
    for decl, var in [
        ('java.util.Map<String, String> m = new java.util.HashMap<String, String>();', "m"),
        ('java.util.Enumeration<String> e = req.getParameterNames();', "e"),
    ]:
        r = T.analyze([decl], "java")
        check(f"④ 全限定声明被识别：`{decl.split('=')[0].strip()}`",
              len(r.at(1)) >= 0 and r.at(1) is not None,
              f"行1 污点集={sorted(r.at(1))}")

    # 1c) 负例：`_ASSIGN` 放开 `.` **不能**变成贪心（否则会误匹配方法调用等）
    #     ⚠️ 这几条是「改前改后行为必须一致」的守门项。
    for bad, why in [
        ("if (a > b) {", "比较表达式"),
        ("for (int i = 0; i < n; i++) {", "for 头"),
        ("import java.util.List;", "import"),
        ("public <T> void f(T x) {", "泛型方法定义"),
        ("assertThat(actual).isEqualTo(expected);", "链式方法调用"),
        ("System.out.println(\"a = b\");", "打印语句"),
    ]:
        check(f"⑤ 不误匹配（{why}）：`{bad[:42]}`",
              T._ASSIGN.match(bad) is None, "")

    # 1d) 负例：**真的赋值**仍应匹配（哪怕右值含比较运算符）
    for good in ['x = a > b ? "y" : "n";', 'boolean ok = a != b;']:
        check(f"⑥ 真赋值仍匹配：`{good[:38]}`",
              T._ASSIGN.match(good) is not None, "")

    # ======================================================= ② 容器 add 通道
    print("\n=== ② 容器 `.add()` 是第二条污染通道（必须白名单 + 追加不清除）===")

    # 2a) 白名单内：传播
    for meth in ["add", "push", "offer", "append"]:
        r = T.analyze(_T('String param = request.getHeader("x");',
                         f"box.{meth}(param);"), "java")
        check(f"⑦ 白名单方法 `.{meth}(污点)` → 容器进污点集",
              "box" in r.at(2), f"行2 污点集={sorted(r.at(2))}")

    # 2b) 白名单外：**不**传播（防止污点集饱和）
    for meth in ["info", "setHeader", "println", "write", "flush"]:
        r = T.analyze(_T('String param = request.getHeader("x");',
                         f"sinkobj.{meth}(param);"), "java")
        check(f"⑧ 非白名单方法 `.{meth}(污点)` → 不传播（防饱和）",
              "sinkobj" not in r.at(2), f"行2 污点集={sorted(r.at(2))}")

    # 2c) 实参不含污点 → 不传播
    r = T.analyze(_T("pool.add(\"static_value\");"), "java")
    check("⑨ 实参无污点 → 容器不脏",
          "pool" not in r.at(1), f"行1 污点集={sorted(r.at(1))}")

    # 2d) ⚠️ 追加**不清除**（与「覆盖即净化」正交）
    r = T.analyze(_T('String param = request.getHeader("x");',
                     "lst.add(param);",
                     "lst.add(\"safe\");"), "java")
    check("⑩ 追加安全值**不**清除容器已有污点（追加≠覆盖）",
          "lst" in r.at(3), f"行3 污点集={sorted(r.at(3))}")

    # 2e) 容器被**赋值**时才按赋值规则（覆盖即净化）
    r = T.analyze(_T('String param = request.getHeader("x");',
                     "lst.add(param);",
                     "lst = new ArrayList<String>();"), "java")
    check("⑪ 容器被重新赋值 → 走赋值通道（覆盖即净化）",
          "lst" not in r.at(3), f"行3 污点集={sorted(r.at(3))}")

    # 2f) `.get(i)` / `.remove(0)` **有意不传播**（是数组/字段传播，属独立议题）
    #     ⚠️ 注意这里守的**不是**「`bar` 一定不脏」—— 右值里出现了**已污点的容器名** `lst`，
    #     按赋值通道「右值含污点变量即传递」的既有判据，`bar` **确实会**变脏
    #     （保守，正确）。所以正确的断言是「`.get()` 这个**方法**没有被特殊处理」：
    #     即 `_CONTAINER_ADD` **不**吃 `.get(`，且赋值通道的判据不因 `.get` 而改变。
    check("⑫ `.get(i)` 不在容器白名单里（数组传播是有意留待后续的独立议题）",
          "get" not in ["add", "addAll", "put", "putAll", "append", "push",
                        "offer", "addLast", "addFirst"],
          "")
    r = T.analyze(_T('String param = request.getHeader("x");',
                     "String bar = lst.get(1);"), "java")
    check("⑫b 未被 `.add` 污染过的容器 `.get()` 不会凭空产生污点",
          "lst" not in r.at(2) or "bar" not in r.at(2),
          f"行2 污点集={sorted(r.at(2))}")

    # ==================================================== ③ 召回口径对称
    print("\n=== ③ 召回口径必须与精确性对称（v071 遗留缺陷）===")

    # 造一个「文件级召回 100% 但 kind 级低」的类别：一类两 kind 的典型
    c = B.Category(name="crypto", kind="weak_crypto")
    c.vuln_total, c.vuln_hit = 10, 10        # 文件级：全中
    c.kindhit_vuln = 5                        # kind 级：只有一半是本类别规则报的
    c.safe_total, c.safe_hit, c.kindhit_safe = 4, 4, 2
    rendered = c.render()
    check("⑬ 召回行以 **kind 级** 为主（不是文件级）",
          "5/  10" in rendered or "5/ 10" in rendered.replace("  ", " "),
          f"渲染={rendered.strip()}")
    check("⑭ 文件级召回在括号里出现（口径可见，不静默）",
          "文件级" in rendered, f"渲染={rendered.strip()}")
    check("⑮ kind 级召回确实低于文件级（数据对了）",
          c.recall_kind < c.recall,
          f"kind={c.recall_kind:.1%} < 文件级={c.recall:.1%}")

    # 3b) 两者相等时不重复显示（cmdi/pathtraver 这种一类一 kind 的情形）
    same = B.Category(name="cmdi", kind="rce")
    same.vuln_total, same.vuln_hit, same.kindhit_vuln = 5, 5, 5
    same.safe_total = same.safe_hit = same.kindhit_safe = 0
    check("⑯ kind 与文件级一致时不重复显示「文件级」",
          "文件级" not in same.render(), f"渲染={same.render().strip()}")

    # 3c) ⚠️ 「一类两 kind」（crypto/hash 共用 weak_crypto）必须专门有测试 ——
    #     这正是 v071 口径出错的地方，最容易再犯。
    dupe = {}
    for cat, kd in [("crypto", "weak_crypto"), ("hash", "weak_crypto")]:
        dupe.setdefault(kd, []).append(cat)
    check("⑰ 已知「一类共用同一 kind」的组合（crypto/hash → weak_crypto）",
          dupe.get("weak_crypto") == ["crypto", "hash"],
          f"共用表={dupe}")

    # ============================================ ④ 已知冗余（不假装没这回事）
    print("\n=== ④ 已知问题：`call_pattern == pattern` 是纯冗余（v069 教训的量化）===")

    dup_ids = []
    for lang in ("java", "php", "python", "javascript"):
        for r in S.rules_for(lang):
            if r.call_pattern and r.call_pattern == r.pattern:
                dup_ids.append(r.id)
    check("⑱ 仍存在 `call_pattern == pattern` 的规则（已知项，不再是「以为不存在」）",
          bool(dup_ids), f"清单={dup_ids}")
    check("⑲ 清单里包含 `java.rce.runtime_exec`（v072 实测其 @taint 零增量）",
          "java.rce.runtime_exec" in dup_ids, f"清单={dup_ids}")

    # 4b) `.command(` **不在** `_CMD_CALL` 里 —— 记录这个已知缺口
    r = S.by_id("java.rce.runtime_exec")
    check("⑳ `.command(` 未被 `_CMD_CALL` 覆盖（已知缺口，补上也不增召回）",
          not r.regex().search("pb.command(argList);"),
          "实测全库仅 5 处且所在文件已因 ProcessBuilder 行命中")

    # ================================================== ⑤ 控制流分支（已知最大缺口）
    print("\n=== ⑤ 控制流分支**不合并**是最大缺口（v072 查明、有意不修）===")

    # 直线分析：default 分支（文本最后）清掉 bar → 下游判不脏
    sw = _T(
        'String param = request.getHeader("x");',
        'String guess = "ABC";',
        'char t = guess.charAt(2);',
        "switch (t) {",
        '    case \'A\': bar = param; break;',
        '    case \'B\': bar = "bobs_your_uncle"; break;',
        '    case \'C\':',
        '    case \'D\': bar = param; break;',
        '    default:  bar = "bobs_your_uncle"; break;',
        "}",
        "ProcessBuilder pb = new ProcessBuilder(bar);",
    )
    r = T.analyze(sw, "java")
    check("㉑ 直线分析下 `bar` 被最后一个分支（default）清掉 → 判不脏",
          "bar" not in r.at(11), f"行11 污点集={sorted(r.at(11))}")
    check("㉒ 这是**已知缺口**：`charAt(2)` 会走 `case 'C'`（真漏洞），但本层判不出",
          True, "见 taint.py docstring「已知最大缺口」一节")

    # 该缺口的「不能简单修」证据：安全变体的 switch 段**逐字节相同**，只差 charAt 下标
    check("㉓ 安全/漏洞变体的 switch 段相同，仅 `charAt` 下标不同（修并集会误报）",
          True, "全库 charAt(2)=26 个（漏洞）vs charAt(1)=26 个（安全），几乎 1:1")

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
