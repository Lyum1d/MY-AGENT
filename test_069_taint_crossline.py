# -*- coding: utf-8 -*-
"""v069 跨行污染（taint 两层匹配）的回归测试。

## 这个文件守的是什么

v069 是一次**被实测驱动的改动**，而且中途踩了两个结构性错误。
本文件把「踩坑的判断」固化成断言 —— **同类错误不能再悄悄回来**。

### 守的四件事

1. **`taint.py` 的传播语义**：含污点变量即传递（不论有无 `+`）、覆盖即净化。
   这两条都是实测踩出来的（`URLDecoder.decode(param, ...)` 被误判成净化 →
   下游全断，Benchmark 上一个都命中不了）。
2. **`search.py` 两层匹配必须都产出**：v069 第一版写成
   `if 行级命中: return / elif taint命中: return`，**整层成了死代码**
   （两条平行规则的 pattern 相同 → 永远走不到 taint 分支）。
   这里直接断言「同一行可以同时产出 `lexical` 与 `taint(lexical)` 两条命中」。
3. **禁止「同 pattern 的平行规则」**：那是 v069 第一版的做法，
   会让「故意写宽的 pattern」变成裸奔的宽口径规则
   （实测 `java.sqli.tainted_var` 产出 112 处伪 taint 命中，extractor 全是 `lexical`）。
   断言：**不存在两条 pattern 完全相同、且一条带 call_pattern、一条不带**的规则。
4. **跨行参数区判得了**：Benchmark 大量写
   `connection.prepareStatement(\n    sql, ...);` —— 调用名与参数不同行。
   只在单行里找括号会直接判否（实测 20 个 sqli 用例因此漏报）。

    python test_069_taint_crossline.py
"""
from __future__ import annotations

import re
import sys
import pathlib

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import sink_rules as S      # noqa: E402
from app.codebase import search as Q          # noqa: E402
from app.codebase import taint as T           # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def _T(*lines):
    """把行列表拼成 `splitlines()` 的形态（**不用 heredoc**，见 MEMORY.md 的中文脚本纪律）。"""
    return list(lines)


def main() -> int:                                   # noqa: C901（分支多但都是直线检查）
    print("=" * 68)
    print("v069 跨行污染（taint 两层匹配）")
    print("=" * 68)

    # ============================================ ① taint 模块的传播语义
    print("\n=== ① taint.py 的传播语义（两条都是实测踩出来的）===")

    # 1a) 「含污点变量即传递，不论有无 +」—— 这一条错过的代价是下游全断
    src = _T(
        'String param = request.getParameter("x");',
        'param = URLDecoder.decode(param, "UTF-8");',
        'String sql = "{call " + param + "}";',
        'connection.prepareCall(sql);',
    )
    res = T.analyze(src, "java")
    check("① 经过函数处理仍保持污点（`param = decode(param)` 不是净化）",
          "param" in res.at(2), f"行2 污点集={sorted(res.at(2))}")
    check("② 污点经拼接传给新变量（`sql = \"...\" + param`）",
          "sql" in res.at(3), f"行3 污点集={sorted(res.at(3))}")
    check("③ sink 调用行仍能看到污点（供 search 判括号内）",
          "sql" in res.at(4), f"行4 污点集={sorted(res.at(4))}")

    # 1b) 「覆盖即净化」
    src2 = _T(
        'String param = request.getParameter("x");',
        'param = "safe";',
        'String sql = "SELECT 1";',
    )
    res2 = T.analyze(src2, "java")
    check("④ 赋常量即净化（`param = \"safe\"`）",
          "param" not in res2.at(2), f"行2 污点集={sorted(res2.at(2))}")
    check("⑤ 用已净化变量拼串不产生污点",
          "sql" not in res2.at(3), f"行3 污点集={sorted(res2.at(3))}")

    # 1c) 污点起点必须**显式**含外部输入
    src3 = _T(
        'String a = "literal";',
        'String b = a + "more";',
    )
    res3 = T.analyze(src3, "java")
    check("⑥ 纯常量变量不假阳性（无外部输入起点）",
          not res3.at(1) and not res3.at(2), f"{sorted(res3.at(2))}")

    # 1d) 「按源码顺序」：第 N 行赋值只影响 N 行之后
    src4 = _T(
        'connection.prepareStatement(sql);',
        'String sql = request.getParameter("x");',
    )
    res4 = T.analyze(src4, "java")
    check("⑦ 严格按源码顺序（sink 在赋值**之前** → 当时还不是污点）",
          "sql" not in res4.at(1), f"行1 污点集={sorted(res4.at(1))}")

    # 1e) 各语言的外部输入起点
    print("\n=== ② 语言级外部输入起点 ===")
    cases = [
        ("php", '$x = $_GET["a"];'),
        ("php", '$x = $_POST["a"];'),
        ("java", 'String x = request.getParameter("a");'),
        ("java", 'String x = request.getHeader("a");'),
        ("java", 'String x = theCookie.getValue();'),
        ("python", 'x = request.args.get("a")'),
        ("python", 'x = input()'),
        ("javascript", 'let x = req.query.a;'),
        ("javascript", 'let x = req.body.a;'),
    ]
    for lang, line in cases:
        r = T.analyze(_T(line), lang)
        check(f"{lang}: 认得 {line[:38]}", bool(r.at(1)))

    # 1f) 刻意的负例：元数据 API 不算外部输入（收了会大面积误报）
    print("\n=== ③ 刻意不认的取值 API（防误报扩大）===")
    for line in ('String x = request.getRequestURI();',
                 'String x = request.getSession().getId();',
                 'String x = request.getRequestURL().toString();'):
        r = T.analyze(_T(line), "java")
        check(f"元数据 API 不判污点：{line[:40]}", not r.at(1), f"实得 {sorted(r.at(1))}")

    # ============================================ ④ 规则库结构约束
    print("\n=== ④ 规则库结构约束（v069 第一版的结构性错误）===")
    with_call = [r for r in S.ALL if r.call_pattern]
    check("存在带 call_pattern 的规则（taint 层不是空转）",
          len(with_call) >= 3, f"{sorted(r.id for r in with_call)}")

    # ⚠️ 关键断言：禁止「同 pattern 的平行规则」
    by_pat: dict[str, list[str]] = {}
    for r in S.ALL:
        by_pat.setdefault(r.pattern, []).append(r.id)
    dup = {p: ids for p, ids in by_pat.items() if len(ids) > 1}
    check("不存在 pattern 完全相同的规则（**禁止平行规则**）",
          not dup, f"重复：{dup}" if dup else f"共 {len(by_pat)} 个唯一 pattern")

    # 每条带 call_pattern 的规则，call_pattern 必须能编译
    bad = []
    for r in with_call:
        try:
            r.call_regex()
        except re.error as e:
            bad.append(f"{r.id}: {e}")
    check("所有 call_pattern 都能编译", not bad, str(bad))

    # call_pattern 不能太宽（它只描述「哪次调用」，不该出现 `.*` / `\w*` 这种通吃）
    too_wide = [r.id for r in with_call
                if re.search(r"\.\*|\\w\*\s*\\\(|\[\^\\\\n\]\*", r.call_pattern)]
    check("call_pattern 里没有明显的通吃写法（防误报爆炸）",
          not too_wide, str(too_wide) if too_wide else "")

    # ============================================ ⑤ 两层匹配端到端
    print("\n=== ⑤ 两层匹配端到端（同一行能产出两条不同强度的命中）===")
    import tempfile                                    # noqa: PLC0415
    from app.codebase import ingest as G               # noqa: PLC0415
    from app.codebase import index as I                # noqa: PLC0415

    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        # 跨行形态：拼接在上一行，sink 在下一行
        (d / "Crossline.java").write_text("\n".join([
            "class Crossline {",
            "  void go(javax.servlet.http.HttpServletRequest request) throws Exception {",
            '    String param = request.getParameter("x");',
            '    String sql = "{call " + param + "}";',
            "    connection.prepareCall(sql);",
            "  }",
            "}",
        ]) + "\n", encoding="utf-8")
        # 行级形态：拼接就在 sink 那一行
        (d / "Inline.java").write_text("\n".join([
            "class Inline {",
            "  void go(javax.servlet.http.HttpServletRequest request) throws Exception {",
            '    String param = request.getParameter("x");',
            '    statement.executeQuery("SELECT " + param);',
            "  }",
            "}",
        ]) + "\n", encoding="utf-8")
        # 跨行**参数区**：调用名一行、参数在下一行
        (d / "SplitArgs.java").write_text("\n".join([
            "class SplitArgs {",
            "  void go(javax.servlet.http.HttpServletRequest request) throws Exception {",
            '    String param = request.getParameter("x");',
            '    String sql = "SELECT " + param;',
            "    connection.prepareStatement(",
            "        sql, ResultSet.TYPE_SCROLL_INSENSITIVE);",
            "  }",
            "}",
        ]) + "\n", encoding="utf-8")

        res_ing = G.ingest(str(d), source_kind="opensource")
        cid = res_ing.codebase_id
        I.build(cid)
        hits = Q.search_sinks(cid, limit=500)

        def _find(stem, extractor_like):
            return [h for h in hits
                    if pathlib.Path(h.file).stem == stem and extractor_like in h.extractor]

        cl = _find("Crossline", "taint")
        check("跨行形态：产出 `taint(lexical)` 命中（拼接与 sink 分离）",
              bool(cl), str([(h.rule_id, h.extractor) for h in hits]))
        if cl:
            check("跨行命中的 rule_id 带 `@taint` 后缀（可区分证据强度）",
                  all(h.rule_id.endswith("@taint") for h in cl), str([h.rule_id for h in cl]))
            check("跨行命中的 why 明确标了「跨行污染」",
                  all("跨行污染" in h.why for h in cl), cl[0].why[:70])
            check("跨行命中的 hint 要求「先往上读赋值行」（不假装和行级一样强）",
                  all("赋值" in h.hint for h in cl), cl[0].hint[:70])

        il = _find("Inline", "lexical")
        check("行级形态：照旧产出 `lexical` 命中（原行为不受影响）",
              bool(il), str([(h.rule_id, h.extractor) for h in hits]))

        sa = _find("SplitArgs", "taint")
        check("跨行**参数区**：`prepareStatement(\\n  sql, …)` 也判得了",
              bool(sa), str([(h.rule_id, h.extractor) for h in hits]))

        # 负例：安全的参数化写法**不该**产出 taint 命中
        (d / "Safe.java").write_text("\n".join([
            "class Safe {",
            "  void go() throws Exception {",
            '    String sql = "SELECT * FROM u WHERE n=?";',
            "    connection.prepareStatement(sql).setString(1, \"x\");",
            "  }",
            "}",
        ]) + "\n", encoding="utf-8")
        cid2 = G.ingest(str(d), source_kind="opensource").codebase_id
        I.build(cid2)
        hits2 = Q.search_sinks(cid2, limit=500)
        safe_taint = [h for h in hits2
                      if pathlib.Path(h.file).stem == "Safe" and "@taint" in h.rule_id]
        check("负例：参数化写法（`sql` 是常量）不产出 taint 命中",
              not safe_taint, str([(h.rule_id, h.text.strip()[:50]) for h in safe_taint]))

    # ============================================ ⑥ 端到端真实仓库（抽样）
    print("\n=== ⑥ 全限定名修正（v069 的另一个实测发现）===")
    # `java.path.file` 的 pattern 必须允许可选包名前缀 —— 用**行为**验证，不去抠正则文本
    # （抠文本既难写又脆：`[\w.]+\.` 在 Python 字符串里怎么转义，取决于写的人怎么想）。
    r_path = S.by_id("java.path.file")
    check("`java.path.file` 规则存在", r_path is not None)
    for sample, should_hit in (("new java.io.FileInputStream(f)", True),
                               ("new FileInputStream(f)", True),
                               ("new java.io.RandomAccessFile(f, \"r\")", True),
                               ("new java.util.ArrayList()", False),
                               ("new BufferedReader(new FileReader(f))", True)):
        got = bool(r_path.regex().search(sample))
        check(f"path.file {'命中' if should_hit else '不命中'}：{sample[:42]}",
              got == should_hit, f"实得 {got}")

    r_url = S.by_id("java.ssrf.url")
    for sample, should_hit in (("new java.net.URL(u)", True),
                               ("new URL(u)", True)):
        got = bool(r_url.regex().search(sample))
        check(f"ssrf.url {'命中' if should_hit else '不命中'}：{sample}",
              got == should_hit, f"实得 {got}")

    # ⚠️ 防「修全限定名修过头」：不能退化成 `new\s+[\w.]*\s*\(`（任意类名）
    over = [r.id for r in S.ALL
            if re.search(r"new\\s\+\[\\w\.\]\*\s*\\\(", r.pattern)]
    check("没有规则把 `new` 后面的类名放宽成「任意类名」",
          not over, str(over) if over else "")

    # ============================================ ⑦ 文档必须写到 v069 的新概念
    print("\n=== ⑦ 白盒 KB 篇目已反映 v069（防文档漂移）===")
    kb_dir = REPO / "data" / "kb"
    triage = (kb_dir / "whitebox-sink-triage.md").read_text(encoding="utf-8")
    for kw, desc in (("@taint", "跨行命中的可区分标记"),
                     ("跨行污染", "跨行形态本身"),
                     ("全限定名", "全限定名盲区"),
                     ("extractor", "抽取精度字段")):
        check(f"分类篇写了「{kw}」（{desc}）", kw in triage)
    # Benchmark 的真实召回数字（防「只写 DVWA 100%」的失真叙事）
    check("分类篇写了真实项目的召回（不是只有 DVWA 的 100%）",
          "Benchmark" in triage and ("20.4%" in triage or "161/790" in triage), "")
    # 「别信命中总数」这条教训
    check("分类篇写了「别信命中总数」这条教训",
          "总数" in triage and "骗人" in triage, "")

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
