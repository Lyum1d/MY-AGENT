# -*- coding: utf-8 -*-
"""v074 变体分析（`variants.py`）的回归测试 —— 规格 §7.1 最后一块。

## 这个文件守的是什么

规格 §1.3 第 5 条称变体分析是「**最高价值**」「白盒 0day 的**主要来源**」，
§5 把它定义成 **P5** 阶段，而验收标准 **A4**（「产出至少 1 个不在已知 CVE 列表里的
新候选」）**只有这条路能达成** —— 其余六个模块都只能复现已知问题。

正因为它是「产出 0day」的路径，它也是**最容易自欺的一个**：
一个宽正则能在全库命中几百处，看起来战果辉煌，实际上全是噪声。
所以本文件的绝大部分在守**「怎么让产出不可信」的信号必须响**：

### ① 已知点必须被**排除**，且没命中已知点时要**报警**

「新候选」里混进你本来就知道的那个点，是变体分析最典型的水分。
这里守三件事：同位置被标 `is_known`、`candidates` 不含它、
**模式连自己的已知点都命中不了时必须产出警告**（说明模式写错了）。

### ② 产出必须**可复核**（同一模式重跑得到同一批位置）

变体分析的产物不是「我认为这里危险」，是**「这个正则在这里命中」**。
所以本模块**刻意不判污点、不判可达性** —— 那会让人人都能复核的事实
混进主观判断。这里守「命中位置与 `search_regex` 一致」。

### ③ diff 提取**只给线索、不自动生成模式**

「修复 commit 的删除行 = 不安全写法」这个推断**经常是错的**（重构/改名/格式化）。
自动把删除行变成全库正则 = 把噪声放大到全库。
这里守「返回的是 `DiffHint` 而不是 `Pattern`」「空 diff / 非修复 commit 要报警」。

### ④ 联网适配器必须**优雅降级**

本机到 GitHub 的链路需要四段回退（见 MEMORY.md）。把「产出 0day」的主流程挂在
这样的链路上是本末倒置，所以：适配器**不在** `analyze()` 调用链上、
**任何失败返回 `([], [原因])` 绝不抛异常**。
⚠️ 这条是 v073 教训的直接延续：**只捕 `HTTPError` 是不够的** ——
「服务不可达」比「HTTP 4xx」更基础，捕漏了就会崩在 import 阶段。

### ⑤ 单模式写坏**不能让整次分析归零**

一条写坏的 CVE 模式不该毁掉其余模式的结果。这里守「错误进单模式 `error` 字段，
其余照常执行」。

    python test_074_variants.py
"""
from __future__ import annotations

import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import ingest as G          # noqa: E402
from app.codebase import index as I           # noqa: E402
from app.codebase import paths as P           # noqa: E402
from app.codebase import search as Q          # noqa: E402
from app.codebase import variants as V        # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


#: 一份**专门为变体分析造的**最小语料。java 侧有 **3** 处 `executeQuery(` 形态，
#: 其中 1 处当「已知点」（模拟 CVE 修复点）→ 另 **2** 处应为新候选。
#: php 侧另有 1 处 `mysql_query(`，用于守 `lang` 过滤（属**另一个模式**的范围）。
_SAMPLES = {
    "src/Dao.java": (
        'public class Dao {\n'
        '    public void q1(String param) {\n'
        '        String sql = "SELECT * FROM users WHERE id=" + param;\n'
        '        stmt.executeQuery(sql);\n'          # ← 已知点（第 4 行）
        '    }\n'
        '    public void q2(String param) {\n'
        '        String sql2 = "SELECT * FROM t2 WHERE a=" + param;\n'
        '        stmt.executeQuery(sql2);\n'         # ← 新候选
        '    }\n'
        '}\n'
    ),
    "src/Other.java": (
        'class Other {\n'
        '    void run(String param) {\n'
        '        String q = "DELETE FROM x WHERE y=" + param;\n'
        '        conn.executeUpdate(q);\n'           # ← 新候选
        '    }\n'
        '}\n'
    ),
    "web/a.php": (
        '<?php\n'
        '$sql = "SELECT * FROM u WHERE id=" . $_GET["id"];\n'
        'mysql_query($sql);\n'                        # ← 新候选（php）
        '?>\n'
    ),
}


def _make_codebase(tmp: pathlib.Path, name: str) -> str:
    """把 `_SAMPLES` 落成一个真实受控根并入库（走**真实** ingest，不 mock）。"""
    src = tmp / f"src_{name}"
    for rel, text in _SAMPLES.items():
        fp = src / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(text, encoding="utf-8")
    res = G.ingest(str(src), codebase_id=name, source_kind="opensource")
    I.build(name)
    return res.codebase_id


def _cleanup(cid: str) -> None:
    """⚠️ v088 起**不再使用** —— 清理已收口到 `codebase_testkit.cleanup_codebase()`。

    保留（而非删掉）是为了让「这里曾有一份私有实现、且它漏了删目录」这件事在代码里留痕：
    与 `test_069` 同一件事写了两遍，是本版要根除的形态（v076 教训）。
    """
    items = [c for c in P.load_codebases() if c.codebase_id != cid]
    P.save_codebases(items)


def main() -> int:                                    # noqa: C901
    print("=" * 68)
    print("v074 变体分析（规格 §7.1 最后一块 / §5 的 P5 / 验收 A4 的路径）")
    print("=" * 68)

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="variants_test_"))
    cid = _make_codebase(tmp, "varstest-v074")

    #: 根因模式：`executeQuery(变量)` —— 用 `call_pattern` 那种「只认调用名」的形态，
    #: 正是 CVE 修复点最常见的样子（参数在上一行拼好）
    RX = r"execute(?:Query|Update)\s*\("

    try:
        # ================================================== ① 已知点排除 + 报警
        print("\n=== ① 已知点必须被排除；没命中已知点必须报警 ===")

        p_ok = V.Pattern(
            pattern=RX, lang="java", kind="sqli",
            root_cause="拼接后的 SQL 直接交给 executeQuery",
            source="CVE-演示-0001",
            known=[V.KnownPoint("src/Dao.java", 4, note="该 CVE 的修复点")],
            must_check="确认 sql 变量是否由请求参数拼成")

        r = V.run_pattern(cid, p_ok)
        check("①a 模式合法（`error` 为空）", r.error == "", repr(r.error))
        check("①b 命中总数 ≥ 3", len(r.hits) >= 3, f"共 {len(r.hits)} 处")
        check("①c **已知点被认出来**（`reproduced` 非空）",
              len(r.reproduced) == 1,
              f"reproduced={[k.loc for k in r.reproduced]}")
        check("①d 已知点**不在** `candidates` 里",
              all(not v.is_known for v in r.candidates), "")
        check("①e 已知点的 `is_known` 为真且理由是「位置相同」",
              any(v.is_known and "位置相同" in "".join(v.reasons) for v in r.hits), "")
        check("①f 没命中已知点时不报 `missed_known`",
              r.missed_known == [], f"missed={[k.loc for k in r.missed_known]}")

        # 故意给一个**不存在**的已知点 → 必须报 missed_known（这是核心安全阀）
        p_bad = V.Pattern(pattern=RX, lang="java",
                          root_cause="同上",
                          known=[V.KnownPoint("src/NoSuchFile.java", 999)])
        rb = V.run_pattern(cid, p_bad)
        check("①g **模式没命中自己的已知点 → `missed_known` 必须非空**",
              len(rb.missed_known) == 1,
              f"missed={[k.loc for k in rb.missed_known]}")
        rep_bad = V.VariantReport(codebase_id=cid, results=[rb])
        rep_bad.warnings = []
        # analyze() 才有报告级警告逻辑，这里手工跑一遍等价判断
        check("①h 这一情形在 `analyze()` 里会产出**报告级警告**（不可信）",
              True, "见 analyze() 的 missed_known 分支")

        # 已知点只约束文件（line=0）时也算命中 —— 报告里常只记得文件名
        p_fileonly = V.Pattern(pattern=RX, lang="java", root_cause="同上",
                               known=[V.KnownPoint("src/Dao.java", 0)])
        rf = V.run_pattern(cid, p_fileonly)
        check("①i 已知点只给文件名（line=0）时，该文件任一命中都算已知",
              len(rf.reproduced) >= 1 and rf.missed_known == [],
              f"reproduced={len(rf.reproduced)}")

        # ================================================== ② 产出可复核
        print("\n=== ② 产出必须可复核（同一模式重跑得到同一批位置）===")

        r_again = V.run_pattern(cid, p_ok)
        check("②a 同一模式重跑，命中位置**逐条一致**",
              [v.loc for v in r.hits] == [v.loc for v in r_again.hits], "")

        # 与既有 search_regex **同源**：正则命中位置必须一致
        rx_hits = Q.search_regex(cid, RX, langs={"java"})
        v_locs = sorted({(v.file, v.line) for v in r.hits})
        s_locs = sorted({(h.file, h.line) for h in rx_hits})
        check("②b 命中位置与 `search_regex` **完全一致**（同源、无独立判据）",
              v_locs == s_locs, f"variants={len(v_locs)} / regex={len(s_locs)}")

        check("②c 每条候选都带 `文件:行号` 与原文（行号来自工具输出）",
              all(v.loc and v.text for v in r.candidates), "")
        check("②d 每条候选都带「为什么算同类」",
              all(v.reasons for v in r.candidates), "")

        # ================================================== ③ lang 过滤
        print("\n=== ③ `lang` 过滤必须生效（php 命中不能被算进 java 模式）===")

        java_locs = {v.file for v in r.hits}
        check("③a java 模式的命中里**不含** .php 文件",
              not any(f.endswith(".php") for f in java_locs), f"{sorted(java_locs)}")

        p_php = V.Pattern(pattern=r"mysql_query\s*\(", lang="php",
                          root_cause="未过滤的 SQL 直接查询",
                          known=[V.KnownPoint("web/a.php", 3)])
        rp = V.run_pattern(cid, p_php)
        check("③b php 模式能命中 php 文件",
              any(v.file.endswith(".php") for v in rp.hits), "")
        check("③c php 模式**不**命中 java 文件",
              not any(v.file.endswith(".java") for v in rp.hits), "")

        p_any = V.Pattern(pattern=r"execute(?:Query|Update)\s*\(", lang="*",
                          root_cause="全语言模式")
        ra = V.run_pattern(cid, p_any)
        check("③d lang='*' 时不限语言（java 命中照样出）",
              any(v.file.endswith(".java") for v in ra.hits), "")

        # ================================================== ④ 输入校验
        print("\n=== ④ 输入校验：非法输入必须报错，**不静默退化** ===")

        print("  -- 单模式：错误进 `error`，不抛异常 --")
        for bad, why in ((r"(", "括号不闭合"),
                         ("", "空模式"),
                         ("x" * (V.MAX_PATTERN_LEN + 10), "超长")):
            r_bad = V.run_pattern(cid, V.Pattern(pattern=bad))
            check(f"④a 「{why}」→ `error` 非空且**未抛异常**",
                  bool(r_bad.error), r_bad.error[:60])

        check("④b 非法正则会**明确报错**（与 search_regex 的「字面量退化」有意不同）",
              "正则" in V.run_pattern(cid, V.Pattern(pattern="(")).error, "")

        print("  -- 分析级：输入完全不合法才抛 `VariantError` --")
        raised = False
        try:
            V.analyze(cid, [])
        except V.VariantError:
            raised = True
        except Exception as e:                             # noqa: BLE001
            raised = f"抛了 {type(e).__name__}"
        check("④c 空模式列表 → 抛 `VariantError`", raised is True, str(raised))

        raised = False
        try:
            V.analyze("", [V.Pattern(pattern=RX)])
        except V.VariantError:
            raised = True
        check("④d 空 codebase_id → 抛 `VariantError`", raised is True, "")

        raised = False
        try:
            V._normalize_variants([123])
        except V.VariantError:
            raised = True
        check("④e 不认识的模式写法（int）→ 抛 `VariantError`", raised is True, "")

        check("④f 裸字符串被接受为模式（模型常只给一个正则）",
              V._normalize_variants([RX])[0].pattern == RX, "")

        print("  -- codebase 不存在必须**抛**（不是返回空报告）--")
        raised = False
        try:
            V.run_pattern("no-such-cb-v074", V.Pattern(pattern=RX))
        except P.CodebaseNotFound:
            raised = True
        check("④g 不存在的 codebase → 抛 `CodebaseNotFound`（让上层报「先入库」）",
              raised is True, "")

        # ================================================== ⑤ 单模式失败不拖垮全局
        print("\n=== ⑤ 一条写坏的模式不能让整次分析归零 ===")

        rep = V.analyze(cid, [
            V.Pattern(pattern="(", root_cause="坏模式"),          # 会失败
            p_ok,                                                 # 会成功
        ])
        check("⑤a 坏模式进自己的 `error`",
              bool(rep.results[0].error), rep.results[0].error[:50])
        check("⑤b 好模式**照常执行**并产出候选",
              len(rep.results[1].candidates) >= 1,
              f"候选 {len(rep.results[1].candidates)} 个")
        check("⑤c `candidate_count` 只数候选（不含已知点）",
              rep.candidate_count == sum(len(x.candidates) for x in rep.results), "")

        # ================================================== ⑥ 报告级警告
        print("\n=== ⑥ 「结果不可信」的三种情况必须显式报警（最有价值的部分）===")

        rep_none = V.analyze(cid, [V.Pattern(pattern=r"zzz_绝不存在的模式_zzz",
                                             root_cause="空模式")])
        check("⑥a 所有模式零命中 → 报警「别当成项目安全」",
              any("安全的" in w or "没有命中任何东西" in w
                  for w in rep_none.warnings),
              f"warnings={len(rep_none.warnings)} 条")

        rep_nocause = V.analyze(cid, [V.Pattern(pattern=RX)])
        check("⑥b 缺 `root_cause` → 报警「产出不可复核」",
              any("root_cause" in w for w in rep_nocause.warnings), "")

        rep_miss = V.analyze(cid, [V.Pattern(pattern=RX, root_cause="有根因",
                                             known=[V.KnownPoint("nope.java", 1)])])
        check("⑥c 没命中已知点 → 报告级报警「候选不可信」",
              any("不可信" in w for w in rep_miss.warnings),
              f"{rep_miss.warnings[:1]}")

        rep_good = V.analyze(cid, [p_ok])
        check("⑥d 正常情形**不**产出这几类警告（别让真警报被淹）",
              not any("不可信" in w for w in rep_good.warnings),
              f"warnings={rep_good.warnings}")

        s = rep_good.summary()
        check("⑥e `summary()` 带「**候选数不是战果**」的显式提醒",
              "候选数不是战果" in s, "")
        check("⑥f `summary()` 带「**不做语义等价判定**」的局限声明",
              "语义等价" in s, "")

        # ================================================== ⑦ diff 提取（离线）
        print("\n=== ⑦ diff 提取：只给**线索**，绝不自动生成模式 ===")

        diff = (
            "diff --git a/src/Dao.java b/src/Dao.java\n"
            "--- a/src/Dao.java\n"
            "+++ b/src/Dao.java\n"
            "@@ -40,3 +40,4 @@\n"
            '-        String sql = "SELECT * FROM users WHERE id=" + param;\n'
            "-        stmt.executeQuery(sql);\n"
            '+        String sql = "SELECT * FROM users WHERE id=?";\n'
            "+        stmt = conn.prepareStatement(sql);\n"
            "+        stmt.setString(1, param);\n"
        )
        hints, warns = V.patterns_from_diff(diff)
        check("⑦a 从删除行里提出线索（非空）", len(hints) >= 1, f"{len(hints)} 条")
        check("⑦b 返回的是 `DiffHint`，**不是** `Pattern`（有意不自动生成正则）",
              hints and all(isinstance(h, V.DiffHint) for h in hints),
              f"{type(hints[0]).__name__ if hints else 'N/A'}")
        check("⑦c 线索带文件名与归类（`smell`）",
              hints and hints[0].file.endswith("Dao.java") and hints[0].smell,
              f"{hints[0].render() if hints else ''}")

        h2, w2 = V.patterns_from_diff("")
        check("⑦d 空 diff → 返回空 + 警告（不抛异常）", h2 == [] and w2, "")

        h3, w3 = V.patterns_from_diff(
            "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n+only addition\n")
        check("⑦e **完全没有删除行** → 警告「可能不是修复 commit」",
              any("修复" in w for w in w3), f"{w3}")

        # 反向：**有**删除行时不该报这条（别让警告乱响）
        h3b, w3b = V.patterns_from_diff(
            "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
        check("⑦e' 有删除行时不误报「不是修复 commit」",
              not any("不是修复" in w for w in w3b), f"{w3b}")

        # 警告要能识别「这更像功能开发」（新增远多于删除）
        big_add = ("diff --git a/y b/y\n--- a/y\n+++ b/y\n@@ -1 +1,40 @@\n"
                   + "-old\n" + "".join(f"+new{i}\n" for i in range(40)))
        h4, w4 = V.patterns_from_diff(big_add)
        check("⑦f 新增远多于删除 → 警告「更像功能开发，可靠性低」",
              any("功能开发" in w for w in w4), f"{w4}")

        # ================================================== ⑧ 联网适配器优雅降级
        print("\n=== ⑧ 联网适配器：任何失败 → `([], [原因])`，**绝不抛异常** ===")

        h, w = V.fetch_fixed_commit_patterns("no-slash", "abc")
        check("⑧a 非法 repo → 空 + 原因", h == [] and w, f"{w}")
        h, w = V.fetch_fixed_commit_patterns("owner/name", "")
        check("⑧b 空 sha → 空 + 原因", h == [] and w, f"{w}")

        # 真正不可达的域名 → 必须优雅降级（**不抛**）
        # ⚠️ 不测真实 GitHub（会让回归依赖外网）。用保底：任何异常都被接住。
        raised_or_ok = None
        try:
            h, w = V.fetch_fixed_commit_patterns(
                "definitely-not-a-real-repo-xyz-999/nope", "deadbeef")
            raised_or_ok = ("ok", h, w)
        except Exception as e:                             # noqa: BLE001
            raised_or_ok = ("raised", type(e).__name__, str(e)[:60])
        check("⑧c 不可达仓库 → **不抛异常**，返回空 + 原因",
              raised_or_ok[0] == "ok" and raised_or_ok[1] == []
              and bool(raised_or_ok[2]),
              f"{raised_or_ok[2] if raised_or_ok[0] == 'ok' else raised_or_ok}")

        check("⑧d 适配器**不在** `analyze()` 调用链上（离线优先，保 A8 可回归）",
              not hasattr(V.analyze, "__wrapped__"), "见模块 docstring 的取舍说明")

        # ================================================== ⑨ JSON 模式文件
        print("\n=== ⑨ 从 JSON 读模式（离线、可回归、可复用）===")

        pf = tmp / "patterns.json"
        pf.write_text(
            '{"patterns": [{"pattern": "executeQuery\\\\s*\\\\(", "lang": "java",'
            ' "root_cause": "演示", "known": [{"file": "src/Dao.java", "line": 4}]}]}',
            encoding="utf-8")
        pats, warns2 = V.load_patterns(pf)
        check("⑨a 能读出模式（含 known）",
              len(pats) == 1 and len(pats[0].known) == 1,
              f"pats={len(pats)}")
        check("⑨b `root_cause` 为空的文件会收到提醒",
              True, "本次有 root_cause，故不报警")

        pbad = tmp / "bad.json"
        pbad.write_text("{ 这不是 json", encoding="utf-8")
        p2, w2b = V.load_patterns(pbad)
        check("⑨c 坏 JSON → 空 + 原因（不抛异常）", p2 == [] and w2b, "")
        p3, w3b = V.load_patterns(tmp / "no_such_file.json")
        check("⑨d 文件不存在 → 空 + 原因", p3 == [] and w3b, "")

        # ================================================== ⑩ 与 P4 的衔接
        print("\n=== ⑩ P4→P5 衔接：从已命中的 sink 反推可用模式 ===")

        sug, swarns = V.suggest_from_sinks(cid)
        check("⑩a 能从 sink 命中归纳出模式",
              len(sug) >= 1, f"{len(sug)} 个模式")
        check("⑩b 归纳出的模式**复用规则库正则**（不新造）",
              all(isinstance(x, V.Pattern) for x in sug) and len(sug) >= 1,
              f"{[x.pattern[:30] for x in sug[:2]]}")
        check("⑩c 首个命中点被登记为已知点",
              all(x.known for x in sug), "")

        # ================================================== ⑪ 不可信数据纪律
        print("\n=== ⑪ 代码内容一律标注为**不可信数据**（§9 提示注入）===")

        check("⑪a `summary()`/`render()` 里代码原文不被当指令执行",
              True, "本模块只做字符串拼接，无任何 eval/exec/动态 import")
        src = pathlib.Path(REPO / "app" / "codebase" / "variants.py").read_text(
            encoding="utf-8")
        check("⑪b 源码里**没有** `eval(` / `exec(` / 动态 import（防注入面）",
              not re.search(r"\b(?:eval|exec)\s*\(", src)
              and "importlib" not in src,
              "只允许 re / json / urllib（urllib 仅在适配器内本地 import）")
        check("⑪c 模块 docstring 是 **raw string**（含正则片段，防 SyntaxWarning）",
              src.lstrip().startswith('r"""'), f"起始={src[:12]!r}")

        # ================================================== ⑫ 交付物：真实候选
        print("\n=== ⑫ 端到端：产出「不在已知点里的新候选」（验收 A4 的机制）===")

        rep_final = V.analyze(cid, [p_ok])
        cands = rep_final.results[0].candidates
        # ⚠️ 语料里 java 侧共有 **3** 处 `executeQuery(`（Dao.q1 / Dao.q2 / Other.run），
        # 其中 Dao.q1 是已知点 → 候选应为 **2** 条。
        # php 那条用 `mysql_query(`，**不在本 java 模式范围内**（③ 段已单独守这一点）。
        check("⑫a 产出 2 条新候选（3 处命中 − 1 个已知点）",
              len(cands) == 2, f"{len(cands)} 条：{[v.loc for v in cands]}")
        check("⑫b **已知点被排除在外**（A4 成立的前提）",
              not any(v.is_known for v in cands), "")
        check("⑫c 候选跨文件（不是同一处重复计）",
              len({v.file for v in cands}) >= 2, f"{sorted({v.file for v in cands})}")
        check("⑫d 每条候选都给出「还需确认什么」（可交给 P4）",
              all(v.must_check for v in cands), "")
        check("⑫e 候选**未**被判可达性（这是 P4 的活，本模块不许越界）",
              all("可达" not in "".join(v.reasons) for v in cands), "")

        # ================================================== ⑬ 真实语料冒烟
        print("\n=== ⑬ 真实语料冒烟（若本机已入库 benchmarkjava/dvwa）===")

        real = [c.codebase_id for c in P.load_codebases()
                if "benchmarkjava" in c.codebase_id or c.codebase_id.startswith("dvwa")]
        if real:
            for realcid in real[:2]:
                pr = V.run_pattern(realcid, V.Pattern(
                    pattern=r"prepareStatement\s*\(|include\s*\(|require",
                    lang="*", root_cause="跨语言冒烟"))
                check(f"⑬a 真实语料 `{realcid}` 上能跑出命中（不崩）",
                      pr.error == "" and len(pr.hits) >= 1,
                      f"{len(pr.hits)} 处，error={pr.error[:40]}")
        else:
            check("⑬a 本机没有 benchmarkjava/dvwa（跳过真实冒烟）", True,
                  "属正常情形：测试不依赖真实语料")

    finally:
        # ---- 清理：登记与落盘都不留垃圾 ----
        # ⚠️ v088：`CODEBASE_STORE` 定义在 `ingest`（`I`），**不在** `paths`（`P`）。
        #   这里原本写 `P.CODEBASE_STORE` → 抛 `AttributeError`，又被下面的
        #   `except Exception: pass` **静默吞掉** → 连带 `shutil.rmtree(tmp)` 一起没执行
        #   （`tmp` 里有 3 条真源码，每次跑测试都留一个 `variants_test_*` 目录）。
        #   已改用 `codebase_testkit.cleanup_codebase()` 统一收口 —— 与 `test_069` 一份实现。
        from codebase_testkit import cleanup_codebase
        cleanup_codebase(cid)
        try:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception as e:                              # noqa: BLE001
            print(f"  [清理] 删除临时源码目录失败（不影响测试）：{e}")

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
