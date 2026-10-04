# -*- coding: utf-8 -*-
"""v070 批量基准的回归测试（`app/codebase/batch.py`）。

## 这个文件为什么重要

v069 起「真实召回」这个数字才可信 —— 但它一直靠**手跑的探针脚本**（`_bench_probe.py`）。
手跑的东西有三个毛病：**会漂、会被忘、没人看**。本套件把它变成**产品的一部分**：

- 用**自造的小夹具**（不依赖本机有没有 OWASP Benchmark 检出）验证机器本身；
- 把 v069 实测出的**语义**钉死：命中→用例的归属、按类别聚合、`None` 而非 `0` 的精确性；
- 把**三条纪律**变成会失败的断言（读不到返回空、不抛异常、不做环境硬卡点）。

## 为什么不拿真 Benchmark 跑

那取决于本机有没有检出那份代码 —— 拿它做**硬断言**就是把回归绑到一台机器上
（本项目的既有教训：环境相关的东西不要进硬门槛）。所以：

- **机器语义** → 用小夹具硬卡（本文件）；
- **真 Benchmark** → 另外跑，**只报数**（`data/recall_batch.json.example` 里留了基线）。

    python test_070_batch_benchmark.py
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import batch as B                          # noqa: E402
from app.codebase import index as I                          # noqa: E402
from app.codebase import ingest as G                         # noqa: E402
from app.codebase import paths as P                          # noqa: E402
from app.codebase import recall as R                         # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def _lines(*ls):
    """⚠️ 一律用 `"\\n".join([...])` 造多行文本，**不用三引号/heredoc** ——
    引号错误在这个项目里已经累计栽过 9 次；且 Git Bash 会把三引号里的 `\\n` 变成 `/n`。"""
    return "\n".join(ls)


#: 自造评测集：4 个用例（2 真漏洞 / 2 安全），覆盖「命中 / 漏报 / 误报 / 正确放过」四种情况。
FIXTURE_JAVA = {
    "BenchmarkTest00001.java": _lines(          # sqli 真漏洞 —— 应命中
        "public class BenchmarkTest00001 {",
        "    void go(java.sql.Connection c, String p) throws Exception {",
        "        java.sql.Statement s = c.createStatement();",
        "        s.executeQuery(\"select * from t where a = '\" + p + \"'\");",
        "    }",
        "}",
    ),
    "BenchmarkTest00002.java": _lines(          # sqli 真漏洞 —— 形态打不到（漏报）
        "public class BenchmarkTest00002 {",
        "    void go(String p) {",
        "        String q = \"select * from t where a = \" + p;",
        "        helper(q);",
        "    }",
        "    void helper(String q) { }",
        "}",
    ),
    "BenchmarkTest00003.java": _lines(          # sqli 安全 —— 参数化，不该命中
        "public class BenchmarkTest00003 {",
        "    void go(java.sql.Connection c, String p) throws Exception {",
        "        java.sql.PreparedStatement s = c.prepareStatement(",
        "            \"select * from t where a = ?\");",
        "        s.setString(1, p);",
        "    }",
        "}",
    ),
    "BenchmarkTest00004.java": _lines(          # sqli 安全 —— **但会误报**（宽口径规则）
        "public class BenchmarkTest00004 {",
        "    void go(java.sql.Connection c, String p) throws Exception {",
        "        java.sql.Statement s = c.createStatement();",
        "        s.executeQuery(\"select * from t where a = '\" + p + \"'\");",
        "    }",
        "}",
    ),
}

#: ⚠️ v071：这 4 个用例**故意不写源码** —— 用来硬卡「部分检出」口径。
#: CSV 里有标注、检出里没文件 → 必须进 `*_missing`，**不进分母**。
#: 其中 00005 是「真漏洞」，如果它进了分母，sqli 召回会从 1/2 掉到 1/3
#: —— 这正是 v069/v070 那个「分母虚高」错误的最小复现。
MISSING_CASES = ["BenchmarkTest00005", "BenchmarkTest00006",
                 "BenchmarkTest00007", "BenchmarkTest00008"]

FIXTURE_CSV = _lines(
    "# test name, category, real vulnerability, cwe, Benchmark version: fixture",
    "BenchmarkTest00001,sqli,true,89",
    "BenchmarkTest00002,sqli,true,89",
    "BenchmarkTest00003,sqli,false,89",
    "BenchmarkTest00004,sqli,false,89",
    # ---- 以下 4 条**没有源码**（`_build_fixture` 不写这些文件）----
    "BenchmarkTest00005,sqli,true,89",           # 真漏洞但无源码
    "BenchmarkTest00006,sqli,true,89",           # 真漏洞但无源码
    "BenchmarkTest00007,sqli,false,89",          # 安全但无源码
    "BenchmarkTest00008,pathtraver,true,22",     # 另一个类别，整类无源码
)


def _build_fixture(tmp: pathlib.Path) -> pathlib.Path:
    repo = tmp / "fakebench"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    for name, text in FIXTURE_JAVA.items():
        (repo / "src" / name).write_text(text + "\n", encoding="utf-8")
    # ⚠️ v071：故意放两个**非用例文件**进树（真实 Benchmark 里有 140 个这类）。
    # `cases_unannotated` 必须**不把它们算成「无标注的用例」**，
    # 否则那个报警会每轮都响 → 看的人学会忽略它 → 真出问题时也看不见。
    (repo / ".gitignore").write_text("target/\n", encoding="utf-8")
    (repo / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (repo / "expectedresults-fixture.csv").write_text(FIXTURE_CSV + "\n",
                                                      encoding="utf-8")
    return repo


def main() -> int:
    print("=" * 68)
    print("v070 批量基准（真实仓库 + 官方标注）")
    print("=" * 68)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="v070_batch_"))

    print("\n=== ① 标注解析（坏行一律跳过，不抛异常）===")
    bad_csv = tmp / "bad.csv"
    bad_csv.write_text(_lines(
        "# 注释行",
        "",
        "OnlyThree,pathtraver,true",          # 只有 3 列 → 合法（CWE 可缺）
        "TwoCols,sqli",                       # 字段不足 → 跳过
        ",sqli,true",                         # 用例名为空 → 跳过
        "NoCat,,true",                        # 类别为空 → 跳过
        "CapTrue,xss,TRUE",                   # 大小写不敏感
    ) + "\n", encoding="utf-8")
    t = B.load_ground_truth(bad_csv)
    check("坏行被跳过而不是报错", set(t) == {"OnlyThree", "CapTrue"}, str(sorted(t)))
    check("注释行/空行不进入标注", "# 注释行" not in str(t))
    check("缺 CWE 列时 CWE 为空串", t.get("OnlyThree", ("", False, "x"))[2] == "")
    check("真漏洞标记大小写不敏感", t.get("CapTrue", ("", False, ""))[1] is True)
    check("不存在的文件返回空表（**不抛异常**）",
          B.load_ground_truth(tmp / "nope.csv") == {})

    print("\n=== ② 配置加载（读不到就空表；目录不在就跳过）===")
    check("不存在的配置文件返回空表（正常状态，不该报错）",
          B.load_batches(tmp / "nope.json") == [])
    junk = tmp / "junk.json"
    junk.write_text("{ this is not json", encoding="utf-8")
    check("坏 JSON 返回空表而不是抛异常", B.load_batches(junk) == [])

    fixture = _build_fixture(tmp)
    cfg = tmp / "batch.json"
    cfg.write_text(_lines(
        "{",
        '  "batches": [',
        '    {"name": "fixture", "dir": "' + str(fixture).replace("\\", "\\\\") + '",',
        # ⚠️ pathtraver **也**要映射 kind —— 才有「有规则、但本机无源码可测」这一支
        # （若这里不映射，它会掉进「能力外」组，那条分支就永远测不到）
        '     "category_kind": {"sqli": "sqli", "pathtraver": "path_traversal"}},',
        '    {"name": "gone", "dir": "' + str(tmp / "not-here").replace("\\", "\\\\") + '"}',
        "  ]",
        "}",
    ) + "\n", encoding="utf-8")
    loaded = B.load_batches(cfg)
    check("目录不存在的批次被跳过（换机器了不该崩）", len(loaded) == 1,
          str([x.get("name") for x in loaded]))
    check("标注文件被自动定位（expectedresults*.csv）",
          loaded and pathlib.Path(loaded[0]["csv"]).name == "expectedresults-fixture.csv",
          loaded[0]["csv"] if loaded else "—")

    print("\n=== ③ 端到端：召回 / 误报 / 精确性（自造夹具，硬卡）===")
    real_cb, real_idx, real_store = P.CODEBASES_FILE, I.INDEX_DIR, G.CODEBASE_STORE
    cb_existed = real_cb.exists()
    rep = B.run_batch(loaded[0], tmp / "work")
    print()
    print(rep.render())
    print()
    check("没有执行错误", not rep.errors, "；".join(rep.errors))
    check("官方标注条数正确（8 条）", rep.cases_total == 8, str(rep.cases_total))
    check("该批有两个类别 sqli + pathtraver",
          sorted(c.name for c in rep.categories) == ["pathtraver", "sqli"],
          str([c.name for c in rep.categories]))
    sqli = next(c for c in rep.categories if c.name == "sqli")
    # ⚠️ 分母 = **可命中**（4 条），不是标注总数（6 条）—— v071 的核心断言
    check("召回分母 = 可命中真漏洞数（2，不是标注的 4）",
          sqli.vuln_total == 2, str(sqli.vuln_total))
    check("误报分母 = 可命中安全用例数（2，不是标注的 3）",
          sqli.safe_total == 2, str(sqli.safe_total))
    check("无源码真漏洞被单列（不进分母）", sqli.vuln_missing == 2, str(sqli.vuln_missing))
    check("无源码安全用例也被单列", sqli.safe_missing == 1, str(sqli.safe_missing))
    check("annotated 属性 = 可命中 + 无源码", sqli.vuln_annotated == 4,
          str(sqli.vuln_annotated))
    check("真漏洞命中 1 个（形态打得中的那个）", sqli.vuln_hit == 1, str(sqli.vuln_hit))
    check("精确性 = 1/(1+误报数)，且真漏洞与安全用例**分开**统计",
          sqli.precision is not None and 0.0 < sqli.precision <= 1.0,
          f"{sqli.precision}")
    check("召回率 = 命中/真漏洞 且 **不受误报影响**",
          abs(sqli.recall - sqli.vuln_hit / sqli.vuln_total) < 1e-9, f"{sqli.recall:.1%}")

    print("\n=== ③b v071：部分检出（分母口径）===")
    check("报告识别出「部分检出」", rep.partial_checkout is True)
    check("标注总数 8 / 有源码 4 / 无源码 4",
          (rep.cases_total, rep.cases_present, rep.cases_missing) == (8, 4, 4),
          f"{rep.cases_total}/{rep.cases_present}/{rep.cases_missing}")
    check("非用例文件（.gitignore / pom.xml）**不算**无标注用例",
          rep.cases_unannotated == 0, str(rep.cases_unannotated))
    check("缺口不为 0 时**不触发**口径提示（那是版本不一致才报的）",
          not any("口径提示" in e for e in rep.errors), str(rep.errors))
    _r = rep.render()
    check("报告里显式打印缺口（否则数字变了没人知道为什么）",
          "本机检出是部分的" in _r and "不进召回分母" in _r)
    check("缺口提示里写明分母口径",
          "召回分母 = 标注 ∩ 检出 = 4" in _r, "")
    check("类别行标出「标注另有 N 条无源码已排除」",
          "标注另有 3 条无源码，已排除" in _r, "")
    # 整类无源码的类别：报「召回 0/0 = 0.0%」是把「没测」说成「0 分」（v067 同族）
    pt = next(c for c in rep.categories if c.name == "pathtraver")
    check("整类无源码 → 该类别分母为 0（**没测到**）",
          pt.vuln_total == 0 and pt.vuln_missing == 1,
          f"{pt.vuln_total}/{pt.vuln_missing}")
    check("「有规则但无源码可测」的类别**单列**且写明不是 0 分",
          "有规则、但本机无源码可测的类别" in _r and "没测到，不是 0 分" in _r, "")
    check("小计**不含**无源码可测的类别（否则召回被稀释成假象）",
          "小计（1 个类别）" in _r, "")

    print("\n=== ③c v071：精确性的**跨 kind 污染**（去掉别类规则的「误报」）===")
    # 夹具里 00004 是 sqli 安全用例，但其代码含 `.executeQuery("... " + p)`
    # → 被 **sqli 规则**命中 = 真·同 kind 误报。
    # 为了测跨 kind，另造一个：安全用例里放 `new java.io.File(`（pathtraver 规则），
    # 但该用例标注的是 sqli → 这是**别的 kind 蹭进来**，不算 sqli 的误报。
    xk = tmp / "crosskind"
    (xk / "src").mkdir(parents=True, exist_ok=True)
    (xk / "src" / "BenchmarkTest00001.java").write_text(_lines(
        "public class BenchmarkTest00001 {",
        "    void go(java.sql.Connection c, String p) throws Exception {",
        "        java.sql.Statement s = c.createStatement();",
        "        s.executeQuery(\"select * from t where a = '\" + p + \"'\");",
        "    }",
        "}") + "\n", encoding="utf-8")
    # 这个标注是 sqli 安全，但代码里**没有 sqli sink**，只有文件操作
    (xk / "src" / "BenchmarkTest00002.java").write_text(_lines(
        "public class BenchmarkTest00002 {",
        "    void go(String p) throws Exception {",
        "        java.io.File f = new java.io.File(p);",
        "        f.exists();",
        "    }",
        "}") + "\n", encoding="utf-8")
    (xk / "expectedresults-fixture.csv").write_text(_lines(
        "BenchmarkTest00001,sqli,true,89",
        "BenchmarkTest00002,sqli,false,89",
    ) + "\n", encoding="utf-8")
    xrep = B.run_batch({"name": "crosskind", "dir": str(xk),
                        "category_kind": {"sqli": "sqli"}}, tmp / "work4")
    xs = xrep.categories[0]
    check("文件级口径：安全用例被**任何** kind 命中 → 计入 safe_hit",
          xs.safe_hit == 1, str(xs.safe_hit))
    check("kind 级口径：那命中**不是 sqli** → 不计入 kindhit_safe",
          xs.kindhit_safe == 0, str(xs.kindhit_safe))
    check("跨 kind 命中被单列出来", xs.crosshit_safe == 1, str(xs.crosshit_safe))
    check("文件级精确性被跨 kind 拖低（1/2 = 50%）",
          abs(xs.precision - 0.5) < 1e-9, f"{xs.precision}")
    check("kind 级精确性**不受影响**（1/1 = 100%）",
          abs(xs.precision_kind - 1.0) < 1e-9, f"{xs.precision_kind}")
    xr = xrep.render()
    check("render() 主值用 kind 级、文件级放括号",
          "100.0%（文件级 50.0%）" in xr, "")
    # 「一致时不显示文件级」要**只看类别行**，别把末尾的口径说明也数进去
    cat_line = next(l for l in xr.splitlines() if l.strip().startswith("sqli"))
    check("类别行只在两边不一致时才补文件级（避免噪音）",
          "文件级" in cat_line and cat_line.count("文件级") == 1, cat_line.strip()[:90])
    same = B.Category(name="same", kind="k", vuln_total=1, safe_total=1,
                      vuln_hit=1, safe_hit=0, kindhit_vuln=1, kindhit_safe=0)
    check("kind 级与文件级一致时**不**补括号",
          "文件级" not in same.render(), same.render().strip()[:90])
    check("两类精确性都为 None 时显示「未测」（不是 0）",
          B.Category(name="z", kind="k")._fmt_prec() == "（未测）", "")

    print("\n=== ④ 三条纪律 ===")
    # 纪律一：读不到标注 → 报错进 errors，不是抛异常
    norep = B.run_batch({"name": "no-truth", "dir": str(fixture),
                         "ground_truth": "does-not-exist.csv"}, tmp / "work2")
    check("读不到标注文件时**进 errors 而不是抛异常**",
          bool(norep.errors) and norep.cases_total == 0, str(norep.errors[:1]))
    check("出错时 render() 仍能输出（不炸）", "读不到标注文件" in norep.render())
    # 纪律二：能力外类别单列
    covered = {c.name for c in rep.covered}
    check("有 kind 映射的类别进「有能力」组", "sqli" in covered, str(covered))
    # 纪律三：只读性
    check("跑完后真实 codebases 记录**没被改写/新建**",
          P.CODEBASES_FILE == real_cb and real_cb.exists() == cb_existed,
          f"{P.CODEBASES_FILE}")
    check("索引目录指回原路径（mock 已还原）", I.INDEX_DIR == real_idx, str(I.INDEX_DIR))
    check("入库落盘位置指回原路径", G.CODEBASE_STORE == real_store, str(G.CODEBASE_STORE))

    print("\n=== ④b 「用例文件无标注」= 版本不一致，必须报警 ===")
    # 造一个「检出里有 BenchmarkTest99999、CSV 里没有」的仓库
    # → 说明标注与检出不是同一版本，此时召回数字不可信，必须提示。
    mism = tmp / "mismatch"
    (mism / "src").mkdir(parents=True, exist_ok=True)
    for name, text in FIXTURE_JAVA.items():
        (mism / "src" / name).write_text(text + "\n", encoding="utf-8")
    (mism / "src" / "BenchmarkTest99999.java").write_text(
        _lines("public class BenchmarkTest99999 {", "}") + "\n", encoding="utf-8")
    (mism / ".gitignore").write_text("target/\n", encoding="utf-8")
    (mism / "expectedresults-fixture.csv").write_text(FIXTURE_CSV + "\n",
                                                      encoding="utf-8")
    mrep = B.run_batch({"name": "mismatch", "dir": str(mism),
                        "category_kind": {"sqli": "sqli"}}, tmp / "work3")
    check("检出里有 CSV 没标的用例 → 计入 cases_unannotated",
          mrep.cases_unannotated == 1, str(mrep.cases_unannotated))
    check("此时**发出**口径提示（数字仅供参考）",
          any("口径提示" in e for e in mrep.errors), str(mrep.errors[:1]))
    check("该提示**不阻断**跑分（errors 里只有提示，没有失败）",
          len(mrep.errors) == 1 and mrep.categories, str(len(mrep.errors)))
    check("非用例文件仍不算（.gitignore 不是用例）",
          mrep.cases_unannotated == 1, str(mrep.cases_unannotated))

    print("\n=== ⑤ 「没测」不是「0 分」（v067 踩过的坑，这里同样必须成立）===")
    empty = B.Category(name="nothing", kind="sqli")
    check("一次都没命中时 precision 返回 None（未测）", empty.precision is None)
    check("一次都没命中时 recall 是 0.0（**有分母才叫 0 分**）", empty.recall == 0.0)
    check("无真漏洞用例时 recall 也是 0.0（分母为 0 不除零）",
          B.Category(name="x", kind="k", safe_total=5, safe_hit=5).recall == 0.0)
    check("汇总里全无命中时 precision 为 None 而不是 0.0",
          B.BatchReport(categories=[empty]).total([empty])["precision"] is None)
    # ⚠️ v071：整类无源码时，报「召回 0%」是**把没测说成 0 分**。
    # 判定权在 render()（单列），但结构上必须保证：无源码**不进分母**。
    ghost = B.Category(name="ghost", kind="sqli", vuln_missing=50, safe_missing=50)
    check("整类无源码 → 分母为 0（不是 50）", ghost.vuln_total == 0 and ghost.safe_total == 0,
          f"{ghost.vuln_total}/{ghost.safe_total}")
    check("annotated 仍能看到「官方标了多少」", ghost.vuln_annotated == 50,
          str(ghost.vuln_annotated))
    check("汇总把无源码条数一并带出（供报告显示缺口）",
          B.BatchReport(categories=[ghost]).total([ghost])["vuln_missing"] == 50)

    print("\n=== ⑥ 汇总只算「有能力」的类别 ===")
    cov = B.Category("sqli", "sqli", vuln_total=2, safe_total=2, vuln_hit=1, safe_hit=1)
    unc = B.Category("xss", "", vuln_total=100, safe_total=0, vuln_hit=0, safe_hit=0)
    br = B.BatchReport(categories=[cov, unc])
    check("covered 只含映射了 kind 的类别", br.covered == [cov])
    check("uncovered 只含没映射的（能力外，低召回不是缺陷）", br.uncovered == [unc])
    tt = br.total(br.covered)
    check("小计分母**不含**能力外类别（否则召回被拉低成假象）",
          tt["vuln_total"] == 2 and tt["recall"] == 0.5, str(tt["recall"]))
    check("render() 里能力外类别**单列**且带说明",
          "能力外类别" in br.render(), "")

    print("\n=== ⑦ 与单点基准的编排：互不干扰 ===")
    r = R.Report()
    check("Report 默认不含批量结果（不用就零开销）", r.batches == [])
    r.batches = [br]
    check("render() 会把批量结果附在单点报告之后",
          "批量基准" in r.render())
    check("recall.evaluate 支持 include_batch 开关（日常快速回归可跳过整仓入库）",
          "include_batch" in R.evaluate.__code__.co_varnames)
    check("批量基准**不进**单点用例的统计口径",
          R.Report(batches=[br]).recall() == 0.0)

    shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
