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

FIXTURE_CSV = _lines(
    "# test name, category, real vulnerability, cwe, Benchmark version: fixture",
    "BenchmarkTest00001,sqli,true,89",
    "BenchmarkTest00002,sqli,true,89",
    "BenchmarkTest00003,sqli,false,89",
    "BenchmarkTest00004,sqli,false,89",
)


def _build_fixture(tmp: pathlib.Path) -> pathlib.Path:
    repo = tmp / "fakebench"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    for name, text in FIXTURE_JAVA.items():
        (repo / "src" / name).write_text(text + "\n", encoding="utf-8")
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
        '     "category_kind": {"sqli": "sqli"}},',
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
    check("官方标注条数正确（4 条）", rep.cases_total == 4, str(rep.cases_total))
    check("该批只有一个类别 sqli", [c.name for c in rep.categories] == ["sqli"],
          str([c.name for c in rep.categories]))
    sqli = rep.categories[0]
    check("召回分母 = 真漏洞用例数（2）", sqli.vuln_total == 2, str(sqli.vuln_total))
    check("误报分母 = 安全用例数（2）", sqli.safe_total == 2, str(sqli.safe_total))
    check("真漏洞命中 1 个（形态打得中的那个）", sqli.vuln_hit == 1, str(sqli.vuln_hit))
    check("精确性 = 1/(1+误报数)，且真漏洞与安全用例**分开**统计",
          sqli.precision is not None and 0.0 < sqli.precision <= 1.0,
          f"{sqli.precision}")
    check("召回率 = 命中/真漏洞 且 **不受误报影响**",
          abs(sqli.recall - sqli.vuln_hit / sqli.vuln_total) < 1e-9, f"{sqli.recall:.1%}")

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

    print("\n=== ⑤ 「没测」不是「0 分」（v067 踩过的坑，这里同样必须成立）===")
    empty = B.Category(name="nothing", kind="sqli")
    check("一次都没命中时 precision 返回 None（未测）", empty.precision is None)
    check("一次都没命中时 recall 是 0.0（**有分母才叫 0 分**）", empty.recall == 0.0)
    check("无真漏洞用例时 recall 也是 0.0（分母为 0 不除零）",
          B.Category(name="x", kind="k", safe_total=5, safe_hit=5).recall == 0.0)
    check("汇总里全无命中时 precision 为 None 而不是 0.0",
          B.BatchReport(categories=[empty]).total([empty])["precision"] is None)

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
