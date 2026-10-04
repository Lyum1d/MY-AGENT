# -*- coding: utf-8 -*-
"""v065 召回基准的回归测试（实施规格 §7.3 / §8 的 A2·A8）。

## 这个文件为什么重要

§8 把 **A8（有固定基准，能回答"这次改动让召回涨了还是跌了"）** 列为**硬门槛**，
理由是本项目的既有教训：**没有回归，改动就是盲改**。
用户决策④也明确要求「已知答案的回归集**建在 P3 之前**」。

所以这里不只是"跑一遍看看"，而是**卡住阈值**：
召回或精确性掉了，这个测试就红 —— 改动**不能悄悄变差**。

## 基准测什么、不测什么（别误读）

测的是「**规则能不能打中这个形态**」，**不是**「在真实项目里的召回率」——
内置样本是手工写的**形态样本**（复现 Log4Shell 的 JNDI、pickle、LFI 等已知形态），
不是那些项目的真实源码。真实仓库要走 `recall.Case(dir=...)` 那条路（机制已留好）。

    python test_065_recall_baseline.py
"""
from __future__ import annotations

import sys
import tempfile
import pathlib

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app.codebase import ingest as G                        # noqa: E402
from app.codebase import index as I                          # noqa: E402
from app.codebase import paths as P                          # noqa: E402
from app.codebase import recall as R                          # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def main() -> int:
    print("=" * 68)
    print("v065 白盒召回基准（已知答案的回归集）")
    print("=" * 68)

    print("\n=== ① 语料自身体检 ===")
    problems = R.corpus_health()
    check("语料无结构问题（id 唯一 / 引用的规则都存在 / 正负样本都有答案）",
          not problems, "；".join(problems[:3]))
    pos = [c for c in R.CORPUS if c.kind == "positive"]
    neg = [c for c in R.CORPUS if c.kind == "negative"]
    check("正样本不少于 10 个（样本太少测不出召回变化）", len(pos) >= 10, str(len(pos)))
    check("负样本不少于 5 个（**只测召回不测误报等于只测一半**）",
          len(neg) >= 5, str(len(neg)))
    langs = {c.lang for c in pos}
    check("正样本覆盖首批四种语言（决策②）",
          {"php", "java", "python", "javascript"} <= langs, str(sorted(langs)))
    kinds = {r for c in pos for r in c.expect_rules}
    check("覆盖多个漏洞类别（不是只测一种）", len(kinds) >= 6, str(len(kinds)))

    print("\n=== ② 真跑一遍（结果落临时目录，**不碰真实数据**）===")
    real_cb = P.CODEBASES_FILE
    real_idx = I.INDEX_DIR
    real_store = G.CODEBASE_STORE
    cb_existed = real_cb.exists()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="v065_recall_"))
    rep = R.evaluate(workspace=tmp)

    print()
    print(rep.render())
    print()

    check("跑完后真实 codebases 记录**没被改写/新建**",
          P.CODEBASES_FILE == real_cb and real_cb.exists() == cb_existed,
          f"{P.CODEBASES_FILE}（存在性是否变化：{real_cb.exists() != cb_existed}）")
    check("索引目录指回原路径（mock 已正确还原）", I.INDEX_DIR == real_idx, str(I.INDEX_DIR))
    check("入库落盘位置指回原路径（mock 已正确还原）",
          G.CODEBASE_STORE == real_store, str(G.CODEBASE_STORE))
    check("基准的产物都落在临时目录里（不污染工作区）",
          str(real_store) not in str(tmp) and tmp.exists())

    print("\n=== ③ 卡住阈值（这是 A8「能回答涨了还是跌了」的落点）===")
    # ⚠️ 硬阈值只看**内置语料** —— 它稳定、可复现；
    # 真实项目那批取决于本机有没有检出那份代码，不能用来做环境相关的硬卡点。
    b_recall = rep.recall_of(rep.builtin_results)
    b_prec = rep.precision_of(rep.builtin_results)
    check("内置语料召回率 = 100%（**掉了就是回归**）", b_recall == 1.0,
          f"{b_recall:.0%}；失败项：{[r.case.id for r in rep.builtin_results if not r.ok]}")
    check("内置语料精确性 = 100%（负样本不许误报）", b_prec == 1.0,
          f"{b_prec:.0%}；失败项：{[r.case.id for r in rep.builtin_results if not r.ok]}")
    check("内置语料没有未解释的失败项",
          not [r for r in rep.builtin_results if not r.ok and not r.case.known_fp],
          str([r.case.id for r in rep.builtin_results if not r.ok and not r.case.known_fp]))
    check("已知误报列表已清空（两条规则 bug 已修）",
          not rep.known_fp_triggered, str(rep.known_fp_triggered))

    print("\n=== ③-b 「没测」不等于「0 分」（这个语义我踩过一次）===")
    check("无负样本时 precision_of 返回 None 而不是 0.0",
          rep.precision_of([r for r in rep.builtin_results if r.case.kind == "positive"]) is None)
    check("有负样本时返回真实比例", isinstance(b_prec, float))

    print("\n=== ③-c 真实项目用例（配了才跑；DVWA 那批是实测基线）===")
    real = rep.real_results
    if not real:
        print("  [SKIP] 未配置 data/recall_real.json —— 真实项目用例跳过"
              "（模板见 data/recall_real.json.example）")
    else:
        r_recall = rep.recall_of(real)
        r_prec = rep.precision_of(real)
        n_pos = len([r for r in real if r.case.kind == "positive"])
        n_neg = len([r for r in real if r.case.kind == "negative"])
        print(f"  读到真实用例 {len(real)} 条（正 {n_pos} / 负 {n_neg}）")
        check("真实项目召回 = 100%（DVWA 6 个已知漏洞点全打中）",
              r_recall == 1.0,
              f"{r_recall:.0%}；失败：{[r.case.id for r in real if not r.ok]}")
        if r_prec is not None:
            check("真实项目精确性 = 100%（安全实现版 impossible.php 不误报）",
                  r_prec == 1.0,
                  f"{r_prec:.0%}；失败：{[r.case.id for r in real if not r.ok]}")
        else:
            print("  [SKIP] 真实用例未含负样本 → 精确性未测")

    print("\n=== ④ 每条正样本必须给出**可引用的位置**（不是只给个规则名）===")
    builtin_pos = [r for r in rep.builtin_results if r.case.kind == "positive"]
    bad = [r.case.id for r in builtin_pos if not r.case.expect_loc]
    check("内置正样本都带 `文件:行号` 期望答案", not bad, str(bad))
    hit_loc = [r for r in builtin_pos if any(l in r.hits for l in r.case.expect_loc)]
    check("命中的位置都在实际命中里（含具体行号）",
          len(hit_loc) == len(builtin_pos), f"{len(hit_loc)}/{len(builtin_pos)}")
    real_pos = [r for r in rep.real_results if r.case.kind == "positive"]
    if real_pos:
        check("真实项目用例也都带具体行号（不是只给文件名）",
              all(any(":" in l for l in r.case.expect_loc) for r in real_pos),
              str([r.case.id for r in real_pos if not all(":" in l for l in r.case.expect_loc)]))

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
