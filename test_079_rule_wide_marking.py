# -*- coding: utf-8 -*-
"""v079 宽口径规则的**标注约定**。

## 这个文件防的是什么

自审一个真实仓库（206 条命中逐条分诊）得到一个结论：**噪声集中在两条规则上** ——

    js.xss.innerhtml  92 处（占 45%）—— 逐条读后**全部是假阳性**（插值都过了 `esc()`/`md()`）
    py.path.open      59 处（占 29%）—— 绝大多数是固定路径或内部计算的路径

这两条**不是写错了**，而是**有意宽**：`.innerHTML =` 和 `open(` 在任何项目里都太普遍，
但「DOM XSS 的注入点」「路径穿越点」又**没有它们就全漏**。
所以项目早就立了一条约定（v066 用在 `php.xss.echo_var` 上）：

    why/hint 里写明「⚠️ 这是**宽口径**规则（+ 实测数字）」，
    并要求「命中当**低置信候选**看待，必须先追来源再下结论」。

问题是：**这条约定只在 1 条规则上落实过**（`php.xss.echo_var`），
另外两条同样宽的却没标 —— 于是一个本来可以用一句话消化的分诊成本，
被浪费在每个命中都要重新推理一遍。

## 本文件锁住三件事

  ① 三条宽口径规则**都带标注**，且措辞符合既有约定（含「宽口径」「低置信」）；
  ② ⭐ **宽口径是设计意图，不能被静默收紧** —— 断言它们对**最朴素的写法**仍然命中
     （未来谁要收紧，必须改这条测试，也就是必须**显式地**承认自己在改契约）；
  ③ ⭐ **标注是纯注解** —— 改 `why`/`hint` 不改变命中集合（端到端跑一遍确认）。

    python test_079_rule_wide_marking.py
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from app.codebase import ingest as IG        # noqa: E402
from app.codebase import index as IX         # noqa: E402
from app.codebase import paths as P          # noqa: E402
from app.codebase import search as SE        # noqa: E402
from app.codebase import sink_rules as SR    # noqa: E402

ok: list[str] = []
fail: list[str] = []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


#: 三条**有意宽口径**的规则
WIDE = ["php.xss.echo_var", "js.xss.innerhtml", "py.path.open"]

#: 「最朴素的写法」—— 这些必须**继续命中**，否则就是把契约偷偷收紧了
PLAIN = {
    "php.xss.echo_var": ('<?php\n$x = $_GET["a"];\necho $x;\n', "a.php"),
    "js.xss.innerhtml": ("el.innerHTML = data;\n", "b.js"),
    "py.path.open": ("data = open(p).read()\n", "c.py"),
}


def main() -> int:
    print("=" * 70)
    print("v079 宽口径规则的标注约定")

    rules = {r.id: r for r in SR.ALL}

    # ---------------------------------------------------------------- ① 标注到位
    print("\n=== ① 三条宽口径规则都带标注，且措辞一致 ===")
    for rid in WIDE:
        r = rules.get(rid)
        check(f"{rid} 存在", r is not None)
        if r is None:
            continue
        blob = (r.why or "") + (r.hint or "")
        check(f"{rid} 标了「宽口径」", "宽口径" in blob)
        check(f"{rid} 要求按「低置信候选」看待", "低置信" in blob)
        check(f"{rid} 说明了它为什么仍要保留（「没有它就全漏」这类）",
              "全漏" in blob or "保留" in blob, blob[-40:].replace("\n", " "))

    print("\n=== ①b 标注里不许掺进 pattern（否则就是改行为不是改注解） ===")
    for rid in WIDE:
        r = rules.get(rid)
        if r is None:
            continue
        pat = r.pattern + (r.call_pattern or "") + (r.runner_pattern or "")
        check(f"{rid} 的 pattern 不含「宽口径」字样", "宽口径" not in pat)
        check(f"{rid} 的 pattern 不含「低置信」字样", "低置信" not in pat)

    # ---------------------------------------------------------------- ② 宽口径是契约
    print("\n=== ② ⭐ 宽口径是**设计意图** —— 最朴素的写法必须继续命中 ===")
    import re as _re
    for rid, (src, _fn) in PLAIN.items():
        r = rules.get(rid)
        if r is None:
            continue
        hit = any(_re.search(r.pattern, ln) for ln in src.splitlines())
        check(f"{rid} 对最朴素写法仍命中（收紧它必须显式改本测试）", hit,
              repr(src.splitlines()[-1] if src.splitlines() else ""))

    # ---------------------------------------------------------------- ③ 纯注解
    print("\n=== ③ ⭐ 标注是纯注解：端到端跑一遍，命中集合不变 ===")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="v079_wide_"))
    cid = "v079-wide-e2e"
    try:
        for rid, (src, fn) in PLAIN.items():
            (tmp / fn).write_text(src, encoding="utf-8")
        IG.ingest(tmp, codebase_id=cid, register_only=True)
        IX.build(cid)
        hits = SE.search_sinks(cid, limit=500)
        got = {h.rule_id for h in hits}
        for rid in WIDE:
            check(f"端到端：{rid} 仍出现在命中里", rid in got, str(sorted(got)))
        check("每条命中都带 `why`（标注是随命中一起给模型看的）",
              all(h.why for h in hits))
        for h in hits:
            if h.rule_id in WIDE:
                # 注：既有约定把标注放在 `hint`（「还要确认什么、防误报」）而非 `why`，
                # 本测试按并集判 —— 与 `php.xss.echo_var` 的写法保持一致即可。
                check(f"{h.rule_id} 的命中里带「宽口径」提示（why + hint）",
                      "宽口径" in (h.why or "") + (h.hint or ""))
                break
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        P.save_codebases([c for c in P.load_codebases() if c.codebase_id != cid])
        try:
            IX.index_path(cid).unlink()
        except OSError:
            pass

    # ---------------------------------------------------------------- ④ 自命中守卫
    print("\n=== ④ ⭐ 规则库**不该被自己命中**（自命中 = 结构性噪声） ===")
    # 规则文件本身就是 `.py`，而 `py.*` 规则只作用于 Python 文件 ——
    # 所以规则文件里**写出带半角括号的调用字面量**（如 `.exec（` 若写成半角）
    # 会被自己命中。v079 实测：清掉 8 处（base.py 2 / java.py 5 / python.py 1）。
    # 做法是**用全角括号**引用调用 —— 中文里本来就该用全角：
    #     `\s*\(` 只认半角，全角 `（` 绕开。
    import re as _re2
    rules_dir = pathlib.Path(__file__).resolve().parent / "app" / "codebase" / "sink_rules"
    self_hits = []
    for fp in sorted(rules_dir.glob("*.py")):
        for i, line in enumerate(fp.read_text(encoding="utf-8").splitlines(), 1):
            for r in SR.ALL:
                if r.lang != "python":        # 文件是 .py → 只有 python 规则会作用于它
                    continue
                if _re2.search(r.pattern, line):
                    self_hits.append(f"{fp.name}:{i} [{r.id}] {line.strip()[:60]}")
                    break
    check("规则库自命中 = 0（新写的说明文字不要带半角括号的调用字面量）",
          self_hits == [], str(self_hits[:4]))

    print("\n" + "=" * 70)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 70)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
