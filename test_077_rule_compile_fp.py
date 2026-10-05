# -*- coding: utf-8 -*-
"""v077 修 `py.rce.eval` 把 `re.compile(` 当 RCE 的误报。

## 这个文件防的是什么

`py.rce.eval` 的原 pattern 是 `\\b(?:eval|exec|compile|__import__)\\s*\\(`，
它想抓的是 Python **内建** `compile(source, filename, mode)`（可控输入 → 编译执行），
但 `compile` 这个分支**同时撞上了无处不在的 `re.compile(pattern)`** —— 那是正则编译，
与「把字符串当代码执行」毫无关系。

v076 自审 src-agent 时实测到后果：

    这条规则命中 151 处，其中 85 处（56%）是
        re.compile(r"...") / ("class", re.compile(...)) / re.compile(_user, re.I)

**零 RCE。** 而且这条规则通常还是命中数第一名 —— 噪声会盖住真信号。

修法：`compile` 分支加 lookbehind 排除**方法调用**形态。

    \\b(?:eval|exec|__import__)\\s*\\(|(?<![.\\w])compile\\s*\\(

这个文件锁住四件事：

  ① `re.compile(` / `x.compile(` **不再**命中 `py.rce.eval`（也不能命中任何别的规则）；
  ② 裸 `compile(src, "f", "exec")`（内建）**仍然**命中 —— 别把该抓的一起修掉了；
  ③ `eval` / `exec` / `__import__` 三个分支**完全不受影响**；
  ④ 边界：`re.compile` 之外，`foo.compile(`、`self.compile(`、`.compile (` 也都不算。

    python test_077_rule_compile_fp.py
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from app.codebase import sink_rules as SR        # noqa: E402

ok: list[str] = []
fail: list[str] = []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


RULE = next(r for r in SR.ALL if r.id == "py.rce.eval")


def hits_all_rules(line: str, lang: str = "python") -> list[str]:
    """这一行会被**哪些**规则命中（不只 py.rce.eval —— 误报可能来自别的规则）。"""
    import re as _re
    out = []
    for r in SR.ALL:
        if r.lang not in (lang, "*"):
            continue
        try:
            if _re.search(r.pattern, line):
                out.append(r.id)
        except _re.error:
            pass
    return out


def main() -> int:
    print("=" * 68)
    print("v077 py.rce.eval：`re.compile(` 误报")

    # ---------------------------------------------------------------- ① 不该命中
    print("\n=== ① `re.compile(` 及同类方法调用**不该**命中 ===")
    NOT_HIT = [
        ('re.compile(r"(\\d+)")', "re.compile 常见形态"),
        ('"java": re.compile(r"^\\s*import\\s+(?:static\\s+)?([\\w.]+)"),', "字典值里的 re.compile"),
        ('("class", re.compile(r"\\bclass\\s+(\\w+)")),', "元组里的 re.compile"),
        ('_user_rx = re.compile(_user, re.I)', "带 flags 的 re.compile"),
        ('return re.compile(pattern).search(text)', "链式调用"),
        ('self._rx = re.compile(self.pattern)', "self 上的 re"),
        ('rx = regex.compile(p)', "别名模块的 .compile"),
        ('m = re.compile(p)',
         "通用形态"),
    ]
    for line, desc in NOT_HIT:
        got = hits_all_rules(line)
        check(f"{desc} → 不命中任何规则", got == [], f"{line[:52]} → {got}")

    # ---------------------------------------------------------------- ② 该命中
    print("\n=== ② 内建 `compile(` 仍然命中（别把该抓的一起修掉） ===")
    SHOULD_HIT = [
        ('code = compile(source, "srcagent.py", "exec")', "内建 compile 三参"),
        ('exec(compile(tpl, "<t>", "exec"), ns)', "exec(compile(...)) 组合"),
        ('src = compile(user_input, "x", "single")', "内建 compile（输入可疑）"),
    ]
    for line, desc in SHOULD_HIT:
        got = hits_all_rules(line)
        check(f"{desc} → 命中 py.rce.eval", "py.rce.eval" in got, f"{line[:52]} → {got}")

    # ---------------------------------------------------------------- ③ 三分支不受影响
    print("\n=== ③ `eval` / `exec` / `__import__` 三分支不受影响 ===")
    for line, desc in [
        ('return eval(tpl)', "eval"),
        ('exec(cmd)', "exec"),
        ('mod = __import__("os")', "__import__"),
        ('x = __import__("a" + "b")', "拼接模块名（真该警惕）"),
    ]:
        got = hits_all_rules(line)
        check(f"{desc} → 仍命中 py.rce.eval", "py.rce.eval" in got, f"{line[:52]} → {got}")

    # ---------------------------------------------------------------- ④ 边界
    print("\n=== ④ 边界 ===")
    for line in ['rx = re.compile (p)', 'a = foo.compile(x)', 'b = self.compile(x)',
                 'c = mod.compile(x)']:
        got = hits_all_rules(line)
        check(f"`{line[:34]}` → 不命中", got == [], f"{got}")

    # 反例：裸 compile 前若紧贴一个标识符字符，不应被误判成方法调用而漏掉
    check("`compile(` 前面是行首/空格/括号时仍算内建",
          all("py.rce.eval" in hits_all_rules(s) for s in
              ["compile(a,b,c)", "  compile(a,b,c)", "x = compile(a,b,c)",
               "return(compile(a,b,c))"]))

    # ---------------------------------------------------------------- ⑤ 规则库自洽
    print("\n=== ⑤ 规则库自洽（别把误报转给了别的规则） ===")
    pats = [r.pattern for r in SR.ALL]
    check("没有 pattern 完全相同的规则", len(pats) == len(set(pats)))
    check("`re.compile` 在整个规则库里都不命中",
          all(hits_all_rules('re.compile(r"x")') == [] for _ in [0]))
    check("py.rce.eval 规则仍然存在且 kind=rce",
          RULE.lang == "python" and RULE.kind == "rce",
          f"{RULE.lang}/{RULE.kind}")

    # ---------------------------------------------------------------- ⑥ 真实语料冒烟
    print("\n=== ⑥ 真实语料冒烟：仓库源码里「方法调用形态」的 compile 必须一处都不命中 ===")
    repo = pathlib.Path(__file__).resolve().parent
    import re as _re
    n_py = n_method = n_method_hit = n_builtin = n_builtin_hit = 0
    samples: list[str] = []
    for fp in sorted(repo.rglob("*.py")):
        if any(x in fp.parts for x in (".venv", "venv", "__pycache__", ".git")):
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        n_py += 1
        # (a) 方法调用形态：`X.compile(` —— 这是本版要修掉的误报
        for m in _re.finditer(r"[\w.]+\s*\.\s*compile\s*\(", text):
            n_method += 1
            if _re.search(RULE.pattern, m.group(0)):
                n_method_hit += 1
                samples.append(f"{fp.name}:…{m.group(0)[-24:]}")
        # (b) 内建形态：前面既不是 `.` 也不是标识符字符 —— 这些该照常命中
        for m in _re.finditer(r"(?<![.\w])compile\s*\(", text):
            n_builtin += 1
            if _re.search(RULE.pattern, m.group(0)):
                n_builtin_hit += 1
    check(f"扫了 {n_py} 个 .py 文件", n_py > 50, f"{n_py}")
    check(f"语料里确有方法调用形态 `X.compile(`（{n_method} 处，说明冒烟有效）",
          n_method > 0, f"{n_method}")
    check("⭐ 其中被 py.rce.eval 命中的 = **0**（这就是本版修掉的误报）",
          n_method_hit == 0, f"仍有 {n_method_hit} 处：{samples[:3]}")
    check(f"语料里的内建 `compile(`（{n_builtin} 处）仍然全部命中（没修过头）",
          n_builtin > 0 and n_builtin_hit == n_builtin,
          f"{n_builtin_hit}/{n_builtin}")

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
