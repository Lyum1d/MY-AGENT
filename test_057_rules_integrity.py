# -*- coding: utf-8 -*-
"""v057 规则文件守卫：防止「复制粘贴污染」再次发生（§7.0）+ 白盒依据文件的定向回归。

## 背景（已实测）

`data/rules/researcher-blackbox-whitebox.md` 的头部被 `playwright-browser-mcp.md` 的内容
**整段覆盖**（前 43 行逐字相同），于是系统提示每轮注入的这份「黑白盒方法论」，
模型看到的第一行是「Playwright Browser MCP」。而它的**原文从未进过 git**
（该文件库里只有 1 个提交），上游包仓库也没有更早版本 → 只能重建（已在 v057 修完）。

这条守卫就是为了让同类问题**以后能自动抓到**。

## 判据里两个必须避开的坑（文档特别提醒，我实测确认过）

1. **不能按「第一行」判**：`data/kb/` 里有文件首行是 `>` 引用块，H1 排在后面；
2. **不能直接正则 `^# `**：这些文件里大量 `#` 开头的行其实是**代码块里的注释**
   （如 payload 示例的 `# 发送两次相同请求`）→ 必须**先剥掉 ``` 围栏**再解析。

    python test_057_rules_integrity.py
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def first_heading(text: str) -> str | None:
    """剥掉 ``` 围栏后取**首个 `# ` 标题**（两个坑都在这里避开）。"""
    fence = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        if stripped.startswith("# "):
            return stripped.rstrip()
    return None


def collect(folder: pathlib.Path) -> dict[str, str | None]:
    return {p.name: first_heading(p.read_text(encoding="utf-8", errors="replace"))
            for p in sorted(folder.glob("*.md"))}


# ---------------------------------------------------------------- 判据自检（先证判据本身可信）
def test_detector_selftest():
    print("\n=== 判据自检：确保护栏「会报警」且不会大面积误报 ===")
    # ① 围栏内的 # 不能被当成标题（否则会把代码注释误判成标题 —— 文档说曾误判 30 多处）
    fenced = "```bash\n# 这是代码里的注释，不是标题\ncurl -s http://x\n```\n\n# 真正的标题\n"
    check("围栏内的 `# 注释` 不被当成标题（先剥围栏）",
          first_heading(fenced) == "# 真正的标题", repr(first_heading(fenced)))
    # ② 首行是引用块时，仍能找到后面的 H1
    quoted = "> 说明性引用块\n> 第二行\n\n## 一、原有知识库\n\n# 真标题\n"
    check("首行是 `>` 时仍能找到 H1（不按第一行判）",
          first_heading(quoted) == "# 真标题", repr(first_heading(quoted)))
    # ③ 重复标题能被检出（护栏不是永不报警的摆设）
    dup = {"a.md": "# 同一个标题", "b.md": "# 同一个标题"}
    seen = {}
    for f, t in dup.items():
        seen.setdefault(t, []).append(f)
    check("构造的重复标题能被检出（护栏会报警）",
          any(len(v) > 1 for v in seen.values() if list(seen)[0]))
    # ④ 四级标题不算 H1
    check("`#### x` 不被当成 H1", first_heading("#### 小标题\n\n# 真 H1\n") == "# 真 H1")


# ---------------------------------------------------------------- 主检查：标题唯一性
def test_heading_uniqueness():
    print("\n=== data/rules 与 data/kb：首个标题必须存在且同目录内唯一 ===")
    for name in ("rules", "kb"):
        d = ROOT / "data" / name
        titles = collect(d)
        missing = [f for f, t in titles.items() if not t]
        check(f"{name}/ 每个文件都有 H1 标题（{len(titles)} 个）",
              not missing, f"缺标题：{missing}" if missing else "")
        seen: dict[str, list[str]] = {}
        for f, t in titles.items():
            if t:
                seen.setdefault(t, []).append(f)
        dups = {t: v for t, v in seen.items() if len(v) > 1}
        check(f"{name}/ 无重复标题（复制粘贴污染的典型症状）",
              not dups, f"重复：{dups}" if dups else "")


# ---------------------------------------------------------------- 定向回归：白盒依据文件
def test_whitebox_rule_fixed():
    print("\n=== 定向回归：researcher-blackbox-whitebox.md（v057 修复对象）===")
    f = ROOT / "data/rules/researcher-blackbox-whitebox.md"
    txt = f.read_text(encoding="utf-8", errors="replace")
    h1 = first_heading(txt)
    check("首个标题不再是 Playwright",
          h1 is not None and "Playwright" not in h1, repr(h1))
    check("首个标题描述的是黑白盒研究方法论",
          h1 is not None and ("黑白盒" in h1 or "白盒" in h1), repr(h1))
    check("Playwright 的内容已从本文件移除",
          "Playwright Browser MCP" not in txt)
    check("Playwright 内容仍完整存在于它自己的文件里",
          "Playwright Browser MCP" in
          (ROOT / "data/rules/playwright-browser-mcp.md").read_text(encoding="utf-8"))
    # 方法论骨架必须完整（§10 引用「Phase0～6」，缺任何一 Phase 都是断链）
    for i in range(7):
        check(f"Phase {i} 存在（§10 引用了 Phase0～6）", f"Phase {i}" in txt)
    for i in range(3, 11):
        check(f"§{i} 存在", f"## {i}." in txt)
    # 重建内容必须被标注（不能让人把推断当原文）
    check("有「重建记录」章节", "重建记录" in txt)
    check("重建处有 ⚠️ 标注（>= 6 处）", txt.count("⚠️") >= 6, str(txt.count("⚠️")))
    check("明确写了「原文不可恢复」的原因",
          "只有 1 个提交" in txt or "不可恢复" in txt)


def main() -> int:
    print("=" * 68)
    print("v057 规则文件守卫 + 白盒依据文件定向回归")
    print("=" * 68)
    test_detector_selftest()
    test_heading_uniqueness()
    test_whitebox_rule_fixed()
    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
