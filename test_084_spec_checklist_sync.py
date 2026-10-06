# -*- coding: utf-8 -*-
"""v084：规格勾选框**绑代码事实**的双向守卫（`白盒审计_实施规格.md` §7）。

## 这个文件防的是什么

`白盒审计_实施规格.md` 的 §7 任务清单**漂移过两次**：

  · §7.1 —— 2026-10-04 补过一次（文件里那段「此前勾选框长期未更新，属文档漂移」的批注就是它）；
  · §7.0 / §7.2 / §7.3 —— **当时被漏下**，直到 2026-10-06 写状态报告时才被发现。

根因不是「忘了勾」这么简单：**勾选状态只靠人记得改**，而项目里已经有一条同类守卫
（`test_068` 卡「KB 文档不漂移」）—— 规格的清单当时没被同样对待。

## 判据：**双向**断言（只测一侧等于没测）

| 方向 | 断言 | 防的是 |
|---|---|---|
| 正 | **代码事实在 → 勾选必须是 `[x]`** | 做完了却忘了勾（本次漂移） |
| 反 | **勾选是 `[x]` → 代码事实必须在** | 勾了但其实没做（更坏：**假信心**） |

⚠️ 双向是刻意的：只断言「勾了就有」的话，**把所有勾都抹掉也能过**；
只断言「有就该勾」的话，**把所有勾都打上也能过**（这正是漂移的方向）。

## ⚠️ 前置：**本规格是「本机规划材料」，不在版本控制里**（`.gitignore:81`）

所以**干净 clone 上不存在这个文件** —— 本测试在那种情况下**优雅跳过**（报 `跳过 1`），
不报失败。这是刻意的：把「本机规划文档」做成硬依赖，会让别人的回归永远红。

⭐ 但反过来说，**这正是漂移发生的原因**：文档不在 git 里 ⇒
`git status` 看不见它、也没有提交历史提醒 ⇒ 没人会在改代码时想起同步勾选框。
**本测试就是补上这个提醒**（只在有规格的机器上生效）。

## ⚠️ 本测试为什么按「唯一子串」定位规格条目

不是按行号、也不是按顺序 —— 所以规格可以自由排版/加批注。
但**改了条目的措辞就必须同步改本测试**，这是**刻意**的：
让「改契约」变成**显式动作**（与 `test_079` 用同一种做法）。
所以本测试里每个条目都有一个「规格里的唯一子串」，找不到就**直接失败**并提示同步。

    python test_084_spec_checklist_sync.py
"""
from __future__ import annotations

import io
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
SPEC = HERE / "白盒审计_实施规格.md"

ok: list[str] = []
fail: list[str] = []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def read(p: pathlib.Path) -> str:
    return io.open(p, encoding="utf-8", errors="replace").read()


# --------------------------------------------------------------------------- 事实探测
def fact_file(rel: str) -> bool:
    return (HERE / rel).exists()


def fact_contains(rel: str, needle: str) -> bool:
    p = HERE / rel
    return p.exists() and needle in read(p)


def fact_in_run_all(rel: str) -> bool:
    p = HERE / "run_all_tests.py"
    return p.exists() and rel in read(p)


def fact_kb_registered(stem: str) -> bool:
    p = HERE / "data" / "kb" / "README.md"
    return p.exists() and stem in read(p)


#: (规格里的唯一子串, 规格条目标题, 期望勾选, 事实探测函数, 「不适用」说明)
#:
#: 期望勾选 = True 表示这一项**该是 [x]**；事实探测必须同样为 True 才算一致。
ITEMS = [
    # ---- §7.0 ----
    ("修 `data/rules/researcher-blackbox-whitebox.md`", "§7.0 修 rules 文件", True,
     lambda: fact_file("data/rules/researcher-blackbox-whitebox.md")
     and read(HERE / "data/rules/researcher-blackbox-whitebox.md").splitlines()[0].startswith("# 黑白盒"),
     ""),
    ("加守卫测试：`data/rules/*.md`", "§7.0 规则文件标题守卫测试", True,
     lambda: fact_file("test_057_rules_integrity.py") and fact_in_run_all("test_057_rules_integrity.py"),
     ""),
    # ---- §7.1 ----
    ("`ingest.py`：接收入库", "§7.1 ingest.py", True,
     lambda: fact_file("app/codebase/ingest.py"), ""),
    ("`index.py`：符号表", "§7.1 index.py", True,
     lambda: fact_file("app/codebase/index.py"), ""),
    ("`search.py`：正则 + AST", "§7.1 search.py", True,
     lambda: fact_file("app/codebase/search.py"), ""),
    ("`sink_rules/`：按语言/框架的危险 sink", "§7.1 sink_rules/", True,
     lambda: fact_file("app/codebase/sink_rules/__init__.py"), ""),
    ("`sbom.py`：依赖清单解析", "§7.1 sbom.py", True,
     lambda: fact_file("app/codebase/sbom.py"), ""),
    ("`variants.py`：变体分析", "§7.1 variants.py", True,
     lambda: fact_file("app/codebase/variants.py"), ""),
    ("`paths.py`：受控根校验", "§7.1 paths.py", True,
     lambda: fact_file("app/codebase/paths.py"), ""),
    # ---- §7.2 ----
    ("`app/registry.py::_add_builtin_tools()`", "§7.2 registry 追加 code_*", True,
     lambda: fact_contains("app/registry.py", "code_list"), ""),
    ("路径 A 挂 `BUILTIN_STEP_TOOLS`", "§7.2 agent 挂 BUILTIN_STEP_TOOLS", True,
     lambda: fact_contains("app/agent.py", "BUILTIN_STEP_TOOLS"), ""),
    ("新增 `NO_EVIDENCE` / `UNREACHABLE` 归因", "§7.2 NO_EVIDENCE/UNREACHABLE 归因（有偏离，见规格）", True,
     lambda: fact_contains("app/agent.py", "NO_EVIDENCE")
     and fact_contains("app/codebase/evidence.py", "NO_EVIDENCE")
     and fact_contains("app/codebase/evidence.py", "UNREACHABLE"),
     "偏离：两者落在 evidence.py（触发点不是工具失败），agent.py 只留 NO_EVIDENCE 计数"),
    ("的系统提示片段：加入白盒纪律", "§7.2 白盒系统提示片段", True,
     lambda: fact_contains("app/agent.py", "code_search") or fact_contains("app/agent.py", "codebase"), ""),
    ("若需 codebase 表则新增迁移", "§7.2 store codebase 表（**不适用**）", True,
     lambda: not fact_contains("app/store.py", "codebase"),  # 事实＝「确实没有这张表」
     "codebase 走 data/codebases.json 文件，未引入 DB 表 → 按不适用结案"),
    ("`data/kb/code-audit-*.md`：新增白盒 KB 篇目", "§7.2 白盒 KB 篇目（实际命名 whitebox-*）", True,
     lambda: fact_file("data/kb/whitebox-audit-method.md")
     and fact_kb_registered("whitebox-audit-method"), ""),
    # ---- §7.3 ----
    ("用**已知有 CVE 的历史版本**做召回测试", "§7.3 已知 CVE 版本召回测试", True,
     lambda: fact_file("test_065_recall_baseline.py"), ""),
    ("反幻觉测试：喂入一段**不存在漏洞**的代码", "§7.3 反幻觉测试", True,
     lambda: fact_file("test_064_codebase_evidence.py"), ""),
    ("受控根测试：断言路径穿越被拒", "§7.3 受控根测试", True,
     lambda: fact_file("test_058_codebase_paths.py"), ""),
    ("回归基准：固定一组代码 + 已知答案", "§7.3 回归基准", True,
     lambda: fact_file("test_070_batch_benchmark.py"), ""),
]


def parse_checkboxes(text: str) -> dict[str, bool]:
    """{条目原文摘要: 是否已勾选}。"""
    out = {}
    for ln in text.splitlines():
        m = re.match(r"\s*-\s+\[([ xX])\]\s+(.*)$", ln)
        if m:
            out[m.group(2).strip()] = m.group(1).lower() == "x"
    return out


def main() -> int:
    print("=" * 84)
    print("v084 规格勾选框 ↔ 代码事实 双向守卫")
    print("=" * 84)

    if not SPEC.exists():
        # 规格是「本机规划材料」，.gitignore:81 有意排除 → 干净 clone 上没有它。
        # 此时**跳过**（不是失败）：把本机规划文档做成硬依赖，会让别人的回归永远红。
        print("  [跳过] `白盒审计_实施规格.md` 不存在 ——")
        print("         该文件是本机规划材料（.gitignore:81 有意排除），干净 clone 上不会有。")
        print("         本守卫只在**有规格的机器**上生效；漂移的根因也正是它不在 git 里。")
        print("=" * 84)
        print("结果：0 通过 / 0 失败 / 1 跳过")
        print("=" * 84)
        return 0

    check("规格文件存在", True, str(SPEC))
    text = read(SPEC)
    boxes = parse_checkboxes(text)
    check("规格里有勾选条目", len(boxes) > 0, f"{len(boxes)} 条")

    print("\n=== 逐条：规格勾选 ⟺ 代码事实 ===")
    for key, title, want_checked, probe, na in ITEMS:
        # 1) 先在规格里找这个条目（唯一子串）
        hit = [t for t in boxes if key in t]
        if not hit:
            check(f"{title} —— 规格条目可定位", False,
                  f"未找到含 `{key}` 的勾选条目（改过措辞？请同步本测试）")
            continue
        if len(hit) > 1:
            check(f"{title} —— 规格条目唯一", False, f"匹配到 {len(hit)} 条，子串不够唯一")
            continue
        checked = boxes[hit[0]]
        # 2) 探测事实
        try:
            fact = bool(probe())
        except Exception as e:
            check(f"{title} —— 事实探测可执行", False, repr(e)[:60])
            continue
        # 3) 双向断言
        same = (checked == fact)
        check(f"{title} —— 勾选({checked}) ⟺ 事实({fact})", same,
              na if na else ("" if same else "⚠️ 文档与事实不一致：先改事实，或显式同步文档+本测试"))
        # 4) 期望值也得对上（防止「事实和文档一起错」）
        check(f"{title} —— 与期望一致（want={want_checked}）", checked == want_checked,
              "" if checked == want_checked else "⚠️ 与设计预期不符，需人工确认")

    print("\n=== ⭐ 反向自检：**用合成用例**验证判据本身是双向的 ===")
    # ⚠️ 不要用「把文档里所有勾抹掉再跑一遍」来自检 —— 那是错的：
    #    当所有事实都为 True 时，「全打勾」本来就该判**一致**，它测不出反向断言。
    #    要测「判据是否双向」，只能喂**构造的 (勾选, 事实) 组合**。
    cases = [
        (True, True, True, "勾了·事实在 → 一致"),
        (True, False, False, "勾了·事实不在 → 必须判不一致（防假信心）"),
        (False, True, False, "没勾·事实在 → 必须判不一致（**本次漂移就是这个方向**）"),
        (False, False, True, "没勾·事实不在 → 一致"),
    ]
    for checked, fact, want_consistent, desc in cases:
        got = (checked == fact)
        check(f"判据自检：{desc}", got == want_consistent, f"consistent={got}")

    print("\n=== 反向自检之二：**事实缺失时**文档的 `[x]` 必须被判不一致 ===")
    # 用一个必然不成立的事实，确认「勾了·事实不在」这条在真实数据上也会触发
    fake_fact = fact_contains("__definitely_missing__.py", "anything")
    check("构造的假事实确实为 False", fake_fact is False)
    check("勾选 True 配假事实 → 判不一致", (True == fake_fact) is False)

    print("\n" + "=" * 84)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败 / 0 跳过")
    if fail:
        print("失败项：" + "、".join(fail[:6]))
    print("=" * 84)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
