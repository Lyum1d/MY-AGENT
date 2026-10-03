# -*- coding: utf-8 -*-
"""v064 白盒证据闸门（`app/codebase/evidence.py` + agent 接线）的回归测试。

## 这个文件在测什么

§1.4 说白盒头号陷阱是「误报被当成发现」，而三种失败模式里**最危险的是纯编造**
（模型直接说出不存在的函数、行号或不存在的漏洞）。挡它的不是「提醒别编」，而是**校验**：

> 引用的代码位置必须能在**白盒工具的历史输出**里被检回；检不回 → 只能记候选 + 回喂要求补证据。

本文件同时覆盖一个**容易静默失效的接线点**：`attribute_source_step()` 原先排除**整个**
`BUILTIN_STEP_TOOLS`，而 v063 把 `code_*` 加进了那个集合 —— 若不拆集合，
**白盒事实要么没有溯源、要么被挂到无关的网络步骤上**（因果图会连错边）。

    python test_064_codebase_evidence.py
"""
from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from unittest import mock

REPO = __import__("pathlib").Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app import agent                                        # noqa: E402
from app.codebase import evidence as E                       # noqa: E402
from app.codebase import tools as T                          # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def step(alias: str, output: str):
    return SimpleNamespace(tool_alias=alias, output=output, id=f"st-{alias}")


def main() -> int:
    print("=" * 68)
    print("v064 白盒证据闸门（NO_EVIDENCE 主闸门 + UNREACHABLE 标记 + 接线）")
    print("=" * 68)

    print("\n=== ① 引用抽取 ===")
    cites = E.extract_citations("在 a.php:3 处调用了 system，另外 src/b.py:42 也危险")
    check("抽出 `文件:行号`", ("a.php", 3) in cites and ("src/b.py", 42) in cites, str(cites))
    check("去重（同一位置只留一次）",
          len(E.extract_citations("a.php:3 与 a.php:3")) == 1)
    check("没有引用时返回空", E.extract_citations("这是一句没有位置的结论") == [])
    check("不会把普通小数当引用", E.extract_citations("覆盖率 3.5 倍") == [],
          str(E.extract_citations("覆盖率 3.5 倍")))

    print("\n=== ② 主闸门：检不回 → NO_EVIDENCE ===")
    # 情形 A：引用了位置，但本轮**根本没跑过白盒工具**
    v = E.verify("a.php:3 有 RCE", [step("httpreplay", "HTTP/1.1 200 OK")])
    check("没有白盒工具输出 → no_evidence", v.status == "no_evidence", v.reason)
    check("回喂里写明「没有工具输出背书」", "没有工具输出背书" in v.feedback)
    # 情形 B：跑了白盒工具，但引用的是**别的位置**（典型编造）
    steps = [step("code_search", "a.php:7  [rce] system($u);")]
    v = E.verify("b.php:99 有命令执行", steps)
    check("引用在工具输出里检不回 → no_evidence", v.status == "no_evidence", v.reason)
    check("未背书的引用被列出来", ("b.php", 99) in v.unbacked, str(v.unbacked))

    print("\n=== ③ 检得回 → **仍然是候选**（代码存在 ≠ 可达）===")
    v = E.verify("a.php:3 处 system($u) 有 RCE 风险", steps=[step("code_search", "a.php:3  [rce] system($u);")])
    check("检得回时状态是 candidate 而**不是 verified**（§4.3 的表）",
          v.status == "candidate", f"{v.status} / {v.reason}")
    check("理由里说明了为什么不能升已证", "可达" in v.reason or "候选" in v.reason, v.reason)
    check("检得回时不给「要补证据」的回喂", v.feedback == "")
    # code_read 的编号输出形态：`   42 | 代码`
    v2 = E.verify("src/a.py:42 这里有注入",
                  [step("code_read", "【src/a.py:42】第 40~44 行\n  42 | cursor.execute(sql)")])
    check("也认 code_read 的「路径 + 编号行」形态", v2.status == "candidate", v2.status)

    print("\n=== ④ 只认**白盒工具**的输出（别的内置输出不算证据）===")
    texts = E.backing_texts([
        step("code_search", "a.php:3 system($u);"),
        step("kb_read", "示例：a.php:3 里有 system($u)"),
        step("note_fact", "a.php:3 有 RCE"),
    ])
    check("只有 code_* 的输出进证据池", len(texts) == 1, str(len(texts)))
    v = E.verify("a.php:3 有 RCE", [step("kb_read", "示例：a.php:3 里有 system($u)")])
    check("知识库正文**不能**给白盒事实背书（它是示例文本）",
          v.status == "no_evidence", v.status)

    print("\n=== ⑤ 不涉及代码引用时**不改变原行为** ===")
    v = E.verify("目标开放 8080 端口", [])
    check("无引用 → status 为空串（调用方保持原判定）", v.status == "", repr(v.status))
    check("无引用时不给回喂", v.feedback == "")

    print("\n=== ⑥ UNREACHABLE 标记 ===")
    s = E.format_unreachable("a.php:3", "上游有白名单校验，输入不可控")
    check("标记可判定", E.is_unreachable(s))
    check("能取回位置", E.unreachable_loc(s) == "a.php:3", E.unreachable_loc(s))
    check("无理由也能用", E.unreachable_loc(E.format_unreachable("b.php:9")) == "b.php:9")
    check("普通事实不会被误判为不可达", not E.is_unreachable("a.php:3 有 RCE"))

    print("\n=== ⑦ 接线：两个内置集合必须分开（否则白盒事实挂错溯源）===")
    check("BUILTIN_STEP_TOOLS 含 code_*（走旁路）",
          all(a in agent.BUILTIN_STEP_TOOLS for a in T.ALIASES))
    check("NON_EVIDENCE_BUILTIN_TOOLS **不含** code_*（否则输出被当「知识库正文」排除）",
          not any(a.startswith("code_") for a in agent.NON_EVIDENCE_BUILTIN_TOOLS),
          str(sorted(agent.NON_EVIDENCE_BUILTIN_TOOLS)))
    check("NON_EVIDENCE_BUILTIN_TOOLS 仍含 kb_read / note_fact（它们确实不能当证据）",
          {"kb_read", "kb_search", "note_fact"} <= agent.NON_EVIDENCE_BUILTIN_TOOLS)
    check("两者都是从同一处派生（不重复列举）",
          agent.NON_EVIDENCE_BUILTIN_TOOLS ==
          agent.BUILTIN_STEP_TOOLS - frozenset(T.ALIASES))

    print("\n=== ⑧ 接线：code_* 的输出能做事实溯源 ===")
    session = agent.SessionManager().create(project="p1")
    session.steps.append(step("code_search", "a.php:3  [rce] system($u); 输入来自 $_GET"))
    sid = agent.attribute_source_step(session, "a.php:3 处 system 的输入来自 $_GET")
    check("引用内容能在 code_* 步骤里回查到溯源",
          sid == "st-code_search", sid)
    session2 = agent.SessionManager().create(project="p1")
    session2.steps.append(step("kb_read", "a.php:3 system($u) 是示例"))
    sid2 = agent.attribute_source_step(session2, "a.php:3 system($u)")
    check("知识库步骤仍然不被当溯源（保持原纪律）", sid2 != "st-kb_read", sid2)

    print("\n=== ⑨ 接线：note_fact 端到端（mock 掉落库）===")
    captured = {}

    def fake_add(project, content, source="manual", session_id="", step_id="", status=""):
        captured.update(project=project, content=content, step_id=step_id, status=status)
        return {"id": "f1"}

    async def run_note(content, steps_):
        sess = agent.SessionManager().create(project="p1")
        sess.steps.extend(steps_)
        with mock.patch.object(agent.store, "add_fact", side_effect=fake_add), \
             mock.patch.object(agent.graph, "on_fact_added", lambda *a, **k: None):
            return await agent.Agent._note_fact(None, sess, {"id": "tc1"}, "", content)

    # ⑨-1 引用检不回 → 候选 + 回喂
    note = asyncio.run(run_note("z.php:77 有反序列化漏洞",
                                [step("code_search", "a.php:3 system($u);")]))
    check("检不回时落库 status=candidate", captured.get("status") == "candidate", captured.get("status"))
    check("回执里写明是**候选**", "候选" in note, note.splitlines()[0][:50])
    check("回执里带上「没有工具输出背书」的提醒", "没有工具输出背书" in note)
    check("NO_EVIDENCE 计数 +1", agent._NO_EVIDENCE_COUNT[0] >= 1,
          str(agent._NO_EVIDENCE_COUNT[0]))

    # ⑨-2 检得回 → **仍是候选**（不能因为「有输出」就升已证）
    captured.clear()
    note = asyncio.run(run_note("a.php:3 处 system 危险",
                                [step("code_search", "a.php:3 [rce] system($u);")]))
    check("检得回时落库**仍是** candidate（代码存在≠可达）",
          captured.get("status") == "candidate", captured.get("status"))
    check("回执说明已被工具输出背书", "白盒证据校验" in note or "检回" in note, note[:60])

    # ⑨-3 不涉及代码 → 保持原行为（status 交给 add_fact 自动判定）
    captured.clear()
    note = asyncio.run(run_note("目标开放 8080", [step("httpreplay", "200 OK")]))
    check("无引用时 status 传空串（不改变原判定）", captured.get("status") == "",
          repr(captured.get("status")))
    check("无引用时回执仍是「已证事实」措辞", "已证事实" in note, note[:40])

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
