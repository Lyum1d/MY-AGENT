# -*- coding: utf-8 -*-
"""记忆机制回归：续聊恢复 / 异常沉淀 / 事实溯源 / 检索面 / 落库裁剪 / 留痕。

不联网、不调用真实工具、不碰任何目标资产；数据库与供应商配置均落在临时目录。
"""
import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config                                    # noqa: E402
from app import providers, store                          # noqa: E402
from app import agent as agent_mod                        # noqa: E402
from app.agent import agent, sessions                     # noqa: E402
from app.registry import registry                         # noqa: E402

# 隔离：数据库与供应商配置全部落在临时目录，绝不碰真实数据
_TMP = Path(tempfile.mkdtemp(prefix="src_agent_memory_test_"))
store.DB_PATH = _TMP / "test_memory.db"
config.LLM_PROVIDERS_FILE = _TMP / "providers_test.json"
config.AUTO_ROUTE_VULN = False
providers.invalidate()
store.init_db()
registry.load()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


def _step(sid, alias, name, out="", status="done", target="t.example.com"):
    return agent_mod.Step(id=sid, tool_alias=alias, tool_name=name, target=target,
                          args="", risk={"level": "L0"}, status=status, output=out)


# ---------------------------------------------------------------- 闸门不变量
def test_builtin_step_tools_invariant():
    """BUILTIN_STEP_TOOLS 里的工具会在风险闸门之前 continue 掉。

    所以这个集合是**安全边界**：一旦有人把 py_exec / httpreplay / nuclei_cli
    这类需要闸门的工具加进来，L3 二次确认就会被静默绕过。
    """
    gated = {"py_exec", "httpreplay", "nuclei_cli"}
    check("BUILTIN_STEP_TOOLS 不包含任何需要过风险闸门的工具",
          not (agent_mod.BUILTIN_STEP_TOOLS & gated),
          sorted(agent_mod.BUILTIN_STEP_TOOLS & gated))
    builtin_aliases = {t.alias for t in registry.tools if t.type == "内置"}
    check("BUILTIN_STEP_TOOLS 都是注册表里的内置工具",
          agent_mod.BUILTIN_STEP_TOOLS <= builtin_aliases,
          sorted(agent_mod.BUILTIN_STEP_TOOLS - builtin_aliases))


# ---------------------------------------------------------------- 事实溯源
def test_fact_attribution():
    s = agent_mod.Session(id="sess_m3", project="p", target="t.example.com")
    s.steps = [
        _step("call_http", "httpx", "Httpx辅助工具",
              "https://t.example.com [200] 中教云课 ZS-Proxy21/v201"),
        _step("call_ehole", "ehole", "Ehole", "[ https://other.example.net | nginx | 404 ]"),
    ]
    check("事实来自 httpx 的产出 → 归到 httpx（不再无脑取最后一步）",
          agent_mod.attribute_source_step(s, "t.example.com 200 中教云课 ZS-Proxy21/v201")
          == "call_http")
    check("事实来自 ehole 的产出 → 归到 ehole",
          agent_mod.attribute_source_step(s, "other.example.net nginx 404") == "call_ehole")
    check("对不上内容时回退到最近的非内置步骤",
          agent_mod.attribute_source_step(s, "完全无关的一句话") == "call_ehole")
    s.steps.append(_step("call_kb", "kb_read", "知识库阅读", "知识库正文 target.com 示例"))
    check("内置步骤不参与溯源（不会把事实挂到 kb_read 上）",
          agent_mod.attribute_source_step(s, "无关内容") == "call_ehole")
    check("没有任何步骤时返回空串",
          agent_mod.attribute_source_step(agent_mod.Session(id="x"), "f") == "")


# ---------------------------------------------------------------- 落库裁剪
def test_clip_output():
    big = "HEAD" * 400 + "MID" * 2000 + "TAIL" * 400
    c = agent_mod.clip_output(big)
    check("超长输出被折叠", len(c) < len(big), f"{len(big)} → {len(c)}")
    check("首部被保留（原实现只留尾部会永久丢掉它）", c.startswith("HEADHEAD"))
    check("尾部被保留", c.endswith("TAILTAIL"))
    check("短输出原样不动", agent_mod.clip_output("short") == "short")
    check("空值安全", agent_mod.clip_output("") == "" and agent_mod.clip_output(None) == "")


# ---------------------------------------------------------------- 内置工具留痕
def test_builtin_step_recorded():
    s = agent_mod.Session(id="sess_m4", project="p", target="t.example.com")

    class _T:
        alias, name, risk_level, risk_reason = "kb_read", "知识库阅读", "L0", "纯本地文件读取"

    before = len(s.steps)
    agent._record_builtin_step(s, {"id": "c1"}, _T(), "", "打穿短表", "【打穿短表】\n正文")
    check("内置工具调用后 steps 增加 1 条", len(s.steps) == before + 1)
    st = s.steps[-1]
    check("补记步骤 status=done", st.status == "done")
    check("补记步骤的 alias / output 正确",
          st.tool_alias == "kb_read" and "打穿短表" in st.output)
    check("补记步骤带风险等级（registry 已 load）",
          (st.risk or {}).get("level") == "L0", st.risk)


# ---------------------------------------------------------------- 续聊记忆
def test_adopt_restores_messages():
    pid = store.create_project("记忆回归", "t.example.com")["id"]
    store.save_chat_message("sess_m1", "user", "先做存活探测")
    store.save_chat_message("sess_m1", "assistant", "已确认可达，HTTP 200", kind="reasoning")
    store.save_chat_message("sess_m1", "assistant", "结论：站点存活", kind="answer")
    store.save_session("sess_m1", pid, "先做存活探测", "t.example.com", "done",
                       summary="结论：站点存活")
    sessions.sessions.pop("sess_m1", None)
    a = sessions.adopt("sess_m1")
    check("adopt 能取到会话", a is not None)
    check("messages 被恢复（修复前恒为 0 —— 续聊即失忆）", len(a.messages) > 0,
          f"n={len(a.messages)}")
    roles = [m["role"] for m in a.messages]
    check("相邻同角色已合并（避免连续 assistant 触发严格端点报错）",
          all(roles[i] != roles[i + 1] for i in range(len(roles) - 1)), roles)
    check("首条是 user（与 run() 追加的新 user 能构成合法交替）", roles[0] == "user")
    check("恢复后仍带 summary / target",
          bool(a.summary) and a.target == "t.example.com")
    # 再 adopt 一次不应重复灌入历史
    sessions.sessions.pop("sess_m1", None)
    a2 = sessions.adopt("sess_m1")
    check("重复 adopt 不会叠加历史", len(a2.messages) == len(a.messages))
    return pid


# ---------------------------------------------------------------- 检索面
def test_search_history_coverage(pid):
    store.save_session("sess_m5", pid, "任务", "t.example.com", "done")
    store.save_step("sess_m5", {"id": "st1", "tool_alias": "httpx", "tool_name": "Httpx辅助工具",
                                "target": "t.example.com", "args": "", "risk": {"level": "L0"},
                                "status": "done", "output": "t.example.com 200 标记ALPHA"})
    store.add_fact(pid, "已确认 secret-bravo 接口不需要鉴权")
    store.merge_intel(pid, {"hosts": ["api.gamma.example.net"]})
    kinds = lambda kw: {x.get("kind") for x in store.search_history(pid, kw)}
    check("能搜到工具执行输出", "step" in kinds("ALPHA"), kinds("ALPHA"))
    check("能搜到已证事实（修复前搜不到）", "fact" in kinds("secret-bravo"), kinds("secret-bravo"))
    check("能搜到项目情报（修复前搜不到）", "intel" in kinds("gamma"), kinds("gamma"))
    check("关键词为空时返回空", store.search_history(pid, "  ") == [])


# ---------------------------------------------------------------- 异常沉淀
def test_persist_on_error(pid):
    s = agent_mod.Session(id="sess_m2", project=pid, target="t.example.com", state="error")
    s.steps = [_step("a", "httpx", "Httpx辅助工具", "https://deep-host.example.org 存活")]
    agent._persist_intel(s)
    check("异常会话的情报也能沉淀（修复前整轮归零）",
          "deep-host.example.org" in (store.get_intel(pid).get("hosts") or []),
          store.get_intel(pid).get("hosts"))

    kb = agent_mod.Session(id="sess_kb", project=pid, state="error")
    kb.steps = [_step("b", "kb_read", "知识库阅读", "示例域名 target.com 出现在知识库正文")]
    agent._persist_intel(kb)
    check("内置工具的正文不会污染情报库（知识库里的示例域名不算资产）",
          "target.com" not in (store.get_intel(pid).get("hosts") or []),
          store.get_intel(pid).get("hosts"))

    s4 = agent_mod.Session(id="sess_m2b", project=pid, target="t.example.com", state="error")
    s4.steps = [_step("a", "httpx", "Httpx辅助工具"), _step("b", "ehole", "Ehole", status="denied")]
    store.save_session("sess_m2b", pid, "任务", "t.example.com", "error")
    agent.persist_interrupted(s4, reason="模型调用失败")
    summary = store.get_session_row("sess_m2b").get("summary") or ""
    check("中断摘要已落库并带【中断】标记", "【中断】" in summary, summary[:60])
    check("中断摘要写明总步数与成功步数", "2 步" in summary and "1 步成功" in summary)

    s5 = agent_mod.Session(id="sess_m2c", project=pid, state="error")
    s5.summary = "已有正式结论"
    agent.persist_interrupted(s5, reason="x")
    check("已有正式结论时不被半程快照覆盖", s5.summary == "已有正式结论")


# ---------------------------------------------------------------- 跨线索通知
def test_branch_update_redelivery(pid):
    store.save_session("sess_parent", pid, "父线索", "t.example.com", "running")
    store.save_session("sess_child", pid, "子线索", "t.example.com", "done",
                       parent_id="sess_parent")
    sessions.sessions.pop("sess_parent", None)
    sessions.sessions.pop("sess_child", None)
    child = agent_mod.Session(id="sess_child", project=pid,
                              parent_id="sess_parent", title="子线索")
    asyncio.run(agent._write_back(child, "子线索结论：发现可疑接口"))
    parent = sessions.sessions.get("sess_parent")
    check("父会话不在内存时被从持久化层装回", parent is not None)
    evs = []
    if parent is not None:
        while not parent.events.empty():
            evs.append(parent.events.get_nowait())
    check("branch_update 已入父会话队列（可随 SSE 补投，修复前直接丢弃）",
          any(e.get("type") == "branch_update" for e in evs), [e.get("type") for e in evs])


# ---------------------------------------------------------------- 注入上限
def test_inject_limits_declared():
    for name in ("FACT_INJECT_MAX", "RECORD_INJECT_MAX", "BRANCH_INJECT_MAX"):
        check(f"注入上限 {name} 已声明且为正整数",
              isinstance(getattr(config, name, None), int) and getattr(config, name) > 0)
    src = (ROOT / "app" / "agent.py").read_text(encoding="utf-8")
    check("事实注入超限会写明未展示条数（不再无声截断）", "条未展示" in src)
    check("records / 其他线索注入超限也会写明", src.count("条未展示") + src.count("条线索未展示") >= 3)
    check("续聊恢复与落库裁剪参数已声明",
          config.RESTORE_CHAT_MAX > 0 and config.RESTORE_CHAT_CHARS > 0
          and config.STEP_OUTPUT_HEAD > 0 and config.STEP_OUTPUT_TAIL > 0)


def main():
    print("== 安全边界不变量 ==")
    test_builtin_step_tools_invariant()
    print("\n== 事实溯源（按内容回查）==")
    test_fact_attribution()
    print("\n== 步骤输出落库裁剪（首尾保留）==")
    test_clip_output()
    print("\n== 内置记忆类工具留痕 ==")
    test_builtin_step_recorded()
    print("\n== 续聊恢复对话记忆 ==")
    pid = test_adopt_restores_messages()
    print("\n== 检索面覆盖 ==")
    test_search_history_coverage(pid)
    print("\n== 异常路径也要沉淀 ==")
    test_persist_on_error(pid)
    print("\n== 跨线索通知可补投 ==")
    test_branch_update_redelivery(pid)
    print("\n== 记忆注入上限 ==")
    test_inject_limits_declared()

    print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：", "；".join(fail))
        sys.exit(1)


if __name__ == "__main__":
    main()
