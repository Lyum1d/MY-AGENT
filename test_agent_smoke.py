# -*- coding: utf-8 -*-
"""Agent 冒烟：用假后端跑通 ReAct 全链路，验证供应商层改造后主循环未坏。

不联网、不调用真实工具、不碰任何目标资产。跑完自动删除。
"""
import asyncio
import json
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
from app.llm import OllamaBackend                         # noqa: E402

# 隔离供应商配置：本脚本对 auto_route / current 的读写落在临时文件，
# 绝不污染用户真实的 %USERPROFILE%\.src_agent_llm.json。
config.LLM_PROVIDERS_FILE = Path(tempfile.gettempdir()) / "src_agent_providers_smoke.json"
providers.invalidate()

registry.load()   # 独立脚本不会触发 main.py 里的加载，内置工具需要手动注册

FACT_TEXT = "冒烟测试：已证事实写入通路正常"
ANSWER = "SMOKE-OK：链路完整"

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


class FakeBackend:
    """第 1 轮调 note_fact，之后只给结论（触发 agent 的催促与收尾分支）。"""
    name = "ollama"
    label = "本地 Ollama"
    model = "fake-smoke-model"
    local = True

    def __init__(self):
        self.calls = 0

    def available(self):
        return True

    async def chat(self, messages, tools=None):
        self.calls += 1
        self.last_messages = messages
        if self.calls == 1:
            return {
                "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "note_fact",
                                 "arguments": json.dumps({"args": FACT_TEXT}, ensure_ascii=False)},
                }],
                "content": "记录一条已证事实",
            }
        return {"tool_calls": [], "content": ANSWER}


async def main():
    print("== A. 供应商 → 后端实例 ==")
    b = agent_mod.get_backend(None)
    check("默认后端是 OllamaBackend", isinstance(b, OllamaBackend), type(b).__name__)
    check("后端带 label/local 属性供前端显示",
          bool(getattr(b, "label", "")) and b.local is True, f"{b.label} local={b.local}")

    print("== B. 漏洞类任务自动路由 ==")
    providers.set_auto_route(True, "deepseek")
    cand = agent_mod.auto_route_candidate("ollama")
    check("命中关键词时会路由到 deepseek 供应商",
          cand is not None and cand.name == "deepseek",
          getattr(cand, "label", None))
    check("当前已是该云端时不再自我路由",
          agent_mod.auto_route_candidate("deepseek") is None)
    providers.set_auto_route(False)
    check("关闭自动路由后返回 None", agent_mod.auto_route_candidate("ollama") is None)
    providers.set_auto_route(True, "deepseek")   # 复原

    print("== C. ReAct 全链路（假后端） ==")
    proj = store.create_project("冒烟测试项目", "smoke.local", "跑完即删")
    fake = FakeBackend()
    agent_mod.get_backend = lambda name=None: fake     # 只替换 agent 模块内的引用

    s = sessions.create(project=proj["id"])
    events = []

    async def consume():
        while True:
            ev = await s.events.get()
            events.append(ev)
            if ev.get("type") == "done":
                return

    consumer = asyncio.create_task(consume())
    await agent.run(s, "冒烟：记录一条已证事实然后结束")
    await asyncio.wait_for(consumer, timeout=15)   # 等事件消费完再断言，否则读到的是半截列表

    model_ev = next((e for e in events if e.get("type") == "model"), None)
    check("发出 model 事件且带 label", model_ev is not None
          and model_ev["data"].get("label") == "本地 Ollama", model_ev["data"] if model_ev else None)
    check("note_fact 写入事实库",
          any(FACT_TEXT in f["content"] for f in store.list_facts(proj["id"])),
          f"{len(store.list_facts(proj['id']))} 条")
    ans = next((e for e in events if e.get("type") == "answer"), None)
    check("最终结论事件", ans is not None and ANSWER in ans["data"], (ans or {}).get("data", "")[:40])
    done = next((e for e in events if e.get("type") == "done"), None)
    check("done 状态为 done", done is not None and done.get("state") == "done")

    store.delete_project(proj["id"])
    check("测试项目已清理", store.get_project(proj["id"]) is None)

    print("== D. 项目目标注入（企业名/域名识别修复） ==")
    proj2 = store.create_project("目标注入测试", "腾讯", "公益 SRC 授权资产")
    fake2 = FakeBackend()
    agent_mod.get_backend = lambda name=None: fake2

    s2 = sessions.create(project=proj2["id"])
    ev2 = []

    async def consume2():
        while True:
            e = await s2.events.get()
            ev2.append(e)
            if e.get("type") == "done":
                return

    c2 = asyncio.create_task(consume2())
    await agent.run(s2, "做信息收集")     # 任务描述里完全没有目标
    await asyncio.wait_for(c2, timeout=15)

    check("任务无目标时回退到项目目标", s2.target == "腾讯", s2.target)
    target_ev = next((e for e in ev2 if e.get("type") == "target"), None)
    check("发出 target 事件（= 项目目标）", target_ev is not None and target_ev["data"] == "腾讯",
          target_ev["data"] if target_ev else None)
    sys_text = "\n".join(str(m.get("content", "")) for m in fake2.last_messages if m.get("role") == "system")
    check("系统提示注入「项目目标：腾讯」", "项目目标：腾讯" in sys_text)
    check("系统提示注入项目名称", "目标注入测试" in sys_text)
    # 企业名目标引导用 app_info 扩展资产，并明确不调用已禁用的 enscan
    check("企业名目标引导 app_info 扩展资产", "app_info" in sys_text)
    check("明确提示不调用已禁用的 enscan", "enscan" in sys_text)

    # 任务里已有更具体域名时，以任务里的为准，不用项目目标覆盖
    fake3 = FakeBackend()
    agent_mod.get_backend = lambda name=None: fake3
    s3 = sessions.create(project=proj2["id"])
    ev3 = []

    async def consume3():
        while True:
            e = await s3.events.get()
            ev3.append(e)
            if e.get("type") == "done":
                return

    c3 = asyncio.create_task(consume3())
    await agent.run(s3, "对 demo.example.com 做指纹识别")
    await asyncio.wait_for(c3, timeout=15)
    check("任务含域名时优先用任务里的目标", s3.target == "demo.example.com", s3.target)

    store.delete_project(proj2["id"])
    check("目标注入测试项目已清理", store.get_project(proj2["id"]) is None)


asyncio.run(main())
print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：" + "、".join(fail))
    sys.exit(1)
