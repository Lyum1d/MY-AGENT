# -*- coding: utf-8 -*-
"""Agent 端到端测试：不依赖 Web 层，直接在终端跑一轮真实工具调用。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.agent import agent, sessions          # noqa: E402
from app.registry import registry              # noqa: E402
from app.llm import get_backend                # noqa: E402


async def consume(session, stop_state="done"):
    """消费事件队列并打印。"""
    while True:
        ev = await session.events.get()
        t = ev.get("type")
        if t == "thinking":
            print(f"\n[思考] {ev.get('data')}")
        elif t == "reasoning":
            print(f"[模型] {ev.get('data','')[:400]}")
        elif t == "need_confirm":
            s = ev["step"]
            print(f"\n[需要确认] {s['tool_name']} | 风险 {ev['risk'].get('level')} | 目标 {s['target']}")
            print(f"           依据：{ev['risk'].get('reason')}")
            # 测试环境自动拒绝 L3，放行 L2
            approved = ev["risk"].get("level") != "L3"
            print(f"           自动决策：{'放行' if approved else '拒绝(L3)'}")
            await session.control.put({"approved": approved})
        elif t == "command":
            print(f"[命令] {ev.get('data')}")
        elif t == "output":
            print(f"  | {ev.get('data')}")
        elif t == "exit":
            print(f"[退出码] {ev.get('code')}")
        elif t == "step_denied":
            print(f"[已拒绝] {ev['step']['tool_name']}")
        elif t == "answer":
            print(f"\n[结论] {ev.get('data')[:600]}")
        elif t == "error":
            print(f"[错误] {ev.get('data')}")
        elif t == "done":
            print(f"\n[结束] 状态={ev.get('state')}  共 {len(session.steps)} 步")
            return


async def main():
    registry.load()
    print("工具注册表:", registry.stats())

    health = await get_backend("ollama").health()
    print("模型状态:", health)
    if not health.get("ready"):
        print("模型未就绪，退出")
        return

    task = sys.argv[1] if len(sys.argv) > 1 else "探测 example.com 的 Web 指纹，判断它用了什么技术栈"
    print(f"\n任务：{task}\n" + "=" * 60)

    session = sessions.create(project="测试")
    consumer = asyncio.create_task(consume(session))
    await agent.run(session, task)
    await consumer


if __name__ == "__main__":
    asyncio.run(main())
