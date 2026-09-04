# -*- coding: utf-8 -*-
"""端到端真机测试：用已接入的云端 LLM（默认 DeepSeek）驱动真实工具链路。

验证点：
  1. 项目里填的「目标」能在任务描述不含域名时正确注入模型；
  2. 云端模型通过通用 OpenAI 兼容后端正常产出 function calling；
  3. 工具真实执行、风险闸门、结论收尾整条链路跑通。

用法：
  venv_python test_e2e_deepseek.py [backend] ["自定义任务"]
  例：venv_python test_e2e_deepseek.py deepseek
      venv_python test_e2e_deepseek.py deepseek "对 example.com 做指纹识别"

安全：默认只对 example.com 做存活探测 + 指纹识别（L1，全程留痕）；L3 自动拒绝。
"""
import asyncio
import json
import sys

import httpx

BASE = "http://127.0.0.1:8770"
BACKEND = sys.argv[1] if len(sys.argv) > 1 else "deepseek"
# 注意：任务描述里故意不写域名，验证项目目标注入
TASK = sys.argv[2] if len(sys.argv) > 2 else "做存活探测与指纹识别，完成后给出结论"
PROJECT_TARGET = "example.com"

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


async def main():
    async with httpx.AsyncClient(timeout=300, trust_env=False) as c:
        # 记录当前后端，测试完复原
        cur = (await c.get(f"{BASE}/api/llm/providers")).json()["current"]

        # 1. 切到目标后端
        r = await c.post(f"{BASE}/api/llm/providers/{BACKEND}/use", json={"id": BACKEND})
        r.raise_for_status()
        print(f"[后端] 已切换到 {r.json()['current']}（模型 {r.json()['model']}）")

        # 2. 建项目（目标只写在项目里，任务描述里不出现）
        r = await c.post(f"{BASE}/api/projects",
                         json={"name": "e2e云模型测试", "target": PROJECT_TARGET})
        proj = r.json()
        print(f"[项目] {proj['name']}（目标 {PROJECT_TARGET}）")

        # 3. 建会话 + 下发任务
        r = await c.post(f"{BASE}/api/sessions", params={"project_id": proj["id"]})
        sid = r.json()["session_id"]
        await c.post(f"{BASE}/api/sessions/{sid}/run",
                     json={"message": TASK, "project_id": proj["id"]})

        # 4. 消费 SSE
        events, tool_runs = [], []
        print("\n" + "=" * 60)
        async with c.stream("GET", f"{BASE}/api/sessions/{sid}/stream",
                            timeout=httpx.Timeout(600, connect=10)) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                ev = json.loads(line[5:].strip())
                events.append(ev)
                t = ev.get("type")
                if t == "model":
                    print(f"[模型] {ev['data'].get('label')} · {ev['data'].get('model')}")
                elif t == "target":
                    print(f"[目标] {ev['data']}")
                elif t == "thinking":
                    print(f"[思考] {ev['data']}")
                elif t == "reasoning":
                    print(f"[推理] {ev['data'][:160]}")
                elif t == "step_start":
                    print(f"[步骤] {ev['step']['tool_name']} → {ev['step'].get('target','')[:60]}")
                elif t == "command":
                    print(f"  $ {ev['data'][-110:]}")
                elif t == "output":
                    print(f"  | {ev['data'][:110]}")
                elif t == "exit":
                    print(f"  [退出码 {ev['code']}]")
                elif t == "step_done":
                    tool_runs.append(ev["step"])
                    print(f"  ✓ {ev['step']['tool_name']} {ev['step']['status']}")
                elif t == "need_confirm":
                    lvl = ev["risk"]["level"]
                    approved = lvl != "L3"
                    print(f"  [确认] {ev['step']['tool_name']} {lvl} → {'放行' if approved else '拒绝'}")
                    await c.post(f"{BASE}/api/sessions/{sid}/confirm",
                                 json={"approved": approved})
                elif t == "error":
                    print(f"[错误] {ev['data']}")
                elif t == "answer":
                    print(f"\n[结论] {ev['data'][:400]}")
                elif t == "done":
                    print(f"\n[结束] {ev['state']}")
                    break

        # 5. 断言
        print("\n" + "=" * 60)
        target_ev = next((e for e in events if e.get("type") == "target"), None)
        check("目标事件 = 项目目标(example.com)",
              target_ev is not None and PROJECT_TARGET in (target_ev.get("data") or ""),
              target_ev.get("data") if target_ev else None)
        model_ev = next((e for e in events if e.get("type") == "model"), None)
        check("使用云端模型决策",
              model_ev is not None and model_ev["data"].get("local") is False,
              model_ev["data"] if model_ev else None)
        check("至少一个工具真实执行", len(tool_runs) >= 1, f"{len(tool_runs)} 个")
        done = next((e for e in events if e.get("type") == "done"), None)
        check("正常收尾", done is not None and done.get("state") == "done",
              done.get("state") if done else None)

        # 6. 报告可生成
        r = await c.get(f"{BASE}/api/projects/{proj['id']}/report")
        check("报告可生成", len(r.json().get("markdown", "")) > 0)

        # 7. 清理 + 复原后端
        await c.delete(f"{BASE}/api/projects/{proj['id']}")
        await c.post(f"{BASE}/api/llm/providers/{cur}/use", json={"id": cur})
        print(f"[清理] 项目已删，后端已复原为 {cur}")

    print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
