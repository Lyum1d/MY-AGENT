# -*- coding: utf-8 -*-
"""端到端接口测试：项目 → 会话 → SSE 执行 → 确认 → 报告。"""
import asyncio
import json
import sys

import httpx

BASE = "http://127.0.0.1:8770"
TASK = sys.argv[1] if len(sys.argv) > 1 else "对 example.com 做存活探测与指纹识别"


async def main():
    async with httpx.AsyncClient(timeout=300) as c:
        # 1. 建项目
        r = await c.post(f"{BASE}/api/projects", json={"name": "接口测试项目", "target": "example.com"})
        proj = r.json()
        print(f"[项目] {proj['name']} ({proj['id']})")

        # 2. 建会话
        r = await c.post(f"{BASE}/api/sessions", params={"project_id": proj["id"]})
        sid = r.json()["session_id"]
        print(f"[会话] {sid}")

        # 3. 下发任务
        r = await c.post(f"{BASE}/api/sessions/{sid}/run",
                         json={"message": TASK, "project_id": proj["id"]})
        print(f"[下发] {r.json()}")

        # 4. 消费 SSE
        print("\n" + "=" * 60)
        async with c.stream("GET", f"{BASE}/api/sessions/{sid}/stream",
                            timeout=httpx.Timeout(300, connect=10)) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                ev = json.loads(line[5:].strip())
                t = ev.get("type")

                if t == "thinking":
                    print(f"[思考] {ev['data']}")
                elif t == "target":
                    print(f"[目标] {ev['data']}")
                elif t == "reasoning":
                    print(f"[模型] {ev['data'][:200]}")
                elif t == "command":
                    print(f"[命令] {ev['data'][-90:]}")
                elif t == "output":
                    print(f"    | {ev['data'][:120]}")
                elif t == "exit":
                    print(f"[退出] {ev['code']}")
                elif t == "need_confirm":
                    s = ev["step"]
                    lvl = ev["risk"]["level"]
                    print(f"\n[需确认] {s['tool_name']} | {lvl} | target={s['target']}")
                    approved = lvl != "L3"
                    print(f"         → {'放行' if approved else '拒绝(L3)'}")
                    await c.post(f"{BASE}/api/sessions/{sid}/confirm", json={"approved": approved})
                elif t == "error":
                    print(f"[错误] {ev['data']}")
                elif t == "answer":
                    print(f"\n[结论] {ev['data'][:400]}")
                elif t == "done":
                    print(f"\n[结束] {ev['state']}")
                    break

        # 5. 报告
        r = await c.get(f"{BASE}/api/projects/{proj['id']}/report")
        md = r.json()["markdown"]
        print(f"\n[报告] 生成 {len(md)} 字符")
        print("-" * 40)
        print("\n".join(md.splitlines()[:14]))


if __name__ == "__main__":
    asyncio.run(main())
