# -*- coding: utf-8 -*-
"""线索图端到端联调：对着真实运行的服务走一遍攻击图 / 因果图全链路。

会创建一个临时项目并在结束时删除，不留残余数据。
"""
import asyncio
import os
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

BASE = "http://127.0.0.1:8770"
ok, fail = [], []
skipped = []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' -> ' + str(extra)) if extra else ''}")


def skip(name, why):
    """明确记为「已下线」，而不是删掉断言或让它失败。

    保留这段是为了：将来恢复线索图前端时，这里的期望值就是现成的验收标准。
    """
    skipped.append(name)
    print(f"  [跳过] {name} -> 已下线：{why}")


async def main():
    pid = sid = ""
    async with httpx.AsyncClient(timeout=30, trust_env=False) as c:
        # 0) 静态资源
        # graph.js 文件本身还在磁盘上（上游 zip 里没有它，所以没被覆盖，只是没人加载），
        # 但 v006 的 index.html 不再引用它、也没有攻击图/因果图切换按钮 ——
        # 前端入口已下线（2026-09-16 拉上游更新所致，经确认暂不恢复）。
        # 后端链路照旧全量验证，见下面的接口断言。
        r = await c.get(BASE + "/static/graph.js")
        check("graph.js 文件仍可访问（后端静态目录仍提供它）", r.status_code == 200, r.status_code)
        check("graph.js 含 GraphView 定义（将来重接前端可直接复用）",
              "const GraphView" in r.text)
        r = await c.get(BASE + "/")
        skip("页面引用了 graph.js 且在图之前",
             "v006 上游 index.html 无 graph.js 入口，线索图前端已下线")
        skip("页面含攻击图/因果图切换按钮",
             "v006 上游 index.html 无 data-view=attack/causal 切换")

        try:
            # 1) 建临时项目与会话
            r = await c.post(BASE + "/api/projects",
                             json={"name": "线索图E2E-临时", "target": "example.com"})
            pid = r.json()["id"]
            r = await c.post(BASE + "/api/sessions", json={"project_id": pid})
            sid = r.json()["session_id"]
            check("临时项目与会话已建立", bool(pid and sid), f"{pid}/{sid}")

            # 2) 直接落一条成功的执行步骤（模拟 agent 跑过工具）
            from app import store
            # 新会话要到首次执行才写库（与前端「发送后才出现在线索树」一致），
            # 这里补上这次落库，才谈得上攻击图里有节点。
            store.save_session(sid, pid, "对 example.com 做信息收集", "example.com", "idle",
                               parent_id="", title="信息收集", status="active")
            store.save_step(sid, {"id": "e2e_step_1", "tool_name": "nmap",
                                  "target": "example.com", "status": "done",
                                  "output": "80/tcp open http Apache/2.4.49"})
            check("执行步骤已落库", store.get_step("e2e_step_1") is not None)

            # 3) 登记事实（带溯源）→ 因果图应实时长出 Evidence + KeyFact + REVEALS 边
            r = await c.post(f"{BASE}/api/projects/{pid}/facts",
                             json={"content": "example.com 存在 /admin 后台入口",
                                   "session_id": sid, "step_id": "e2e_step_1"})
            check("登记事实接口返回 200", r.status_code == 200, r.status_code)
            r = await c.get(f"{BASE}/api/projects/{pid}/graph/causal")
            g = r.json()
            ids = {n["id"] for n in g["nodes"]}
            check("因果图出现 Evidence 节点（按需物化）", "step:e2e_step_1" in ids, sorted(ids))
            check("因果图出现 KeyFact 节点",
                  any(i.startswith("fact:") for i in ids))
            check("生成 Evidence->KeyFact 的 REVEALS 边",
                  any(e["label"] == "REVEALS" for e in g["edges"]),
                  [e["label"] for e in g["edges"]])
            ev = next(n for n in g["nodes"] if n["id"] == "step:e2e_step_1")
            check("Evidence 节点带工具信息与类型标签",
                  ev["type_label"] == "证据" and "nmap" in ev["title"], ev["title"])

            # 4) 登记带证据的漏洞 → ConfirmedVulnerability，并被同线索事实支撑
            r = await c.post(f"{BASE}/api/projects/{pid}/findings",
                             json={"title": "后台弱口令", "severity": "高危",
                                   "target": "example.com", "detail": "admin/admin 可登录",
                                   "evidence": "登录成功截图", "session_id": sid})
            check("登记漏洞接口返回 200", r.status_code == 200, r.status_code)
            r = await c.get(f"{BASE}/api/projects/{pid}/graph/causal")
            g = r.json()
            vuln = next((n for n in g["nodes"] if n["node_type"] == "ConfirmedVulnerability"), None)
            check("有证据的漏洞生成确认漏洞节点", vuln is not None,
                  vuln["status"] if vuln else None)
            check("漏洞节点状态为 CONFIRMED", vuln and vuln["status"] == "CONFIRMED")
            check("同线索事实与漏洞之间是 REVEALS 关联",
                  any(e["label"] == "REVEALS" for e in g["edges"]),
                  [f"{e['label']}" for e in g["edges"]])

            # 5) 攻击图
            r = await c.get(f"{BASE}/api/projects/{pid}/graph/attack")
            a = r.json()
            aids = {n["id"] for n in a["nodes"]}
            check("攻击图含项目根节点", f"project:{pid}" in aids)
            check("攻击图含该线索节点", sid in aids)
            check("线索挂在项目根上",
                  any(e["source_id"] == f"project:{pid}" and e["target_id"] == sid
                      for e in a["edges"]))
            thr = next(n for n in a["nodes"] if n["id"] == sid)
            check("线索节点带步数", thr["data"]["step_count"] == 1,
                  thr["data"]["step_count"])

            # 6) 增量写入 + 置信度传播
            r = await c.post(f"{BASE}/api/projects/{pid}/graph/causal", json={
                "nodes": [{"id": "e2e_h1", "node_type": "hypothesis",
                           "title": "可能存在其它后台", "confidence": 0.5}],
                "edges": [{"source_id": "e2e_h1", "target_id": f"fact:"
                           + next(i.split(":", 1)[1] for i in ids if i.startswith("fact:")),
                           "label": "DISPROVES", "strength": "necessary"}],
            })
            check("增量写入接口返回 200", r.status_code == 200, r.status_code)
            body = r.json()
            check("节点类型别名 hypothesis -> Hypothesis",
                  next(n for n in body["graph"]["nodes"] if n["id"] == "e2e_h1")["node_type"]
                  == "Hypothesis")
            check("label 别名 DISPROVES -> CONTRADICTS",
                  any(e["label"] == "CONTRADICTS" for e in body["edges"]),
                  [e["label"] for e in body["edges"]])
            check("必要证据触发一票否决",
                  any(p["status"] == "FALSIFIED" for p in body["propagated"]),
                  body["propagated"])

            # 7) derive 重建
            r = await c.post(f"{BASE}/api/projects/{pid}/graph/causal/derive")
            d = r.json()
            check("derive 返回完整图", r.status_code == 200 and "nodes" in d, r.status_code)
            check("derive 后无悬空边",
                  all(e["source_id"] in {n["id"] for n in d["nodes"]}
                      and e["target_id"] in {n["id"] for n in d["nodes"]}
                      for e in d["edges"]))
            check("derive 后既无临时节点残留",
                  not any(n["id"].startswith("e2e_h1") for n in d["nodes"]))

            # 8) 404 分支
            r = await c.get(BASE + "/api/projects/nope-not-exist/graph/attack")
            check("不存在项目返回 404", r.status_code == 404, r.status_code)
        finally:
            if pid:
                await c.delete(f"{BASE}/api/projects/{pid}")

    # 9) 清理校验（走本地 store，服务端已删）
    from app import store
    left = [p for p in store.list_projects() if p["id"] == pid]
    check("临时项目已删除", not left)
    check("临时项目的因果数据已清理",
          store.list_causal_nodes(pid) == [] and store.list_causal_edges(pid) == [])

    print(f"\n{'=' * 56}\n  通过 {len(ok)} 项，失败 {len(fail)} 项")
    for f in fail:
        print(f"    FAIL: {f}")
    if skipped:
        print(f"  另有 {len(skipped)} 项跳过（已下线的线索图前端入口，非回归）：")
        for s in skipped:
            print(f"    SKIP: {s}")
    print("=" * 56)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
