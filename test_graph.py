# -*- coding: utf-8 -*-
"""线索图（攻击图 / 因果图）功能回归：存储层 / 领域逻辑 / HTTP 接口 三层。

不联网、不调用真实工具、不碰任何目标资产；数据库落在临时目录。
运行：python test_graph.py
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config, store                                    # noqa: E402

# 隔离：先改 DB 路径，再导入依赖它的模块
_TMP = Path(tempfile.mkdtemp(prefix="src_agent_graph_test_"))
store.DB_PATH = _TMP / "test_graph.db"
config.LLM_PROVIDERS_FILE = _TMP / "providers_test.json"
store.init_db()

from app import graph                                            # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' -> ' + str(extra)) if extra else ''}")


def section(title):
    print(f"\n=== {title} ===")


# ---------- 一、表结构与迁移 ----------
section("表结构与迁移")
# [2026-09-16 对齐 v006] v004→006 更新包整体替换了 app/store.py，
# 连接工厂由 `_conn()`（裸连接，靠引用计数回收）改为 `_connect()` + `_db()`
# 上下文管理器。`_db()` 会提交/回滚并【保证关闭】连接，语义更强，测试沿用后者。
with store._db() as _c:
    tables = {r["name"] for r in _c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    fact_cols = {r["name"] for r in _c.execute("PRAGMA table_info(facts)").fetchall()}
    find_cols = {r["name"] for r in _c.execute("PRAGMA table_info(findings)").fetchall()}

check("causal_nodes 表已建", "causal_nodes" in tables)
check("causal_edges 表已建", "causal_edges" in tables)
check("facts 具备溯源列 session_id/step_id",
      {"session_id", "step_id"} <= fact_cols)
check("findings 具备溯源列 session_id", "session_id" in find_cols)

# ---------- 二、类型与 label 归一化 ----------
section("节点类型 / 边 label 归一化")
for raw, want in [("evidence", "Evidence"), ("key_fact", "KeyFact"), ("vuln", "Vulnerability"),
                  ("confirmedvulnerability", "ConfirmedVulnerability"), ("Flag", "Flag"),
                  ("我自己编的类型", "我自己编的类型")]:
    check(f"节点类型 {raw!r} -> {want}", graph.normalize_node_type(raw) == want,
          graph.normalize_node_type(raw))

for raw, want in [("FALSIFIES", "CONTRADICTS"), ("disproves", "CONTRADICTS"),
                  ("CONFIRMS", "SUPPORTS"), ("weak_support", "SUPPORTS"),
                  ("leads_to", "REVEALS"), ("INFORMS", "REVEALS"),
                  ("exploit", "EXPLOITS"), ("MITIGATES", "MITIGATES"),
                  ("", "SUPPORTS"), ("完全看不懂", "SUPPORTS")]:
    check(f"边 label {raw!r} -> {want}", graph.normalize_edge_label(raw) == want,
          graph.normalize_edge_label(raw))

# ---------- 三、置信度传播 ----------
section("置信度传播")
check("necessary+SUPPORTS -> 1.0/CONFIRMED",
      graph.score(0.5, "SUPPORTS", "necessary") == (1.0, "CONFIRMED"))
check("necessary+CONTRADICTS -> 0.0/FALSIFIED",
      graph.score(0.5, "CONTRADICTS", "necessary") == (0.0, "FALSIFIED"))
check("REVEALS 不改置信度", graph.score(0.42, "REVEALS", "contingent") == (0.42, None))
check("EXPLOITS 不改置信度", graph.score(0.42, "EXPLOITS", "contingent") == (0.42, None))

c1, s1 = graph.score(0.5, "SUPPORTS", "contingent")
c2, _ = graph.score(c1, "SUPPORTS", "contingent")
check("contingent 累积支撑使置信度单调上升", 0.5 < c1 < c2, f"{c1:.3f} -> {c2:.3f}")
check("支撑后状态为 SUPPORTED", s1 == "SUPPORTED", s1)

hi = 0.5
for _ in range(20):
    hi, _ = graph.score(hi, "SUPPORTS", "contingent")
check("置信度上界夹取在 0.95", hi <= 0.9501, f"{hi:.4f}")

lo = 0.5
for _ in range(20):
    lo, _ = graph.score(lo, "CONTRADICTS", "contingent")
check("置信度下界夹取在 0.05", lo >= 0.0499, f"{lo:.4f}")
_, s_lo = graph.score(0.05, "CONTRADICTS", "contingent")
check("反驳到极低置信度 -> FALSIFIED", s_lo == "FALSIFIED", s_lo)

# ---------- 四、攻击图 ----------
section("攻击图（线索树）")
pid = store.create_project("图测试项目", "example.com")["id"]
store.save_session("s_root", pid, "根线索任务", "example.com", "idle",
                   parent_id="", title="根线索", status="done")
store.save_session("s_child", pid, "分支任务", "example.com", "idle",
                   parent_id="s_root", title="子线索", status="active")
store.save_step("s_root", {"id": "stp_1", "tool_name": "nmap", "target": "example.com",
                           "status": "done", "output": "80/tcp open http"})

atk = graph.build_attack_graph(pid)
ids = {n["id"] for n in atk["nodes"]}
check("攻击图含项目根节点", f"project:{pid}" in ids)
check("攻击图含两条线索节点", {"s_root", "s_child"} <= ids, len(atk["nodes"]))
check("根线索挂在项目根上",
      any(e["source_id"] == f"project:{pid}" and e["target_id"] == "s_root"
          for e in atk["edges"]))
check("分支边 s_root -> s_child",
      any(e["source_id"] == "s_root" and e["target_id"] == "s_child" for e in atk["edges"]))
root_node = next(n for n in atk["nodes"] if n["id"] == "s_root")
child_node = next(n for n in atk["nodes"] if n["id"] == "s_child")
check("线索状态映射 done->completed", root_node["status"] == "completed", root_node["status"])
check("线索状态映射 active->in_progress", child_node["status"] == "in_progress")
check("节点带步数统计", root_node["data"]["step_count"] == 1,
      root_node["data"]["step_count"])
check("类型中文标签可用", root_node["type_label"] == "线索", root_node["type_label"])
check("线索节点带 parent 溯源（前端面包屑靠它回退）",
      child_node["data"].get("parent") == "s_root" and root_node["data"].get("parent") == "",
      f"child.parent={child_node['data'].get('parent')!r}")

# ---------- 五、事实 / 漏洞写入钩子 ----------
section("事实与漏洞的写入钩子")
fact = store.add_fact(pid, "example.com 存在 /admin 后台入口", source="agent",
                      session_id="s_root", step_id="stp_1")
graph.on_fact_added(pid, fact)
node = store.get_causal_node(pid, f"fact:{fact['id']}")
check("登记事实生成 KeyFact 节点", node is not None and node["node_type"] == "KeyFact",
      node["node_type"] if node else None)
check("事实节点带溯源 session/step",
      node["session_id"] == "s_root" and node["source_step"] == "stp_1")

cg = graph.build_causal_graph(pid)
check("溯源命中的步骤 -> 事实 生成 REVEALS 边",
      any(e["source_id"] == "step:stp_1" and e["target_id"] == f"fact:{fact['id']}"
          and e["label"] == "REVEALS" for e in cg["edges"]),
      [e["label"] for e in cg["edges"]])

store.delete_fact(fact["id"])
graph.on_fact_deleted(pid, fact["id"])
check("删除事实后节点被清理", store.get_causal_node(pid, f"fact:{fact['id']}") is None)

f_ok = store.add_finding(pid, "后台弱口令", "高危", "example.com",
                         detail="admin/admin 可登录", evidence="截图 1", session_id="s_root")
graph.on_finding_added(pid, f_ok)
n1 = store.get_causal_node(pid, f"finding:{f_ok['id']}")
check("有证据的漏洞 -> ConfirmedVulnerability/CONFIRMED",
      n1["node_type"] == "ConfirmedVulnerability" and n1["status"] == "CONFIRMED",
      f"{n1['node_type']}/{n1['status']}")

f_sus = store.add_finding(pid, "疑似目录遍历", "中危", "example.com")
graph.on_finding_added(pid, f_sus)
n2 = store.get_causal_node(pid, f"finding:{f_sus['id']}")
check("无证据的漏洞 -> Vulnerability/PENDING",
      n2["node_type"] == "Vulnerability" and n2["status"] == "PENDING",
      f"{n2['node_type']}/{n2['status']}")

# ---------- 六、增量写入与传播 ----------
section("增量写入 apply_updates")
r = graph.apply_updates(pid, {
    "nodes": [
        {"id": "tmp_1", "node_type": "Evidence", "title": "扫描结果",
         "description": "3306 开放", "confidence": 0.6},
        {"id": "tmp_2", "node_type": "hypothesis", "title": "跑着 MySQL",
         "confidence": 0.5},
    ],
    "edges": [
        {"source_id": "tmp_1", "target_id": "tmp_2", "label": "CONFIRMS",
         "strength": "necessary"},
        {"source_id": "tmp_1", "target_id": "不存在", "label": "SUPPORTS"},
    ],
})
check("两个节点写入成功", set(r["nodes"]) == {"tmp_1", "tmp_2"}, r["nodes"])
check("节点类型别名归一化 hypothesis->Hypothesis",
      store.get_causal_node(pid, "tmp_2")["node_type"] == "Hypothesis")
check("端点不存在的边被丢弃", r["dropped_edges"] == 1, r["dropped_edges"])
check("label 别名 CONFIRMS -> SUPPORTS",
      r["edges"][0]["label"] == "SUPPORTS", r["edges"][0]["label"])
n3 = store.get_causal_node(pid, "tmp_2")
check("necessary 支撑触发一票确认", n3["confidence"] == 1.0 and n3["status"] == "CONFIRMED",
      f"{n3['confidence']}/{n3['status']}")

graph.apply_updates(pid, {"edges": [{"source_id": "tmp_1", "target_id": "tmp_2",
                                     "label": "FALSIFIES", "strength": "necessary"}]})
n4 = store.get_causal_node(pid, "tmp_2")
check("FALSIFIES -> CONTRADICTS 触发一票否决",
      n4["confidence"] == 0.0 and n4["status"] == "FALSIFIED",
      f"{n4['confidence']}/{n4['status']}")
check("同一对节点同 label 不重复建边",
      len([e for e in store.list_causal_edges(pid) if e["label"] == "CONTRADICTS"]) == 1)

# ---------- 七、从既有数据派生 ----------
section("derive 派生")
store.save_step("s_root", {"id": "stp_2", "tool_name": "dirsearch",
                           "target": "example.com", "status": "done",
                           "output": "/admin 200"})
store.save_step("s_root", {"id": "stp_3", "tool_name": "失败的扫描",
                           "target": "example.com", "status": "error", "output": "timeout"})
fact2 = store.add_fact(pid, "example.com 存在 /admin 后台入口", source="agent",
                       session_id="s_root", step_id="stp_2")
found2 = store.add_finding(pid, "后台弱口令", "高危", "example.com",
                           detail="admin/admin", evidence="截图", session_id="s_root")
d1 = graph.derive(pid)
node_ids = {n["id"] for n in d1["nodes"]}
check("派生生成成功步骤的 Evidence 节点", "step:stp_2" in node_ids)
check("失败步骤不生成 Evidence 节点", "step:stp_3" not in node_ids)
check("派生生成 KeyFact 节点", f"fact:{fact2['id']}" in node_ids)
check("派生生成固定漏洞节点", f"finding:{found2['id']}" in node_ids)
check("派生不残留旧节点（清空重建）", not any(i.startswith("tmp_") for i in node_ids),
      [i for i in node_ids if i.startswith("tmp_")])
check("派生连出 Evidence->KeyFact 的 REVEALS 边",
      any(e["source_id"] == "step:stp_2" and e["target_id"] == f"fact:{fact2['id']}"
          and e["label"] == "REVEALS" for e in d1["edges"]))
check("同线索事实与漏洞之间是 REVEALS 关联（不冒充支撑证据）",
      any(e["source_id"] == f"fact:{fact2['id']}"
          and e["target_id"] == f"finding:{found2['id']}"
          and e["label"] == "REVEALS" for e in d1["edges"]),
      [(e["label"]) for e in d1["edges"]])

# 事实原文被漏洞证据引用时，才升级为 SUPPORTS（真·支撑）
store.add_finding(pid, "证据引用了事实的漏洞", "高危", "example.com",
                  detail="结论见证据", evidence="依据：example.com 存在 /admin 后台入口")
d3 = graph.derive(pid)
sup = [e for e in d3["edges"] if e["label"] == "SUPPORTS"]
check("漏洞证据引用了事实原文 -> 升级为 SUPPORTS", len(sup) == 1, sup)
check("被引用的漏洞节点是确认漏洞",
      bool(sup) and any(n["id"] == sup[0]["target_id"] and n["type_label"] == "确认漏洞"
                        for n in d3["nodes"]))

d2 = graph.derive(pid)
check("derive 幂等（节点数不变）", len(d2["nodes"]) == len(d3["nodes"]),
      f"{len(d3['nodes'])} -> {len(d2['nodes'])}")
check("无悬空边",
      all(e["source_id"] in {n["id"] for n in d2["nodes"]}
          and e["target_id"] in {n["id"] for n in d2["nodes"]} for e in d2["edges"]))

# ---------- 八、HTTP 接口 ----------
section("HTTP 接口")
from fastapi.testclient import TestClient                     # noqa: E402
from app.main import app as fastapi_app                        # noqa: E402

# base_url 必须带上回环名：v006 起 main.py 加了本机访问守卫
# （DNS 重绑定 + 跨站来源校验），默认的 Host: testserver 会被判成 403。
client = TestClient(fastapi_app, base_url="http://127.0.0.1")
r = client.get(f"/api/projects/{pid}/graph/attack")
check("GET graph/attack 返回 200", r.status_code == 200, r.status_code)
check("attack 载荷含 nodes/edges",
      set(r.json()) >= {"nodes", "edges"} if r.status_code == 200 else False)

r = client.get(f"/api/projects/{pid}/graph/causal")
check("GET graph/causal 返回 200", r.status_code == 200, r.status_code)
check("causal 载荷含类型中文标签",
      r.status_code == 200 and all("type_label" in n for n in r.json()["nodes"]))

r = client.post(f"/api/projects/{pid}/graph/causal", json={
    "nodes": [{"id": "api_1", "node_type": "Evidence", "title": "接口写入",
               "confidence": 0.5}],
    "edges": [],
})
check("POST graph/causal 写入成功", r.status_code == 200 and r.json()["nodes"] == ["api_1"],
      r.status_code)

r = client.post(f"/api/projects/{pid}/graph/causal/derive")
check("POST graph/causal/derive 返回图", r.status_code == 200 and "nodes" in r.json(),
      r.status_code)

r = client.get("/api/projects/不存在的项目/graph/attack")
check("不存在的项目返回 404", r.status_code == 404, r.status_code)

# 事实/漏洞接口的溯源字段：走一遍 HTTP，确认能带上 session_id
r = client.post(f"/api/projects/{pid}/facts",
                json={"content": "接口登记的事实", "session_id": "s_root", "step_id": "stp_2"})
check("POST facts 接受溯源字段", r.status_code == 200, r.status_code)
fid_api = r.json()["id"]
row = store.get_causal_node(pid, f"fact:{fid_api}")
check("HTTP 登记事实同步生成因果节点", row is not None and row["session_id"] == "s_root")

r = client.delete(f"/api/projects/{pid}/facts/{fid_api}")
check("DELETE facts 同步清理因果节点",
      r.status_code == 200 and store.get_causal_node(pid, f"fact:{fid_api}") is None)

# 删项目应连带清掉图数据
store.delete_project(pid)
check("删除项目连带清理因果图",
      store.list_causal_nodes(pid) == [] and store.list_causal_edges(pid) == [])

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
if fail:
    for name in fail:
        print(f"    FAIL: {name}")
print(f"  临时库：{_TMP}")
print("=" * 56)
sys.exit(1 if fail else 0)
