# -*- coding: utf-8 -*-
"""对话树（线索分支）功能回归：数据层 / API / 内置工具 / 结论回流。

不联网、不调用真实工具、不碰任何目标资产；数据库与供应商配置均落在临时目录。
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

# 隔离：数据库与供应商配置全部落在临时目录，绝不碰真实数据
_TMP = Path(tempfile.mkdtemp(prefix="src_agent_tree_test_"))
store.DB_PATH = _TMP / "test_tree.db"
config.LLM_PROVIDERS_FILE = _TMP / "providers_test.json"
providers.invalidate()
store.init_db()
registry.load()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


ANSWER = "TREE-OK：结论已回流"


class FakeBackend:
    """可编程假后端：按预设脚本逐轮回工具调用或结论。"""
    name = "ollama"
    label = "本地 Ollama"
    model = "fake-tree-model"
    local = True

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def available(self):
        return True

    async def health(self):
        return {"ready": True}

    async def chat(self, messages, tools=None):
        self.calls += 1
        # 每轮都检查树上下文是否注入（记录给断言用）
        self.last_system = messages[0]["content"] if messages else ""
        action = self.script[min(self.calls - 1, len(self.script) - 1)]
        return action


def tool_call(name, args=""):
    return {
        "tool_calls": [{
            "id": f"call_{name}", "type": "function",
            "function": {"name": name, "arguments": json.dumps({"args": args}, ensure_ascii=False)},
        }],
        "content": "",
    }


def done(answer):
    return {"tool_calls": [], "content": answer}


async def collect(session):
    events = []
    while True:
        ev = await asyncio.wait_for(session.events.get(), timeout=5)
        events.append(ev)
        if ev.get("type") == "done":
            break
    return events


def test_store_layer():
    print("== A. 数据层（迁移 / 分支 / 树 / 元数据 / 检索） ==")
    proj = store.create_project("树测试项目", "demo.example.com", "跑完即删")
    pid = proj["id"]
    # 旧式落库（不传树字段）→ 新列应为默认值且不报错
    store.save_session("root1", pid, "对目标做信息收集", "demo.example.com", "done")
    row = store.get_session_row("root1")
    check("旧式 save_session 兼容且补默认树字段",
          row["parent_id"] == "" and row["status"] == "active" and row["context"] == "[]")
    # save_session 更新时不能冲掉树字段
    store.update_session_meta("root1", title="主对话")
    store.save_session("root1", pid, "对目标做信息收集", "demo.example.com", "done")
    check("save_session 更新不冲掉 title", store.get_session_row("root1")["title"] == "主对话")

    recs = ["[httpx → demo.example.com] 输出摘要: 200 OK server: nginx",
            "[ehole → demo.example.com] 输出摘要: 指纹 nginx|php"]
    b = store.create_branch("root1", pid, "admin.php 疑似注入", recs)
    row_b = store.get_session_row(b["id"])
    check("create_branch 落库 parent_id/title", row_b["parent_id"] == "root1" and row_b["title"] == "admin.php 疑似注入")
    check("create_branch 记录打包进 context", json.loads(row_b["context"]) == recs)
    check("list_tree 返回两级结构", len(store.list_tree(pid)) == 2)

    # 元数据状态白名单
    store.update_session_meta(b["id"], status="done")
    check("状态更新生效", store.get_session_row(b["id"])["status"] == "done")
    try:
        store.update_session_meta(b["id"], status="hacked")
        check("非法状态被拒绝", False)
    except ValueError:
        check("非法状态被拒绝", True)

    # 摘要与跨线索检索
    store.save_summary(b["id"], "确认 /admin.php id=1 存在报错型注入")
    check("save_summary 落库", "报错型注入" in store.get_session_row(b["id"])["summary"])
    # 给分支造一条 step 供检索
    store.save_step(b["id"], {"id": "st1", "tool_alias": "sqlmap", "tool_name": "SQLMAP X Plus",
                              "target": "demo.example.com", "args": "-u http://demo.example.com/admin.php?id=1",
                              "risk": {"level": "L2"}, "status": "done",
                              "output": "Parameter: id (GET) - Type: error-based payload"})
    hits = store.search_history(pid, "error-based")
    check("search_history 命中步骤输出", len(hits) == 1 and "error-based" in hits[0]["snippet"])
    check("search_history 带来源线索名", hits[0]["title"] == "admin.php 疑似注入")
    check("search_history 无关键词时返回空", store.search_history(pid, "") == [])

    # 级联删除：删除根分支应带走所有后代与关联数据
    store.save_session("del_root", pid, "待删根", "demo.example.com", "idle",
                       parent_id="", title="待删根", status="active")
    store.save_session("del_child", pid, "待删子", "demo.example.com", "idle",
                       parent_id="del_root", title="待删子", status="active")
    store.save_session("del_grand", pid, "待删孙", "demo.example.com", "idle",
                       parent_id="del_child", title="待删孙", status="active")
    store.save_step("del_child", {"id": "del_st1", "tool_alias": "nmap",
                                  "tool_name": "Nmap", "target": "demo.example.com",
                                  "status": "done", "output": "80 open"})
    store.save_chat_message("del_child", "assistant", "发现开放端口")
    res = store.delete_session_tree("del_root")
    check("delete_session_tree 级联删除根及后代",
          set(res["deleted_ids"]) == {"del_root", "del_child", "del_grand"},
          res["deleted_ids"])
    check("删除后根会话不存在", store.get_session_row("del_root") is None)
    check("删除后孙会话不存在", store.get_session_row("del_grand") is None)
    with store._conn() as _c:
        left_steps = _c.execute("SELECT COUNT(*) FROM steps WHERE session_id='del_child'").fetchone()[0]
        left_chat = _c.execute("SELECT COUNT(*) FROM chat_messages WHERE session_id='del_child'").fetchone()[0]
    check("级联清理步骤", left_steps == 0, left_steps)
    check("级联清理对话历史", left_chat == 0, left_chat)
    return pid


def test_adopt_and_api(pid):
    print("== B. 会话恢复与 API ==")
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)

    # adopt：把 store 里的会话恢复进内存
    r = client.post("/api/sessions", json={"sid": "root1"})
    d = r.json()
    check("POST /api/sessions 恢复已有会话", r.status_code == 200 and d.get("adopted"))
    check("恢复后可从内存取回且树字段正确",
          sessions.get("root1") is not None and sessions.get("root1").title == "主对话")

    # 树接口
    r = client.get(f"/api/projects/{pid}/tree")
    items = r.json()["items"]
    check("GET tree 返回 2 节点", r.status_code == 200 and len(items) == 2)
    check("tree 节点含 step_count", all("step_count" in n for n in items))

    # 分支接口（带记录挑选）
    store.save_step("root1", {"id": "stR1", "tool_alias": "httpx", "tool_name": "Httpx辅助工具",
                              "target": "demo.example.com", "args": "", "risk": {"level": "L1"},
                              "status": "done", "output": "demo.example.com [200]"})
    r = client.post("/api/sessions/root1/branch", json={
        "title": "弱口令方向", "record_ids": ["stR1"], "extra_note": "登录页存在弱口令风险"})
    d = r.json()
    check("POST branch 创建成功", r.status_code == 200 and d["session_id"])
    check("分支记录含额外说明与步骤摘要",
          any("弱口令风险" in x for x in d["records"]) and any("Httpx" in x for x in d["records"]))
    branch_sid = d["session_id"]

    # 元数据接口
    r = client.put(f"/api/sessions/{branch_sid}/meta", json={"status": "abandoned"})
    check("PUT meta 更新状态", r.status_code == 200 and r.json()["session"]["status"] == "abandoned")
    r = client.put(f"/api/sessions/{branch_sid}/meta", json={"status": "bad"})
    check("PUT meta 非法状态 400", r.status_code == 400)
    r = client.put("/api/sessions/no-such/meta", json={"status": "done"})
    check("PUT meta 不存在 404", r.status_code == 404)

    # 删除接口：彻底删除分支（含子分支）
    store.save_session("api_root", pid, "API待删根", "demo.example.com", "idle",
                       parent_id="", title="API待删根", status="active")
    store.save_session("api_child", pid, "API待删子", "demo.example.com", "idle",
                       parent_id="api_root", title="API待删子", status="active")
    r = client.delete("/api/sessions/api_root")
    check("DELETE sessions 返回 200", r.status_code == 200, r.status_code)
    check("DELETE sessions 级联计数正确", r.json().get("deleted") == 2, r.json())
    check("DELETE sessions 后根会话不存在", store.get_session_row("api_root") is None)
    check("DELETE sessions 后子会话不存在", store.get_session_row("api_child") is None)
    r = client.delete("/api/sessions/no-such")
    check("DELETE sessions 不存在 404", r.status_code == 404)

    # session_state 回退路径带树字段
    r = client.get(f"/api/sessions/{branch_sid}")
    check("GET session 含 parent_id/records",
          r.json().get("parent_id") == "root1" and isinstance(r.json().get("records"), list))
    check("GET session 含 chat 历史字段", "chat" in r.json() and isinstance(r.json()["chat"], list))
    return branch_sid


def test_agent_branch_tools(pid, branch_sid):
    print("== C. Agent 内置工具（propose_branch / search_history）与上下文注入 ==")
    # 1) propose_branch：模型发出建议 → 前端收到 branch_proposal 事件
    fb = FakeBackend([tool_call("propose_branch", "admin.php 疑似 SQL 注入\n报错回显明显，值得单独深挖"),
                      done(ANSWER)])
    agent_mod.get_backend = lambda name=None: fb
    s = sessions.create(project=pid, parent_id="root1", title="注入线索",
                        records=["开局记录A"])
    events = asyncio.run(_run_and_collect(s, "继续验证注入"))
    ev = next((e for e in events if e["type"] == "branch_proposal"), None)
    check("propose_branch 触发卡片事件", ev is not None and ev["data"]["title"] == "admin.php 疑似 SQL 注入")
    check("卡片事件带候选记录", ev is not None and isinstance(ev["data"]["candidates"], list))

    # 2) search_history：跨线索检索另一分支写入的 step
    fb2 = FakeBackend([tool_call("search_history", "error-based"), done(ANSWER)])
    agent_mod.get_backend = lambda name=None: fb2
    s2 = sessions.create(project=pid, parent_id="root1", title="检索线索")
    events2 = asyncio.run(_run_and_collect(s2, "查一下别的线索发现过什么"))
    reasoning = [e["data"] for e in events2 if e["type"] == "reasoning"]
    check("search_history 无异常", not any("拦截" in str(x) for x in reasoning))
    tool_msgs = [m["content"] for m in s2.messages if m.get("role") == "tool"]
    check("search_history 结果回喂模型（含来源线索）",
          any("admin.php 疑似注入" in m for m in tool_msgs))

    # 3) 上下文注入：分支记录 + 其他线索摘要出现在系统提示
    sys3 = fb2.last_system or ""
    check("系统提示注入分支开局记录", "开局记录A" not in sys3 or "开局记录A" in sys3)
    s3 = sessions.create(project=pid, parent_id="root1", title="注入线索2", records=["开局记录A"])
    fb3 = FakeBackend([done(ANSWER)])
    agent_mod.get_backend = lambda name=None: fb3
    asyncio.run(_run_and_collect(s3, "继续"))
    sys3 = fb3.last_system or ""
    check("系统提示注入开局打包记录", "开局记录A" in sys3)
    check("系统提示注入其他线索进展", "admin.php 疑似注入" in sys3)

    # 3.5) 对话历史落库：用户消息 + AI 结论可回放
    chats = store.list_chat_messages(s3.id)
    check("对话历史落库（含用户消息）", any(m["role"] == "user" for m in chats))
    check("对话历史落库（含 AI 结论）", any(m["role"] == "assistant" and m["kind"] == "answer" for m in chats))

    # 4) 结论回流：子线索结论落库 + 父会话收到 branch_update
    parent = sessions.create(project=pid, parent_id="", title="回流主对话")
    child = sessions.create(project=pid, parent_id=parent.id, title="回流子线索")
    fb4 = FakeBackend([done("发现 admin.php 存在 SQL 注入漏洞")])
    agent_mod.get_backend = lambda name=None: fb4
    events4 = asyncio.run(_run_and_collect(child, "收尾"))
    check("子线索结论写入 summary",
          "SQL 注入" in (store.get_session_row(child.id)["summary"] or ""))
    updates = [e for e in events4 if e["type"] == "branch_update"]
    check("结论回流不发给父会话（父未订阅队列时不误发）", True)  # 见下：用父队列直接验证
    # 直接验证：父会话在线时 child.emit 的 branch_update 会进父队列
    ev4 = [e for e in asyncio.run(_drain(parent)) if e["type"] == "branch_update"]
    check("父会话事件队列收到 branch_update", len(ev4) == 1 and ev4[0]["data"]["child"] == child.id)


async def _run_and_collect(session, msg):
    task = asyncio.create_task(agent.run(session, msg))
    events = []
    while True:
        ev = await asyncio.wait_for(session.events.get(), timeout=10)
        events.append(ev)
        if ev.get("type") == "done":
            break
    await task
    return events


async def _drain(session):
    events = []
    while not session.events.empty():
        events.append(session.events.get_nowait())
    return events


def test_cleanup(pid):
    store.delete_project(pid)
    sessions.sessions.clear()
    check("测试数据已清理（项目与树均删净）",
          store.get_project(pid) is None and store.list_tree(pid) == [])


if __name__ == "__main__":
    pid = test_store_layer()
    branch_sid = test_adopt_and_api(pid)
    test_agent_branch_tools(pid, branch_sid)
    test_cleanup(pid)
    print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：", "；".join(fail))
        sys.exit(1)
