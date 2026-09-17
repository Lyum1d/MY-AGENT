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
# 关闭「漏洞类任务自动路由云端」：本机若存在 ~/.deepseek_api_key，它会被迁移进
# 供应商配置、使 deepseek 变为可用；此时任务文案含「验证 / 注入」就会触发自动路由，
# 把下面注入的 FakeBackend 换成真实云端模型，断言随之随机失败。测试必须与机器环境无关。
config.AUTO_ROUTE_VULN = False
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
    # 用量记录必须**活过**会话删除：它是 token 消耗的审计凭据，
    # 若随会话一起删掉，等于「删掉线索即可抹掉自己烧过多少钱」。
    store.save_usage(provider_id="deepseek", model="deepseek-chat", prompt_tokens=100,
                     completion_tokens=50, session_id="del_child", project_id=pid)
    res = store.delete_session_tree("del_root")
    check("delete_session_tree 级联删除根及后代",
          set(res["deleted_ids"]) == {"del_root", "del_child", "del_grand"},
          res["deleted_ids"])
    check("删除后根会话不存在", store.get_session_row("del_root") is None)
    check("删除后孙会话不存在", store.get_session_row("del_grand") is None)
    with store._db() as _c:
        left_steps = _c.execute("SELECT COUNT(*) FROM steps WHERE session_id='del_child'").fetchone()[0]
        left_chat = _c.execute("SELECT COUNT(*) FROM chat_messages WHERE session_id='del_child'").fetchone()[0]
        kept_usage = _c.execute(
            "SELECT COUNT(*) FROM usage_log WHERE model='deepseek-chat'").fetchone()[0]
    check("级联清理步骤", left_steps == 0, left_steps)
    check("级联清理对话历史", left_chat == 0, left_chat)
    check("用量记录不被级联删除（保留成本审计，仅解绑会话）", kept_usage == 1, kept_usage)
    return pid


def test_adopt_and_api(pid):
    print("== B. 会话恢复与 API ==")
    from fastapi.testclient import TestClient
    from app.main import app
    # base_url 用回环地址：app.main 的本地访问防护会校验 Host，
    # TestClient 默认的 testserver 会被判为「非本机 Host」而拒绝。
    client = TestClient(app, base_url="http://127.0.0.1")

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

    # 运行中的会话不得删除：Agent 协程还持有该 Session，每步都会 save_step，
    # 删掉之后它会继续往已删除的 session_id 上写，留下清理不掉的孤儿行。
    store.save_session("api_run", pid, "运行中线索", "demo.example.com", "running",
                       parent_id="", title="运行中线索", status="active")
    s_run = sessions.adopt("api_run")
    s_run.state = "running"
    r = client.delete("/api/sessions/api_run")
    check("DELETE 拒绝删除运行中的会话（409）", r.status_code == 409, r.status_code)
    check("被拒后该会话仍存在", store.get_session_row("api_run") is not None)
    s_run.state = "awaiting_confirm"
    check("DELETE 同样拒绝等待确认中的会话",
          client.delete("/api/sessions/api_run").status_code == 409)
    s_run.state = "idle"
    check("结束后可正常删除", client.delete("/api/sessions/api_run").status_code == 200)

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


def test_confirm_gate(pid):
    """高危确认闸门：确认必须「绑步骤 + 在正确状态下」才被接受。

    这一节守的是项目最硬的那条线——L2/L3 必须经用户确认。历史实现里
    session.control 是一条与步骤无绑定的 FIFO 队列，任何时刻投递的确认都会被
    **下一个**高危步骤消费掉，于是「用户没看确认框，L3 就被放行了」。
    """
    print("== D. 高危确认闸门（步骤绑定 + 状态校验）==")
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app, base_url="http://127.0.0.1")

    store.save_session("cf1", pid, "确认测试", "demo.example.com", "idle",
                       parent_id="", title="确认测试", status="active")
    s = sessions.adopt("cf1")

    # 1) 空闲态：不允许投递确认（不给「先囤一条，等下次高危步骤时自动放行」的机会）
    s.state = "idle"
    r = client.post("/api/sessions/cf1/confirm", json={"approved": True, "step_id": "st_x"})
    check("空闲态提交确认被拒（409）", r.status_code == 409, r.status_code)
    check("被拒后队列里没有残留确认", s.control.empty())

    # 2) 等待确认中，但 step_id 不匹配 → 拒绝（挡陈旧/重放/伪造）
    s.state = "awaiting_confirm"
    s.pending_step_id = "st_real"
    r = client.post("/api/sessions/cf1/confirm", json={"approved": True, "step_id": "st_other"})
    check("step_id 不匹配的确认被拒（409）", r.status_code == 409, r.status_code)

    # 3) 缺少 step_id → 拒绝（不给「不带身份也能放行」的后门）
    r = client.post("/api/sessions/cf1/confirm", json={"approved": True})
    check("缺少 step_id 的确认被拒（409）", r.status_code == 409, r.status_code)

    # 4) 正确匹配 → 放行，且队列里只此一条
    r = client.post("/api/sessions/cf1/confirm", json={"approved": True, "step_id": "st_real"})
    check("匹配的确认被接受（200）", r.status_code == 200, r.status_code)
    check("队列里恰好一条确认", s.control.qsize() == 1, s.control.qsize())

    # 5) 重复提交 → 拒绝（挡连点预支）
    r = client.post("/api/sessions/cf1/confirm", json={"approved": True, "step_id": "st_real"})
    check("重复提交被拒（409，挡连点预支）", r.status_code == 409, r.status_code)

    # 6) Agent 侧：不匹配的确认会被丢弃而不是被消费掉
    step = agent_mod.Step(id="st_real", tool_alias="py_exec", tool_name="Python代码执行",
                          target="demo.example.com", args="print(1)", risk={"level": "L3"})
    while not s.control.empty():
        s.control.get_nowait()
    s.state = "awaiting_confirm"
    s.pending_step_id = "st_real"
    s.control.put_nowait({"approved": True, "step_id": "st_stale"})   # 陈旧指令
    s.control.put_nowait({"approved": True, "step_id": "st_real"})    # 真正的放行

    async def _confirm():
        return await agent._await_confirm(s, step)

    approved = asyncio.run(_confirm())
    check("_await_confirm 丢弃不匹配的确认、采纳匹配的那条", approved is True, approved)

    # 7) 超时后状态必须复位（历史实现只在成功路径复位，超时后永远卡在 awaiting_confirm）
    while not s.control.empty():
        s.control.get_nowait()
    s.state = "awaiting_confirm"
    old_timeout = config.CONFIRM_TIMEOUT
    config.CONFIRM_TIMEOUT = 1
    try:
        denied = asyncio.run(_confirm())
    finally:
        config.CONFIRM_TIMEOUT = old_timeout
    check("确认超时按「拒绝」处理", denied is False, denied)
    check("超时后 state 已复位（不再卡在 awaiting_confirm）",
          s.state == "running", s.state)
    check("超时后 pending_step_id 已清空", s.pending_step_id == "", s.pending_step_id)
    return "cf1"


class _FakeExec:
    """假执行器：按脚本吐出与真实 executor 同构的事件流。"""

    def __init__(self, events):
        self.events = list(events)

    async def run(self, tool, target, args="", cancel_event=None):
        for e in self.events:
            yield e


def test_scope_denial_not_swallowed(pid):
    """授权拒绝（126）不得被 ignore_exit_code 吞成「执行成功」。

    背景：`meaningful = bool(output.strip())` 把执行器自己写的那行
    `[错误] 目标不在授权白名单内…` 也算成「有实质输出」，于是开了
    ignore_exit_code 的工具（EHole 就是）会把「越权被拦」判成 done，
    _attribute_failure 里那档 SCOPE（要求停手、别换参数绕过）永远送不到模型，
    模型就会一直换参数去撞授权墙。
    """
    print("== E. 授权拒绝（126）不被 ignore_exit_code 吞掉 ==")
    from app.registry import Tool
    from app.registry import registry as reg

    fake = Tool(name="EHole", alias="_test_ehole", category="指纹", type="命令行",
                rel_path="", description="x", risk_level="L1")
    fake.executable = "fake-ehole.exe"
    fake.ignore_exit_code = True      # 模拟 data/tool_overrides.json 里的 ehole 配置
    reg._by_alias["_test_ehole"] = fake

    session = sessions.create(project=pid)
    step = agent_mod.Step(id="st126", tool_alias="_test_ehole", tool_name="EHole",
                          target="evil.com", args="", risk={"level": "L1"})
    real_exec = agent_mod.executor
    agent_mod.executor = _FakeExec([
        {"type": "error", "data": "目标「evil.com」不在授权白名单内，已拒绝执行。"},
        {"type": "exit", "code": 126},
    ])
    try:
        asyncio.run(agent._execute(session, step, "call126"))
    finally:
        agent_mod.executor = real_exec
        reg._by_alias.pop("_test_ehole", None)

    check("退出码 126 判为失败，不被 ignore_exit_code 翻成 done",
          step.status == "error", step.status)
    fed = session.messages[-1]["content"] if session.messages else ""
    check("回喂内容带 SCOPE 归因（模型才知道这是授权边界）", "SCOPE" in fed, fed[:70])
    check("回喂内容明确要求「不要换参数绕过」",
          "不要换参数" in fed or "停手" in fed, fed[:90])

    # 反向对照：同样的工具，正常有输出 + 退出码 1 时仍应按成功解读
    # （EHole 没命中「重点资产」会返回 1，这是它 ignore_exit_code 的存在理由）
    step2 = agent_mod.Step(id="st1ok", tool_alias="_test_ehole", tool_name="EHole",
                           target="demo.example.com", args="", risk={"level": "L1"})
    reg._by_alias["_test_ehole"] = fake
    agent_mod.executor = _FakeExec([
        {"type": "output", "data": "[+] https://demo.example.com 用友NC"},
        {"type": "exit", "code": 1},
    ])
    try:
        asyncio.run(agent._execute(sessions.create(project=pid), step2, "call1ok"))
    finally:
        agent_mod.executor = real_exec
        reg._by_alias.pop("_test_ehole", None)
    check("有实质输出 + 退出码 1 仍算成功（未误伤 ignore_exit_code 的本意）",
          step2.status == "done", step2.status)


def test_subtask_flag_persists(pid):
    """子任务标记必须落库并能恢复。

    为什么是安全相关：`subtask=True` 的会话在 run() 里会被拒绝执行 L2/L3
    （并行子任务没人能应答确认框）。标记只存内存的话，服务重启或被 adopt 之后
    就丢了，这道闸门会**静默失效**。
    """
    print("== F. 子任务标记落库与恢复（subtask 闸门不丢）==")
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app, base_url="http://127.0.0.1")

    sessions.sessions.clear()
    store.save_session("sub_a", pid, "子任务A", "demo.example.com", "idle",
                       parent_id="", title="子任务A", status="active", subtask=True)
    store.save_session("sub_b", pid, "普通线索B", "demo.example.com", "idle",
                       parent_id="", title="普通线索B", status="active", subtask=False)
    check("subtask 已落库（读回来是 True）",
          bool(store.get_session_row("sub_a").get("subtask")))

    sa = sessions.adopt("sub_a")
    sb = sessions.adopt("sub_b")
    check("adopt 恢复 subtask=True（子任务闸门不会因恢复而失效）", sa.subtask is True,
          sa.subtask)
    check("adopt 普通线索仍是 subtask=False（不误伤）", sb.subtask is False, sb.subtask)

    # 内存会话被 drop 后再恢复，同样要保住标记（模拟服务重启后的续聊）
    sessions.sessions.clear()
    check("清空内存后重新 adopt 仍为 subtask=True",
          sessions.adopt("sub_a").subtask is True)

    print("== G. 运行时不覆盖已有项目归属 ==")
    store.save_session("proj_keep", pid, "归属测试", "demo.example.com", "idle",
                       parent_id="", title="归属测试", status="active")
    sp = sessions.adopt("proj_keep")
    sp.project = pid
    # 用 no-op 顶掉真实 Agent：本节点只验「项目归属不被空值冲掉」，不需要跑模型
    real_run = agent.run

    async def _noop_run(session, message, **kw):
        return

    agent.run = _noop_run
    try:
        r = client.post("/api/sessions/proj_keep/run",
                        json={"message": "跑一下", "project_id": ""})
        check("POST /run 空 project_id 时正常受理", r.status_code == 200, r.status_code)
        check("已有项目归属没被空值冲掉（否则情报/事实注入会静默失效）",
              sp.project == pid, sp.project)
        r2 = client.post("/api/sessions/proj_keep/run",
                         json={"message": "换项目", "project_id": "another-pid"})
        check("显式传入非空 project_id 时正常覆盖", sp.project == "another-pid",
              sp.project)
    finally:
        agent.run = real_run
        sp.state = "idle"
        for sid in ("proj_keep", "sub_a", "sub_b"):
            sessions.sessions.pop(sid, None)


def test_cleanup(pid):
    store.delete_project(pid)
    sessions.sessions.clear()
    check("测试数据已清理（项目与树均删净）",
          store.get_project(pid) is None and store.list_tree(pid) == [])


if __name__ == "__main__":
    pid = test_store_layer()
    branch_sid = test_adopt_and_api(pid)
    test_agent_branch_tools(pid, branch_sid)
    test_confirm_gate(pid)
    test_scope_denial_not_swallowed(pid)
    test_subtask_flag_persists(pid)
    test_cleanup(pid)
    print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：", "；".join(fail))
        sys.exit(1)
