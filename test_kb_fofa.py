# -*- coding: utf-8 -*-
"""知识库（kb）/ 工作流规则 / FOFA 测绘工具回归。

不联网（FOFA 未配置走优雅报错路径）、不碰任何目标资产；数据库落在临时目录。
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
from app import fofa, kb                                  # noqa: E402
from app.agent import agent, sessions                     # noqa: E402
from app.registry import registry                         # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_kb_test_"))
store.DB_PATH = _TMP / "test_kb.db"
config.LLM_PROVIDERS_FILE = _TMP / "providers_test.json"
# v012：fofa_search 增加授权约束（查询词必须含白名单主机）——本套件必须
# 改道 SCOPE_FILE 到临时文件并放行 example.com，否则会依赖本机真实
# data/scope.json（里面有真实授权靶标、没有 example.com），测试既脆弱又危险。
config.SCOPE_FILE = _TMP / "scope_test.json"
config.SCOPE_FILE.write_text('{"domains": ["example.com"]}', encoding="utf-8")
providers.invalidate()
store.init_db()
registry.load()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


class FakeBackend:
    name = "ollama"
    label = "本地 Ollama"
    model = "fake-kb-model"
    local = True

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0
        self.last_system = ""

    def available(self):
        return True

    async def health(self):
        return {"ready": True}

    async def chat(self, messages, tools=None):
        self.calls += 1
        self.last_system = messages[0]["content"] if messages else ""
        return self.script[min(self.calls - 1, len(self.script) - 1)]


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


async def run_collect(session, msg):
    task = asyncio.create_task(agent.run(session, msg))
    events = []
    while True:
        ev = await asyncio.wait_for(session.events.get(), timeout=15)
        events.append(ev)
        if ev.get("type") == "done":
            break
    await task
    return events


def test_kb_layer():
    print("== A. 知识库数据层 ==")
    topics = kb.list_topics()
    check("篇目总数 ≥ 60（kb 49 + rules 11）", len(topics) >= 60, len(topics))
    check("kb 与 rules 两个分类都在", {t["category"] for t in topics} == {"kb", "rules"})
    check("打穿短表 存在", any(t["file"] == "打穿短表.md" for t in topics))
    check("vuln-report-format 存在于 rules", any(t["file"] == "vuln-report-format.md" and t["category"] == "rules" for t in topics))
    hits = kb.search("越权")
    check("关键词检索命中 idor-test", any(h["file"] == "idor-test.md" for h in hits))
    check("文件名命中加权排序", hits and hits[0]["score"] >= 10)
    check("空关键词返回空", kb.search("") == [])
    r = kb.read("打穿短表")
    check("kb_read 读取全文", "content" in r and len(r["content"]) > 200)
    r2 = kb.read("vuln-report-format")
    check("跨目录读 rules 篇目", r2.get("file", "").startswith("rules/"))
    r3 = kb.read("../../etc/passwd")
    check("路径穿越被拦截", "error" in r3)
    r4 = kb.read("不存在的篇目xyz")
    check("不存在篇目返回错误提示", "error" in r4 and "list" in r4["error"])


def test_tools_registered():
    print("== B. 工具注册 ==")
    for alias in ("kb_search", "kb_read", "fofa_search"):
        t = registry.get_by_alias(alias)
        check(f"{alias} 已注册为内置工具", t is not None and t.type == "内置")
    check("kb_search L0", registry.get_by_alias("kb_search").risk_level == "L0")
    check("fofa_search L1", registry.get_by_alias("fofa_search").risk_level == "L1")
    schemas = {s["function"]["name"] for s in registry.build_schemas()}
    check("三个工具都进 function calling schema", {"kb_search", "kb_read", "fofa_search"} <= schemas)


def test_agent_flow(pid):
    print("== C. Agent 实际调用 ==")
    fb = FakeBackend([
        tool_call("kb_search", "list"),
        tool_call("kb_read", "打穿短表"),
        tool_call("fofa_search", 'domain="example.com"'),
        done("KB-OK"),
    ])
    agent_mod.get_backend = lambda name=None: fb
    s = sessions.create(project=pid)
    events = asyncio.run(run_collect(s, "测试知识库工具链"))
    tool_msgs = [m["content"] for m in s.messages if m.get("role") == "tool"]
    check("kb_search list 返回篇目目录", any("知识库共" in m for m in tool_msgs))
    check("kb_read 返回全文", any("【kb/打穿短表.md】" in m for m in tool_msgs))
    check("fofa_search 未配置时优雅报错", any("FOFA 未配置" in m for m in tool_msgs))
    check("系统提示包含知识库工作流", "打穿短表" in (fb.last_system or "") and "一种子闭环" in (fb.last_system or ""))
    check("系统提示包含安全红线", "严禁登出" in (fb.last_system or "") and "CORS 永不挖" in (fb.last_system or ""))


def test_cleanup(pid):
    store.delete_project(pid)
    sessions.sessions.clear()
    check("测试数据已清理", store.get_project(pid) is None)


if __name__ == "__main__":
    import json  # noqa: F401  tool_call 需要
    pid = store.create_project("KB测试项目", "demo.example.com", "跑完即删")["id"]
    test_kb_layer()
    test_tools_registered()
    test_agent_flow(pid)
    test_cleanup(pid)
    print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：", "；".join(fail))
        sys.exit(1)
