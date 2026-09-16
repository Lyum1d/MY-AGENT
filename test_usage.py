# -*- coding: utf-8 -*-
"""Token 用量统计回归：落库 / 汇总聚合 / 单价表 / API / 清理导出。

不联网（FakeBackend 提供 usage）、不碰任何目标资产；数据库落在临时目录。
"""
import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config                                    # noqa: E402
from app import providers, store                          # noqa: E402
from app import agent as agent_mod                        # noqa: E402
from app import usage                                     # noqa: E402
from app.agent import agent, sessions                     # noqa: E402
from app.registry import registry                         # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_usage_test_"))
store.DB_PATH = _TMP / "test_usage.db"
config.LLM_PROVIDERS_FILE = _TMP / "providers_test.json"
config.USAGE_PRICES_FILE = _TMP / "usage_prices.json"
usage.PRICES_FILE = config.USAGE_PRICES_FILE
providers.invalidate()
store.init_db()
registry.load()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


class FakeBackend:
    """第 1 轮调 note_fact（带 usage），第 2 轮直接给结论。"""
    name = "model-studio"
    label = "测试云"
    model = "qwen3.7-plus"
    local = False

    def __init__(self):
        self.calls = 0

    def available(self):
        return True

    async def health(self):
        return {"ready": True}

    async def chat(self, messages, tools=None):
        self.calls += 1
        if self.calls == 1:
            return {
                "tool_calls": [{"id": "c1", "type": "function",
                                "function": {"name": "note_fact",
                                             "arguments": json.dumps({"args": "用量测试事实"}, ensure_ascii=False)}}],
                "content": "记录事实",
                "usage": {"prompt": 1000, "completion": 200},
            }
        return {"tool_calls": [], "content": "USAGE-OK：统计完成",
                "usage": {"prompt": 800, "completion": 500}}


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


def test_collect_and_summary():
    print("== A. 采集与汇总 ==")
    proj = store.create_project("用量测试项目", "demo.example.com", "跑完即删")
    pid = proj["id"]
    fb = FakeBackend()
    agent_mod.get_backend = lambda name=None: fb
    s = sessions.create(project=pid)
    asyncio.run(run_collect(s, "测试用量统计"))

    rows = store.list_usage()
    # note_fact 1 次 + 收尾结论 1 次 = 2 次模型调用（收尾免催促：干过活不再催 2 次）
    check("2 次模型调用均落库（收尾免催促）", len(rows) == 2, len(rows))
    check("记录含 provider/model/项目/会话",
          rows[0]["provider_id"] == "model-studio" and rows[0]["model"] == "qwen3.7-plus"
          and rows[0]["project_id"] == pid and rows[0]["session_id"] == s.id)
    check("token 数正确（1000/200 + 800/500 各一次）",
          {r["prompt_tokens"] for r in rows} == {1000, 800}
          and {r["completion_tokens"] for r in rows} == {200, 500})
    check("耗时已记录", all(r["duration_ms"] >= 0 for r in rows))

    # 单价：默认 qwen3.7-plus → 输入 0.8 / 输出 2.0（元/百万）
    total_tokens = sum(r["prompt_tokens"] + r["completion_tokens"] for r in rows)
    expected_cost = (1000 * 0.8 + 200 * 2.0 + 800 * 0.8 + 500 * 2.0) / 1_000_000
    sm = usage.summary()
    check("汇总 tokens 一致", sm["total"]["tokens"] == total_tokens, sm["total"]["tokens"])
    check("费用按输入/输出分开估算", abs(sm["total"]["cost"] - expected_cost) < 5e-5,
          f"{sm['total']['cost']} vs {expected_cost}")
    check("今日汇总与累计一致（新库）", sm["today"]["tokens"] == sm["total"]["tokens"])
    check("分模型聚合存在", "model-studio:qwen3.7-plus" in sm["by_model"])
    check("分项目聚合存在", pid in sm["by_project"])
    daily = usage.daily(days=3)
    check("按天聚合返回 3 天（含补 0）", len(daily) == 3 and sum(d["tokens"] for d in daily) == total_tokens)
    return pid


def test_prices():
    print("== B. 单价表 ==")
    p = usage._load_prices()
    check("预填单价表存在（qwen3.7-plus/deepseek-chat/ollama）",
          "qwen3.7-plus" in p and "deepseek-chat" in p and p["ollama"]["input"] == 0)
    usage.save_prices({"custom-model": {"input": 1.5, "output": 6.0}})
    p2 = usage._load_prices()
    check("保存自定义单价", p2.get("custom-model", {}).get("input") == 1.5)
    d = usage.reset_prices()
    check("恢复默认", "custom-model" not in d and "qwen3.7-plus" in d)
    # 未配置单价的模型：token 统计、费用 0
    store.save_usage("some-provider", "unknown-model", 1000, 1000)
    sm = usage.summary()
    unknown = sm["by_model"].get("some-provider:unknown-model", {})
    check("未知模型费用按 0 计", unknown.get("cost") == 0 and unknown.get("tokens") == 2000)


def test_api(pid):
    print("== C. API ==")
    from fastapi.testclient import TestClient
    from app.main import app
    # base_url 用回环地址：app.main 的本地访问防护会校验 Host，
    # TestClient 默认的 testserver 会被判为「非本机 Host」而拒绝。
    client = TestClient(app, base_url="http://127.0.0.1")
    r = client.get("/api/usage/summary")
    check("GET summary", r.status_code == 200 and r.json()["total"]["calls"] > 0)
    r = client.get("/api/usage/daily?days=7")
    check("GET daily", r.status_code == 200 and len(r.json()["items"]) == 7)
    r = client.get(f"/api/usage/list?project_id={pid}")
    check("GET list 按项目过滤", r.status_code == 200 and len(r.json()["items"]) == 2)
    r = client.get("/api/usage/prices")
    check("GET prices", r.status_code == 200 and "qwen3.7-plus" in r.json()["items"])
    r = client.post("/api/usage/prices", json={"prices": {"qwen3.7-plus": {"input": 1.0, "output": 3.0}}})
    check("POST prices", r.status_code == 200 and r.json()["items"]["qwen3.7-plus"]["input"] == 1.0)
    r = client.post("/api/usage/prices/reset")
    check("POST prices/reset", r.status_code == 200 and r.json()["items"]["qwen3.7-plus"]["input"] == 0.8)
    r = client.get("/api/usage/export.csv")
    check("GET export.csv（UTF-8 BOM）", r.status_code == 200 and r.content[:3] == b"\xef\xbb\xbf")
    r = client.post("/api/usage/clear", json={"days": 0})
    check("POST clear 清空", r.status_code == 200 and store.list_usage() == [])


def test_cleanup(pid):
    store.delete_project(pid)
    sessions.sessions.clear()
    check("测试数据已清理", store.get_project(pid) is None)


if __name__ == "__main__":
    pid = test_collect_and_summary()
    test_prices()
    test_api(pid)
    test_cleanup(pid)
    print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：", "；".join(fail))
        sys.exit(1)
