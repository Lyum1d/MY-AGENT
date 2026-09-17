# -*- coding: utf-8 -*-
"""v011 可靠性回归：事件落库与重放 / 取消 / 因果图幂等 / LLM 重试与故障转移。

    python test_reliability.py

数据库与供应商配置改道临时目录，不联网、不碰真实目标。
"""
import asyncio
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_rely_test_"))
config.DATA_DIR = _TMP
config.LLM_PROVIDERS_FILE = _TMP / "providers.json"
config.RUN_TIME_BUDGET = 0          # 测试不触发时间熔断
config.RUN_TOKEN_BUDGET = 10**9     # 不触发 token 熔断

import importlib                                     # noqa: E402
from app import store, providers                     # noqa: E402
importlib.reload(store)                              # DB_PATH → 临时目录
store.DB_PATH = _TMP / "projects.db"
from app import graph, llm                           # noqa: E402
from app import agent as agent_mod                   # noqa: E402
from app.agent import agent, sessions                # noqa: E402
from app.registry import registry                    # noqa: E402

registry.load()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


# ---------------------------------------------------------------------------
print("== A. 事件表（v011 P1-5）==")
sid = "relysess01"
seq1 = store.save_event(sid, {"type": "session_start", "data": "start"})
seq2 = store.save_event(sid, {"type": "reasoning", "data": "中间步骤"})
seq3 = store.save_event(sid, {"type": "done", "state": "done"})
check("事件 seq 单调递增", 0 < seq1 < seq2 < seq3, f"{seq1},{seq2},{seq3}")
check("last_event_seq 与最后一条一致", store.last_event_seq(sid) == seq3)
evs = store.list_events(sid, since_seq=0)
check("全量回放 3 条且带 _seq", len(evs) == 3 and all(e.get("_seq") for e in evs))
evs2 = store.list_events(sid, since_seq=seq1)
check("since_seq 增量回放（跳过 seq1）",
      len(evs2) == 2 and evs2[0]["_seq"] == seq2)
check("payload 往返无损", evs2[0]["data"] == "中间步骤")
check("空会话 last_event_seq=0", store.last_event_seq("no-such") == 0)

print("== B. Session.emit 落库与 _seq 回填 ==")
async def _emit_case():
    s = agent_mod.Session(id="emitsess01")
    await s.emit({"type": "session_start", "data": "x"})
    await s.emit({"type": "reasoning", "data": "y"})
    return s
_s = asyncio.run(_emit_case())
check("emit 后 last_seq > 0", _s.last_seq > 0)
qev = _s.events.get_nowait()
check("队列事件带 _seq（重放去重依据）", isinstance(qev.get("_seq"), int), qev)
check("emit 落库可回放", len(store.list_events("emitsess01")) == 2)

print("== C. 因果图：UNKNOWN 标签 + 幂等传播（v011 P1-4）==")
pid = store.create_project("可靠性测试项目", "example.com")["id"]
graph.apply_updates(pid, {"nodes": [
    {"id": "ev1", "node_type": "Evidence", "title": "证据1"},
    {"id": "fact1", "node_type": "KeyFact", "title": "事实1", "confidence": 0.3},
]})
# 未知标签：旧行为归成 SUPPORTS 并 +0.4；新行为 UNKNOWN 且不动置信度
graph.apply_updates(pid, {"edges": [
    {"source_id": "ev1", "target_id": "fact1", "label": "MADE_UP_LABEL"}]})
n = store.get_causal_node(pid, "fact1")
check("未知标签 → UNKNOWN 落库",
      any(e["label"] == "UNKNOWN" for e in graph.build_causal_graph(pid)["edges"]))
check("未知标签不改置信度", abs(n["confidence"] - 0.3) < 1e-6, n["confidence"])
# SUPPORTS 首次传播 +0.4（logit 空间）
graph.apply_updates(pid, {"edges": [
    {"source_id": "ev1", "target_id": "fact1", "label": "SUPPORTS"}]})
n1 = store.get_causal_node(pid, "fact1")["confidence"]
check("SUPPORTS 新边传播一次", n1 > 0.3, f"0.3→{n1:.3f}")
# 重复提交同一条边：不重复加分
graph.apply_updates(pid, {"edges": [
    {"source_id": "ev1", "target_id": "fact1", "label": "SUPPORTS"}]})
graph.apply_updates(pid, {"edges": [
    {"source_id": "ev1", "target_id": "fact1", "label": "SUPPORTS"}]})
n2 = store.get_causal_node(pid, "fact1")["confidence"]
check("重复边不再重复加分（幂等）", abs(n2 - n1) < 1e-9, f"{n1:.4f}→{n2:.4f}")
edges = store.list_causal_edges(pid)
check("同一三元组仍只存一条边", len([e for e in edges
      if e["source_id"] == "ev1" and e["label"] == "SUPPORTS"]) == 1)

print("== D. LLM 重试判定与故障转移（v011 P1-6）==")
import httpx
check("429 可重试", llm.is_retryable_error(
    httpx.HTTPStatusError("x", request=httpx.Request("POST", "http://x"),
                          response=httpx.Response(429))))
check("502 可重试", llm.is_retryable_error(
    httpx.HTTPStatusError("x", request=httpx.Request("POST", "http://x"),
                          response=httpx.Response(502))))
check("401 不可重试（Key 无效重试无意义）", not llm.is_retryable_error(
    httpx.HTTPStatusError("x", request=httpx.Request("POST", "http://x"),
                          response=httpx.Response(401))))
check("连接失败可重试", llm.is_retryable_error(httpx.ConnectError("refused")))
check("超时可重试", llm.is_retryable_error(httpx.ReadTimeout("t/o")))
check("配置类错误不可重试", not llm.is_retryable_error(RuntimeError("未配置 Key")))

# failover_backend：隔离 providers 后注册两个可用供应商
# （注意：providers.upsert 会归一化 id——'provA' 落库成 'a'，因此用实际 id 断言）
providers.invalidate()
providers.upsert({"id": "provA", "name": "A", "type": "openai", "enabled": True,
                  "local": False, "base_url": "https://a.example/v1",
                  "model": "m", "api_key": "k"})
providers.upsert({"id": "provB", "name": "B", "type": "openai", "enabled": True,
                  "local": True, "base_url": "http://localhost:11434/v1",
                  "model": "m"})
_all_ids = [p.get("id") for p in providers.cfg().get("providers", [])]
_id_a = next(i for i in _all_ids if i and i.endswith("a") and i != "ollama")
_id_b = next(i for i in _all_ids if i and i.endswith("b"))
fb = llm.failover_backend([_id_a])
check("故障转移跳过被排除的供应商", fb is not None and fb.name != _id_a,
      fb.name if fb else None)
# 全部排除（含内置 ollama/deepseek/anthropic）后应无候选
check("故障转移找不到候选时返回 None",
      llm.failover_backend([_id_a, _id_b, "ollama", "deepseek", "anthropic"]) is None)

print("== E. 软取消（v011 P1-5，假后端全链路）==")


class SlowBackend:
    name, label, model, local = "ollama", "本地", "fake", True
    calls = 0

    def available(self):
        return True

    async def chat(self, messages, tools=None):
        SlowBackend.calls += 1
        return {"tool_calls": [{"id": f"c{SlowBackend.calls}", "type": "function",
                                "function": {"name": "note_fact",
                                             "arguments": "{\"args\":\"第N条\"}"}}],
                "content": ""}


async def _cancel_case():
    s = agent_mod.Session(id="cancelsess01", project=pid)
    sessions.sessions[s.id] = s
    s.cancel_event.set()          # 预先置位：第 1 步边界就应取消
    agent.backend_name = None
    orig_get = agent_mod.get_backend
    agent_mod.get_backend = lambda *a, **k: SlowBackend()
    try:
        await agent.run(s, "测试取消")
    finally:
        agent_mod.get_backend = orig_get
        sessions.sessions.pop(s.id, None)
    return s

_s2 = asyncio.run(_cancel_case())
types = []
while not _s2.events.empty():
    types.append(_s2.events.get_nowait().get("type"))
check("取消后会话正常收尾（done）", types and types[-1] == "done", types[-3:])
check("发出 cancelled 事件", "cancelled" in types)
check("取消路径未调用模型（步骤边界即停）", SlowBackend.calls == 0, SlowBackend.calls)
check("中断摘要已落库", "【中断】" in (_s2.summary or ""), (_s2.summary or "")[:40])
check("取消事件可回放", any(e["type"] in ("cancelled", "done")
      for e in store.list_events("cancelsess01")))

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
