# -*- coding: utf-8 -*-
"""v023.6 回归：shhxqh 实战暴露的四个缺陷修复。

    python test_023_fixes.py

1. 流量事件的 project_id/session_id 透传（实战：442 条事件全落空项目桶）
2. network_control 未声明警告不再每步刷屏（移入工具清单描述）
3. 受控通道响应截断显式告知
4. 确认拒绝后给出可执行的降级替代路径
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_236_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False

from app import registry, store, traffic                 # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


print("== A. 出网入口的 project/session 透传（源码断言） ==")
agent_src = (ROOT / "app" / "agent.py").read_text(encoding="utf-8")
check("agent 构造上下文 _ctx 并透传四个通道",
      '_ctx = {"project_id": session.project or "", "session_id": session.id}' in agent_src
      and agent_src.count("**_ctx") == 4, agent_src.count("**_ctx"))
exec_src = (ROOT / "app" / "executor.py").read_text(encoding="utf-8")
check("executor.run 接受 project_id/session_id",
      'cancel_event=None, project_id: str = "", session_id: str = ""' in exec_src)
check("executor 取许可时透传", "project_id=project_id, session_id=session_id" in exec_src)
rep_src = (ROOT / "app" / "replayer.py").read_text(encoding="utf-8")
check("replayer.run_replay 接受并透传",
      'project_id: str = "", session_id: str = ""' in rep_src
      and "project_id=project_id, session_id=session_id" in rep_src)
check("nuclei 通道也取许可并透传", "出网调度拒绝（不启动 nuclei）" in rep_src)
pye_src = (ROOT / "app" / "pyexec.py").read_text(encoding="utf-8")
check("pyexec 把上下文交给桥接",
      "project_id=project_id," in pye_src and "session_id=session_id)" in pye_src)
br_src = (ROOT / "app" / "pyexec_bridge.py").read_text(encoding="utf-8")
check("桥接保存并透传 session_id", "self.session_id = session_id" in br_src
      and "session_id=self.session_id" in br_src)

print("== B. 警告不再刷屏（进工具清单） ==")
reg = registry.ToolRegistry()
reg.load()
schemas = reg.build_schemas()
declared_note = sum(1 for s in schemas
                    if "未声明内部速率能力" in s["function"]["description"])
check("未声明提示已进入 schema 描述（一次性可见）", declared_note > 0, declared_note)
l2l3 = sum(1 for s in schemas
           if s["function"]["description"].endswith("扫描。"))
check("提示只加在 L2/L3（L0/L1 不刷）", declared_note < len(schemas), 
      f"{declared_note}/{len(schemas)}")
exec_src2 = (ROOT / "app" / "executor.py").read_text(encoding="utf-8")
check("executor 不再 yield 长警告文本",
      "未在 data/tool_overrides.json 的 network_control 中声明" not in exec_src2)
check("严格模式仍拒绝", "已拒绝执行（严格模式）" in exec_src2)

print("== C. 截断显式告知 ==")
check("受控通道带 truncated/total_chars/note",
      '"truncated"' in br_src and '"total_chars"' in br_src
      and "truncation_note" in br_src)
check("截断提示含分片/本地解析建议",
      "Range 头分片" in br_src)

print("== D. 拒绝后给降级替代路径 ==")
check("py_exec 被拒给出 httpreplay/safe_http_request 两条路径",
      "可用替代：①内置 `httpreplay` 单发一次请求" in agent_src)
check("L3 被拒给出收窄范围建议", "改用同功能的 L0/L1 只读工具" in agent_src)

print("== E. 端到端：事件归属（模拟 acquire -> settle） ==")
import asyncio                                          # noqa: E402
traffic.governor.reset()
pid = store.create_project("归属测试", "127.0.0.1")["id"]
permit = asyncio.run(traffic.governor.acquire(
    "https://127.0.0.1/x", project_id=pid, session_id="sess-abc",
    tool_alias="py_exec"))
asyncio.run(traffic.governor.release(permit, status_code=200))
evs = store.list_traffic_events(pid, limit=10)
check("事件按项目可查", len(evs) >= 1, len(evs))
check("事件带 session_id", any(e.get("session_id") == "sess-abc" for e in evs))
aud = store.traffic_audit(pid)
check("项目审计统计到该请求", aud["total_sent"] >= 1, aud["total_sent"])

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
