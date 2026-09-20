# -*- coding: utf-8 -*-
"""v023.5 回归：流量审计报告 + 面板后端 API 支撑（pause-all / clear-queue）。

    python test_traffic_audit.py

离线：不起服务，直接测 store 聚合函数与 governor 的清空排队语义。
"""
import asyncio
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

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_audit_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}],'
                             ' "domains": ["audit-test.com", "audit2.com"]}',
                             encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.TRAFFIC_MAX_REQUESTS = 500
config.TRAFFIC_BURST = 500

from app import report, store, traffic                    # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


pid = store.create_project("审计测试", "127.0.0.1")["id"]

print("== A. 事件采集 ==")
store.add_traffic_event({"project_id": pid, "root_domain": "audit-test.com",
                         "host": "audit-test.com", "event_type": "sent",
                         "tool_alias": "difftest"})
store.add_traffic_event({"project_id": pid, "root_domain": "audit-test.com",
                         "host": "audit-test.com", "event_type": "settled",
                         "tool_alias": "difftest", "status_code": 200})
store.add_traffic_event({"project_id": pid, "root_domain": "audit-test.com",
                         "host": "audit-test.com", "event_type": "sent",
                         "tool_alias": "httpreplay"})
store.add_traffic_event({"project_id": pid, "root_domain": "audit-test.com",
                         "host": "audit-test.com", "event_type": "settled",
                         "tool_alias": "httpreplay", "error_type": "ConnectionResetError",
                         "os_error_code": 10054})
store.add_traffic_event({"project_id": pid, "root_domain": "audit-test.com",
                         "event_type": "rejected", "redaction_summary": "预算耗尽"})
store.add_traffic_event({"project_id": pid, "root_domain": "audit-test.com",
                         "event_type": "paused", "redaction_summary": "2×RST → COOLDOWN"})
store.add_traffic_event({"project_id": pid, "root_domain": "audit2.com",
                         "host": "audit2.com", "event_type": "sent",
                         "tool_alias": "executor"})
store.upsert_traffic_state(pid, {"root_domain": "audit-test.com", "state": "BLOCKED",
                                 "reason": "连接被拒绝", "resolved_ip": "127.0.0.1"})

aud = store.traffic_audit(pid)
check("总发送数聚合", aud["total_sent"] == 3, aud["total_sent"])
check("被拒数聚合", aud["total_rejected"] == 1, aud["total_rejected"])
check("自动暂停数聚合", aud["auto_pauses"] == 1, aud["auto_pauses"])
check("按通道分组（difftest/httpreplay/executor）",
      {t["tool"] for t in aud["by_tool"]} == {"difftest", "httpreplay", "executor"},
      aud["by_tool"])
check("按根域名分组", {t["root_domain"] for t in aud["by_root"]} ==
      {"audit-test.com", "audit2.com"}, aud["by_root"])
check("状态码分布", any(s["status_code"] == 200 for s in aud["by_status"]), aud["by_status"])
check("网络层错误含 10054",
      any(e["os_error_code"] == 10054 for e in aud["errors"]), aud["errors"])
check("防护事件列表", len(aud["waf_events"]) >= 1, aud["waf_events"])
check("目标最终状态含 BLOCKED",
      any(s["state"] == "BLOCKED" for s in aud["states"]), aud["states"])
check("间隔统计（同秒发送 → 间隔 0）",
      aud["avg_interval"] is not None and aud["min_interval"] is not None,
      (aud["avg_interval"], aud["min_interval"]))

print("== B. 报告集成（流量摘要章节） ==")
md = report.render_project_report(pid)
check("报告含「测试流量摘要」章节", "测试流量摘要" in md)
check("报告含请求总数", "实际发出请求" in md)
check("报告含防护事件", "防护/暂停事件" in md)
check("报告含目标最终状态表", "目标最终状态" in md and "BLOCKED" in md)
check("报告不含完整凭据（摘要为脱敏文本）", "Authorization: Bearer" not in md)

print("== C. clear-queue 语义 ==")
gov = traffic.governor
gov.reset()
gov.clear_state("audit-test.com", project_id=pid)
r = asyncio.run(gov.acquire("https://audit-test.com/a", project_id=pid, tool_alias="t"))
check("前置：正常可取许可", r.get("root") == "audit-test.com")
cq = gov.clear_queue("audit-test.com", project_id=pid)
check("清空排队返回当时排队数", "queued_at_clear" in cq, cq)
check("清空后标记存在", "audit-test.com" in gov._queue_cleared)
try:
    asyncio.run(gov.acquire("https://audit-test.com/b", project_id=pid, tool_alias="t"))
    check("清空后的排队请求被取消", False)
except traffic.TrafficCancelled as e:
    check("清空后的排队请求被取消（TrafficCancelled）", "清空" in str(e), str(e)[:60])
check("标记已消费（不持续影响后续请求）", "audit-test.com" not in gov._queue_cleared)
check("后续请求恢复可取许可",
      bool(asyncio.run(gov.acquire("https://audit-test.com/c", project_id=pid,
                                   tool_alias="t"))))

print("== D. pause-all 支撑（roots_seen） ==")
roots = gov.roots_seen()
check("roots_seen 含事件里的目标", "audit-test.com" in roots, roots[:5])
gov.pause("audit-test.com", "暂停全部", project_id=pid)
check("暂停后状态落库",
      (store.get_traffic_state("audit-test.com") or {}).get("state") == traffic.ST_PAUSED)
gov.confirm_resume("audit-test.com", project_id=pid)   # 清理，避免污染后续

print("== E. 峰值并发记录 ==")
check("peak_inflight 有记录", gov._peak_inflight.get("audit-test.com", 0) >= 1,
      gov._peak_inflight)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
