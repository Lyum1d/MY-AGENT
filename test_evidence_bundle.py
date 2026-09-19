# -*- coding: utf-8 -*-
"""v017.4 证据链与复核闸门回归：diff_run 落库、checklist CRUD、confirmed 硬闸门。

    python test_evidence_bundle.py

离线：数据库与 scope.json 改道临时目录。
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_bundle_test_"))
scope_file = _TMP / "scope_v0174.json"
scope_file.write_text('{"domains": ["example.com"]}', encoding="utf-8")
config.SCOPE_FILE = scope_file

import importlib                                         # noqa: E402
from app import store                                    # noqa: E402
importlib.reload(store)
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


print("== A. 差分记录落库 ==")
pid = store.create_project("证据链测试", "example.com")["id"]
run_id = store.add_diff_run(pid, {
    "request_id": "req_1", "baseline_identity": "account_a",
    "target_field": "orderId", "target_location": "query",
    "target_value_masked": "20***02", "verdict": "suspect_idor",
    "reason": "变体与基准返回了不同的对象归属数据", "stable": True,
    "steps": [{"tag": "baseline", "url": "https://example.com/api/o/1", "status": 200},
              {"tag": "variant#1", "url": "https://example.com/api/o/2", "status": 200}],
    "variant_url": "https://example.com/api/o/2",
})
got = store.get_diff_run(pid, run_id)
check("差分记录落库可读", got is not None and got["verdict"] == "suspect_idor")
check("steps JSON 反序列化", isinstance(got["steps"], list) and len(got["steps"]) == 2)
check("列表读取", any(r["id"] == run_id for r in store.list_diff_runs(pid)))
check("跨项目取差分 → None", store.get_diff_run("other", run_id) is None)

print("== B. 五项复核清单 CRUD ==")
fid_rec = store.add_finding(pid, "疑似越权：基准身份可访问他人订单", "高危",
                            "example.com", detail="差分判定…", status="draft")
fid = fid_rec["id"]
check("初始无清单", store.get_checks(fid) is None)
check("未填清单 → checks_complete False（闸门依据）", store.checks_complete(fid) is False)
full = store.set_checks(fid, {"c1_repeat": True, "c2_permission_delta": True,
                              "c3_minimal_chain": True, "c4_readonly_or_safe": True,
                              "c5_impact_proven": True}, note="已复现两次")
check("五项全勾落库", all(full[k] for k in
                          ("c1_repeat", "c2_permission_delta", "c3_minimal_chain",
                           "c4_readonly_or_safe", "c5_impact_proven")))
check("全勾 → checks_complete True", store.checks_complete(fid) is True)
partial = store.set_checks(fid, {"c1_repeat": True}, note="只验证了一半")
check("部分勾选 → False（可回退）", store.checks_complete(fid) is False)
check("note 落库", partial["note"] == "只验证了一半")
store.set_checks(fid, {"c1_repeat": True, "c2_permission_delta": True,
                       "c3_minimal_chain": True, "c4_readonly_or_safe": True,
                       "c5_impact_proven": True}, note="补齐")

print("== C. confirmed 硬闸门（模拟 main 层逻辑） ==")
# main.review_finding: action=confirmed 时要求 store.checks_complete(fid)
can_confirm = store.checks_complete(fid)
check("全勾 finding 允许 confirmed", can_confirm)
r = store.review_finding(pid, fid, "confirmed", note="复核通过")
check("confirmed 落库", r["status"] == "confirmed")
fid2 = store.add_finding(pid, "半证据漏洞", "高危", "example.com", status="draft")["id"]
check("未填清单的 finding 闸门拒绝（checks_complete=False）",
      store.checks_complete(fid2) is False)
# 确认被 main 层 400 拒绝，因此状态应保持 draft（模拟：不调 review_finding）
check("状态仍为 draft", store.list_findings(pid)[[f["id"] for f in store.list_findings(pid)].index(fid2)]["status"] == "draft")

print("== D. 报告集成（复核清单状态） ==")
from app import report                                  # noqa: E402
md = report.render_project_report(pid)
check("报告含复核清单行", "复核清单" in md and "可重复验证" in md)
check("已确认漏洞的清单全勾显示 ✔", "✔ 可重复验证" in md)
fid3 = store.add_finding(pid, "缺清单的确认漏洞", "中危", "example.com",
                         status="confirmed")["id"]
md2 = report.render_project_report(pid)
check("未填清单的 confirmed 显示 ⚠ 缺", "⚠ 缺 可重复验证" in md2)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
