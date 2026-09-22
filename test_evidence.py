# -*- coding: utf-8 -*-
"""v012 回归：事实/漏洞状态模型 + 报告增强 + 端口/协议授权。

    python test_evidence.py

数据库与 scope.json 改道临时目录，不联网、不碰真实目标。
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_ev_test_"))
config.DATA_DIR = _TMP
_ORIG_SCOPE = config.SCOPE_FILE

import importlib                                         # noqa: E402
from app import store, report, scope                     # noqa: E402
importlib.reload(store)
store.DB_PATH = _TMP / "projects.db"

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


# ---------------------------------------------------------------------------
print("== A. 事实状态模型（v012 P1-1）==")
pid = store.create_project("v012测试项目", "example.com")["id"]

f_manual = store.add_fact(pid, "人工登记的事实", source="manual")
check("人工登记 → verified", f_manual["status"] == "verified")
f_step = store.add_fact(pid, "带溯源步骤的事实", source="agent", step_id="stp_1")
check("AI 记录 + 工具输出背书 → verified", f_step["status"] == "verified")
f_agent = store.add_fact(pid, "AI 声称但无溯源", source="agent")
check("AI 记录无溯源 → candidate（不能自称已证）", f_agent["status"] == "candidate")
f_bad = store.add_fact(pid, "显式指定", status="bogus")
check("非法 status 落为 candidate", f_bad["status"] == "candidate")

r1 = store.review_fact(pid, f_agent["id"], "verified")
check("人工复核 candidate → verified", r1 and r1["status"] == "verified")
check("跨项目复核 → None",
      store.review_fact("other-project", f_manual["id"], "rejected") is None)
check("非法 action → None", store.review_fact(pid, f_agent["id"], "hack") is None)

print("== B. 漏洞状态模型（v012 P1-1）==")
v1 = store.add_finding(pid, "AI 报的 SQL 注入", "高危", "example.com",
                       detail="union 注入", evidence="回显截图",
                       vuln_type="SQL 注入", cwe="CWE-89", cvss="8.6")
check("AI 登记 → draft（候选）", v1["status"] == "draft")
check("结构化字段落库", v1["cwe"] == "CWE-89" and v1["vuln_type"] == "SQL 注入")
r2 = store.review_finding(pid, v1["id"], "confirmed", note="已复现")
check("人工确认 → confirmed + 备注落库",
      r2 and r2["status"] == "confirmed" and r2["review_note"] == "已复现")
v2 = store.add_finding(pid, "AI 猜的弱口令", "中危", "example.com")
check("人工复核跨项目拒绝", store.review_finding("other", v2["id"], "confirmed") is None)
check("非法 review action 拒绝",
      store.review_finding(pid, v2["id"], "auto-confirm") is None)

print("== C. 报告增强（v012 P1-2）==")
md = report.render_project_report(pid)
check("已确认漏洞进主章节", "## 一、已确认漏洞清单" in md and "AI 报的 SQL 注入" in md)
check("候选漏洞在附录且标注未确认", "## 附录、待验证候选" in md and "AI 猜的弱口令" in md)
check("修复建议来自模板（不再是「待补充」）",
      "参数化查询" in md and "**修复建议**\n\n（待补充）" not in md)
check("CWE/CVSS 结构化字段进详情", "CWE-89" in md and "8.6" in md)
check("复现步骤章节存在（缺失时有完整性告警）",
      ("**复现步骤**" in md) or ("完整性告警" in md))
v3 = store.add_finding(pid, "无证据的确认漏洞", "高危", "example.com",
                       status="confirmed")
md2 = report.render_project_report(pid)
check("confirmed 缺证据/复现 → 完整性告警",
      "完整性告警" in md2 and "无证据的确认漏洞" in md2)

# 表格转义：项目名带竖线不再毁表
p2 = store.create_project("坏|名字", "example.com")
v4 = store.add_finding(p2["id"], "标题|含竖线", "低危", "a|b.com", status="confirmed")
md3 = report.render_project_report(p2["id"])
check("标题竖线被转义（不破坏表格）", "标题\\|含竖线" in md3)
check("目标竖线被转义", "a\\|b.com" in md3)

print("== D. 端口/协议授权（v012 P2-3）==")
scope_file = _TMP / "scope_v012.json"
scope_file.write_text('{"targets": [{"host": "example.com", "ports": [80, 443],'
                      ' "schemes": ["https"]}], "domains": ["target.test"]}',
                      encoding="utf-8")
config.SCOPE_FILE = scope_file

check("混合写法域名视图兼容（domains 仍在）",
      "target.test" in scope.load_scope())
check("结构化写法的 host 也进白名单视图",
      "example.com" in scope.load_scope())
_t_entry = next(e for e in scope.load_scope_targets() if e["host"] == "example.com")
check("结构化条目解析（ports/schemes）",
      _t_entry["ports"] == {80, 443} and _t_entry["schemes"] == {"https"})
check("host 命中 + 授权端口 → 放行",
      scope.check_scope("https://example.com/") is None)
check("host 命中但端口未授权 → 拒绝",
      isinstance(scope.check_scope("http://example.com:8080/"), str))
check("协议 http 不在授权 schemes（仅 https）→ 拒绝",
      isinstance(scope.check_scope("http://example.com/"), str))
check("host 命中 + https 授权协议（子域）→ 放行",
      scope.check_scope("https://sub.example.com/") is None)
# 只声明 ports、不声明 schemes：协议不受限
scope_file.write_text('{"targets": [{"host": "example.com", "ports": [80, 443]}],'
                      ' "domains": ["target.test"]}', encoding="utf-8")
check("只限端口不限协议：http 默认 80 在授权端口 → 放行",
      scope.check_scope("http://example.com/") is None)
scope_file.write_text('{"targets": [{"host": "example.com", "ports": [80, 443],'
                      ' "schemes": ["https"]}], "domains": ["target.test"]}',
                      encoding="utf-8")
check("旧写法域名不受端口限制（target.test 任意端口）",
      scope.check_scope("http://target.test:9999/") is None)
check("未授权主机照旧拒绝",
      isinstance(scope.check_scope("http://evil.com:80/"), str))

print("== E. 工具 manifest 渐进版（v012 后半 P2-2）==")
from app.executor import _check_target_type, _strip_disallowed_flags   # noqa: E402

check("url 型：完整 URL 通过", _check_target_type("url", "https://example.com/") is None)
check("url 型：裸域名拒绝", isinstance(_check_target_type("url", "example.com"), str))
check("domain 型：裸域名通过", _check_target_type("domain", "example.com") is None)
check("domain 型：带协议拒绝", isinstance(_check_target_type("domain", "http://example.com/"), str))
check("host 型：域名通过", _check_target_type("host", "example.com") is None)
check("host 型：带路径拒绝", isinstance(_check_target_type("host", "example.com/admin"), str))
check("未声明 target_type → 不校验", _check_target_type("", "任意内容") is None)

check("黑名单旗标连同取值剔除",
      _strip_disallowed_flags("-silent -l targets.txt -nc", ["-l", "--list"]) == "-silent -nc")
check("黑名单 `=` 取值形式剔除",
      _strip_disallowed_flags("-o=out.txt -ok", ["-o"]) == "-ok")
check("无黑名单 → 原样返回", _strip_disallowed_flags("-a -b", []) == "-a -b")

print("== F. overrides 声明落盘（v012 后半）==")
# registry 消费逻辑已由 E 组纯函数覆盖；这里断言 JSON 声明本身
# （不依赖 TOOLBOX_ROOT 是否能扫到工具箱）
import json as _json                                     # noqa: E402
_ov = _json.loads((ROOT / "data" / "tool_overrides.json").read_text(encoding="utf-8"))
check("ehole 声明 target_type=url",
      _ov.get("ehole", {}).get("target_type") == "url")
check("dirsearch 声明 target_type=url",
      _ov.get("dirsearch", {}).get("target_type") == "url")
check("httpx 黑名单声明（v023.6 追加 -redirect：该旗标不存在）",
      set(_ov.get("httpx", {}).get("disallowed_flags") or []) >= {"-l", "--list", "-redirect"})
check("oneforall 声明 target_type=domain",
      _ov.get("oneforall", {}).get("target_type") == "domain")
check("_说明 已更新使用文档", "target_type" in _ov.get("_说明", ""))

print("== G. 取消硬终止：py_exec 全链路（v012 后半）==")
import asyncio                                           # noqa: E402
from app import pyexec                                   # noqa: E402

async def _cancel_pyexec():
    ev = asyncio.Event()
    ev.set()   # 预置：spawn 后第一次循环检查即触发
    evs = []
    async for e in pyexec.run_py_exec("import time; time.sleep(30)",
                                      "example.com", cancel_event=ev):
        evs.append(e)
    return evs

_pe = asyncio.run(_cancel_pyexec())
_types = [e.get("type") for e in _pe]
check("py_exec 取消事件发出", "cancelled" in _types, _types)
check("py_exec 取消退出码 130",
      any(e.get("type") == "exit" and e.get("code") == 130 for e in _pe), _types[-2:])
_ci = _types.index("cancelled") if "cancelled" in _types else -1
_after = [t for t in _types[_ci + 1:]] if _ci >= 0 else []
check("取消后不再产生 output（只余 exit 收尾）",
      _ci >= 0 and "output" not in _after, _after)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
