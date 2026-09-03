# -*- coding: utf-8 -*-
"""报告生成：输出补天/SRC 平台可直接提交的漏洞报告 Markdown。"""
from __future__ import annotations

from datetime import datetime

from . import config
from . import store

SEVERITY_ORDER = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}


def render_project_report(project_id: str) -> str:
    proj = store.get_project(project_id)
    if not proj:
        return "# 项目不存在\n"

    findings = sorted(
        store.list_findings(project_id),
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", ""), 9),
    )
    steps = []
    for s in store.list_sessions(project_id):
        steps.extend(_steps_of(s["id"]))

    L = []
    L.append(f"# {proj['name']} — 渗透测试报告\n")
    L.append(f"- **目标**：{proj.get('target') or '（未指定）'}")
    L.append(f"- **生成时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- **漏洞数量**：{len(findings)}")
    L.append(f"- **执行步骤**：{len(steps)}")
    if proj.get("note"):
        L.append(f"- **备注**：{proj['note']}")
    L.append("")

    L.append("\n## 一、漏洞清单\n")
    if findings:
        L.append("| 序号 | 漏洞名称 | 危害等级 | 影响目标 |")
        L.append("|---|---|---|---|")
        for i, f in enumerate(findings, 1):
            L.append(f"| {i} | {f['title']} | {f['severity']} | {f['target']} |")
    else:
        L.append("（暂无已确认的漏洞，可在确认后手动添加到控制台）")
    L.append("")

    if findings:
        L.append("\n## 二、漏洞详情\n")
        for i, f in enumerate(findings, 1):
            L.append(f"\n### {i}. {f['title']}\n")
            L.append(f"- **危害等级**：{f['severity']}")
            L.append(f"- **影响目标**：{f['target']}")
            L.append(f"\n**漏洞描述**\n\n{f.get('detail') or '（待补充）'}\n")
            if f.get("evidence"):
                L.append(f"\n**证明（复现步骤 / 回显）**\n\n```\n{f['evidence']}\n```\n")
            L.append("\n**修复建议**\n\n（待补充）\n")

    L.append("\n## 三、测试过程记录\n")
    if steps:
        L.append("| 时间 | 工具 | 目标 | 风险等级 | 状态 |")
        L.append("|---|---|---|---|---|")
        for s in steps:
            ts = datetime.fromtimestamp(s["created_at"]).strftime("%m-%d %H:%M")
            L.append(
                f"| {ts} | {s['tool_name']} | {s['target']} | {s['risk_level']} | {s['status']} |"
            )
    else:
        L.append("（无执行记录）")
    L.append("")

    L.append("\n---\n")
    L.append("\n> 本报告由本地 SRC 渗透 Agent 生成。所有操作均应在获得书面授权的前提下进行。\n")

    return "\n".join(L)


def _steps_of(session_id: str) -> list[dict]:
    import sqlite3
    conn = sqlite3.connect(store.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM steps WHERE session_id=? ORDER BY created_at", (session_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def export_report(project_id: str) -> str:
    """生成报告并写入产物目录，返回文件路径。"""
    md = render_project_report(project_id)
    proj = store.get_project(project_id) or {}
    name = (proj.get("name") or "project").replace(" ", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return store.save_artifact(project_id, f"报告_{name}_{stamp}.md", md)


def toolbox_root() -> str:
    return str(config.TOOLBOX_ROOT)
