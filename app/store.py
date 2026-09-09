# -*- coding: utf-8 -*-
"""项目仓储：SQLite 持久化项目、会话、执行步骤与漏洞发现。"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from . import config

DB_PATH = config.DATA_DIR / "projects.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    target      TEXT,
    note        TEXT,
    created_at  REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    task        TEXT,
    target      TEXT,
    state       TEXT,
    created_at  REAL,
    parent_id   TEXT DEFAULT '',
    title       TEXT DEFAULT '',
    status      TEXT DEFAULT 'active',
    context     TEXT DEFAULT '[]',
    summary     TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS steps (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    tool_alias  TEXT,
    tool_name   TEXT,
    target      TEXT,
    args        TEXT,
    risk_level  TEXT,
    status      TEXT,
    output      TEXT,
    created_at  REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    title       TEXT,
    severity    TEXT,
    target      TEXT,
    detail      TEXT,
    evidence    TEXT,
    created_at  REAL
);
CREATE TABLE IF NOT EXISTS intel (
    project_id  TEXT PRIMARY KEY,
    data        TEXT,
    updated_at  REAL
);
CREATE TABLE IF NOT EXISTS facts (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    content     TEXT,
    source      TEXT,
    created_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_steps_session ON steps(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_facts_project ON facts(project_id);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as c:
        c.executescript(SCHEMA)
        # 旧库升级：会话树新增列（分支对话树功能）。逐列检查，缺哪个补哪个。
        cols = {r["name"] for r in c.execute("PRAGMA table_info(sessions)").fetchall()}
        for col, ddl in (
            ("parent_id", "TEXT DEFAULT ''"),   # 父会话 id，根线索为 ''
            ("title", "TEXT DEFAULT ''"),       # 线索名（分支卡片/小地图显示）
            ("status", "TEXT DEFAULT 'active'"),# 线索状态：active | done | abandoned
            ("context", "TEXT DEFAULT '[]'"),   # 开分支时打包带来的记录（JSON 数组）
            ("summary", "TEXT DEFAULT ''"),     # 每轮结束的结论摘要（写回主对话用）
        ):
            if col not in cols:
                c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {ddl}")
        # 服务重启后内存里的 running 会话已丢，落库的 running 状态会永远卡住，
        # 这里统一标记为 interrupted，避免前端显示「执行中」的僵尸会话。
        c.execute("UPDATE sessions SET state='interrupted' WHERE state='running'")


# ---------- 项目 ----------
def create_project(name: str, target: str = "", note: str = "") -> dict:
    pid = uuid.uuid4().hex[:12]
    with _conn() as c:
        c.execute(
            "INSERT INTO projects (id,name,target,note,created_at) VALUES (?,?,?,?,?)",
            (pid, name, target, note, time.time()),
        )
    return {"id": pid, "name": name, "target": target, "note": note}


def list_projects() -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT p.*, (SELECT COUNT(*) FROM sessions s WHERE s.project_id=p.id) AS session_count,"
            " (SELECT COUNT(*) FROM findings f WHERE f.project_id=p.id) AS finding_count"
            " FROM projects p ORDER BY p.created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_project(pid: str) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    return dict(r) if r else None


_FIELDS = ("name", "target", "note")


def update_project(pid: str, **fields) -> dict | None:
    """更新项目名称/目标/备注。只接受白名单字段，且跳过未传（None）的项。

    返回更新后的项目；项目不存在时返回 None。
    """
    patch = {k: v for k, v in fields.items() if k in _FIELDS and v is not None}
    if not patch:
        return get_project(pid)
    sets = ", ".join(f"{k}=?" for k in patch)
    with _conn() as c:
        cur = c.execute(f"UPDATE projects SET {sets} WHERE id=?", (*patch.values(), pid))
        if cur.rowcount == 0:
            return None
    return get_project(pid)


def delete_project(pid: str) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM projects WHERE id=?", (pid,))
        if cur.rowcount == 0:
            return False
        c.execute("DELETE FROM findings WHERE project_id=?", (pid,))
        c.execute("DELETE FROM facts WHERE project_id=?", (pid,))
        c.execute("DELETE FROM intel WHERE project_id=?", (pid,))
        c.execute("DELETE FROM steps WHERE session_id IN (SELECT id FROM sessions WHERE project_id=?)", (pid,))
        c.execute("DELETE FROM sessions WHERE project_id=?", (pid,))
        c.execute("DELETE FROM projects WHERE id=?", (pid,))
    return True


# ---------- 会话与步骤 ----------
def save_session(sid: str, project_id: str, task: str, target: str, state: str,
                 parent_id: str | None = None, title: str | None = None,
                 context: list | None = None, status: str | None = None,
                 summary: str | None = None) -> None:
    """保存/更新会话。树相关列（parent_id/title/context/status/summary）只在显式
    传入时更新，避免普通落库把分支元数据冲掉。"""
    with _conn() as c:
        row = c.execute("SELECT id FROM sessions WHERE id=?", (sid,)).fetchone()
        sets = ["project_id=?", "task=?", "target=?", "state=?"]
        vals: list = [project_id, task, target, state]
        if parent_id is not None:
            sets.append("parent_id=?")
            vals.append(parent_id)
        if title is not None:
            sets.append("title=?")
            vals.append(title)
        if status is not None:
            sets.append("status=?")
            vals.append(status)
        if context is not None:
            sets.append("context=?")
            vals.append(json.dumps(context, ensure_ascii=False))
        if summary is not None:
            sets.append("summary=?")
            vals.append(summary)
        if row:
            vals.append(sid)
            c.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE id=?", vals)
        else:
            c.execute(
                "INSERT INTO sessions (id,project_id,task,target,state,created_at,"
                "parent_id,title,status,context,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sid, project_id, task, target, state, time.time(),
                 parent_id or "", title or "", status or "active",
                 json.dumps(context or [], ensure_ascii=False), summary or ""),
            )


def create_branch(parent_sid: str, project_id: str, title: str,
                  records: list[str]) -> dict:
    """从父会话开一条新线索：记录打包带入 context，task/target 首次运行时补齐。"""
    sid = uuid.uuid4().hex[:12]
    parent = get_session_row(parent_sid)
    pid = project_id or (parent.get("project_id") or "" if parent else "")
    with _conn() as c:
        c.execute(
            "INSERT INTO sessions (id,project_id,task,target,state,created_at,"
            "parent_id,title,status,context,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (sid, pid, "", "", "idle", time.time(), parent_sid,
             (title or "新线索").strip()[:60], "active",
             json.dumps(records or [], ensure_ascii=False), ""),
        )
    return {"id": sid, "parent_id": parent_sid, "title": (title or "新线索").strip()[:60],
            "project_id": pid, "records": records or []}


def get_session_row(sid: str) -> dict | None:
    """取会话行（含树字段），不含步骤。"""
    with _conn() as c:
        r = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    return dict(r) if r else None


def list_tree(project_id: str) -> list[dict]:
    """项目内全部会话（按创建时间正序，前端按 parent_id 组装成树）。"""
    with _conn() as c:
        rows = c.execute(
            "SELECT id,parent_id,title,task,target,state,status,summary,created_at,"
            " (SELECT COUNT(*) FROM steps st WHERE st.session_id=sessions.id) AS step_count"
            " FROM sessions WHERE project_id=? ORDER BY created_at ASC",
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


THREAD_STATUS = ("active", "done", "abandoned")


def update_session_meta(sid: str, title: str | None = None,
                        status: str | None = None) -> dict | None:
    """更新线索标题/状态（白名单校验，status 只接受三种合法值）。"""
    patch: dict[str, str] = {}
    if title is not None and title.strip():
        patch["title"] = title.strip()[:60]
    if status is not None:
        if status not in THREAD_STATUS:
            raise ValueError(f"非法线索状态：{status}")
        patch["status"] = status
    if not patch:
        return get_session_row(sid)
    sets = ", ".join(f"{k}=?" for k in patch)
    with _conn() as c:
        cur = c.execute(f"UPDATE sessions SET {sets} WHERE id=?", (*patch.values(), sid))
        if cur.rowcount == 0:
            return None
    return get_session_row(sid)


def save_summary(sid: str, summary: str) -> None:
    """保存会话结论摘要（成果回流：供其他线索的上下文注入与前端小地图展示）。"""
    with _conn() as c:
        c.execute("UPDATE sessions SET summary=? WHERE id=?", (summary[:1000], sid))


def search_history(project_id: str, keyword: str, limit: int = 8) -> list[dict]:
    """跨线索检索：在项目内所有会话的工具输出/参数/目标中搜关键词。

    供内置工具 search_history 使用，实现「新对话调取历史对话内容」。
    """
    kw = (keyword or "").strip()
    if not kw or not project_id:
        return []
    like = f"%{kw}%"
    with _conn() as c:
        rows = c.execute(
            "SELECT st.session_id, s.title, s.task, st.tool_name, st.tool_alias,"
            " st.target, st.args, st.output, st.status, st.created_at"
            " FROM steps st JOIN sessions s ON s.id=st.session_id"
            " WHERE s.project_id=? AND (st.output LIKE ? OR st.target LIKE ?"
            "  OR st.args LIKE ? OR st.tool_name LIKE ?)"
            " ORDER BY st.created_at DESC LIMIT ?",
            (project_id, like, like, like, like, limit),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        text = d.get("output") or ""
        pos = text.find(kw)
        if pos >= 0:
            start = max(0, pos - 120)
            d["snippet"] = ("…" if start else "") + text[start:pos + 220].strip() + "…"
        else:
            d["snippet"] = text[:220].strip()
        out.append(d)
    return out


def save_step(sid: str, step: dict) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO steps"
            " (id,session_id,tool_alias,tool_name,target,args,risk_level,status,output,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                step.get("id") or uuid.uuid4().hex[:12],
                sid,
                step.get("tool_alias", ""),
                step.get("tool_name", ""),
                step.get("target", ""),
                step.get("args", ""),
                (step.get("risk") or {}).get("level", ""),
                step.get("status", ""),
                step.get("output", ""),
                time.time(),
            ),
        )


def list_sessions(project_id: str | None = None) -> list[dict]:
    with _conn() as c:
        if project_id:
            rows = c.execute(
                "SELECT * FROM sessions WHERE project_id=? ORDER BY created_at DESC", (project_id,)
            ).fetchall()
        else:
            rows = c.execute("SELECT * FROM sessions ORDER BY created_at DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


def get_session(sid: str) -> dict | None:
    """从持久化层取会话及其步骤。

    用于「服务重启后」回看历史会话——内存里的 SessionManager 在重启后清空，
    但 SQLite 里仍存着，详情接口应能回退到这里。
    """
    with _conn() as c:
        s = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            return None
        steps = [dict(r) for r in c.execute(
            "SELECT * FROM steps WHERE session_id=? ORDER BY created_at ASC", (sid,)
        ).fetchall()]
    return {"session": dict(s), "steps": steps}


# ---------- 漏洞发现 ----------
def add_finding(project_id: str, title: str, severity: str, target: str,
                detail: str = "", evidence: str = "") -> dict:
    fid = uuid.uuid4().hex[:12]
    with _conn() as c:
        c.execute(
            "INSERT INTO findings (id,project_id,title,severity,target,detail,evidence,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (fid, project_id, title, severity, target, detail, evidence, time.time()),
        )
    return {"id": fid, "project_id": project_id, "title": title, "severity": severity, "target": target}


def list_findings(project_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC", (project_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_finding(fid: str) -> bool:
    with _conn() as c:
        c.execute("DELETE FROM findings WHERE id=?", (fid,))
    return True


# ---------- 已证客观事实（facts） ----------
def add_fact(project_id: str, content: str, source: str = "manual") -> dict:
    """记录一条「已证实的客观事实」（凭据/漏洞/敏感路径等）。source: manual | agent。"""
    content = content.strip()
    if not content:
        return {}
    fid = uuid.uuid4().hex[:12]
    with _conn() as c:
        c.execute(
            "INSERT INTO facts (id,project_id,content,source,created_at) VALUES (?,?,?,?,?)",
            (fid, project_id, content, source, time.time()),
        )
    return {"id": fid, "project_id": project_id, "content": content, "source": source,
            "created_at": time.time()}


def list_facts(project_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM facts WHERE project_id=? ORDER BY created_at DESC", (project_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_fact(fid: str) -> bool:
    with _conn() as c:
        c.execute("DELETE FROM facts WHERE id=?", (fid,))
    return True


# ---------- 项目情报库 ----------
def get_intel(project_id: str) -> dict:
    with _conn() as c:
        r = c.execute("SELECT data FROM intel WHERE project_id=?", (project_id,)).fetchone()
    if not r:
        return {}
    try:
        return json.loads(r["data"])
    except Exception:
        return {}


def merge_intel(project_id: str, patch: dict) -> dict:
    """合并情报（按类别去重、排序、限量），返回合并后的完整情报。"""
    data = get_intel(project_id)
    for k, vals in patch.items():
        if not isinstance(vals, (list, tuple, set)):
            continue
        cur = set(str(v) for v in data.get(k, []))
        cur.update(str(v) for v in vals if v)
        data[k] = sorted(cur)[:200]
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO intel (project_id,data,updated_at) VALUES (?,?,?)",
            (project_id, json.dumps(data, ensure_ascii=False), time.time()),
        )
    return data


def delete_intel(project_id: str) -> bool:
    with _conn() as c:
        c.execute("DELETE FROM intel WHERE project_id=?", (project_id,))
    return True


# ---------- 产物目录 ----------
def artifact_dir(project_id: str) -> Path:
    p = config.DATA_DIR / "artifacts" / project_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_artifact(project_id: str, filename: str, content: str) -> str:
    d = artifact_dir(project_id)
    path = d / filename
    path.write_text(content, encoding="utf-8")
    return str(path)


init_db()
