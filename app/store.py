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
    created_at  REAL
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
CREATE INDEX IF NOT EXISTS idx_steps_session ON steps(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as c:
        c.executescript(SCHEMA)


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


def delete_project(pid: str) -> bool:
    with _conn() as c:
        c.execute("DELETE FROM findings WHERE project_id=?", (pid,))
        c.execute("DELETE FROM steps WHERE session_id IN (SELECT id FROM sessions WHERE project_id=?)", (pid,))
        c.execute("DELETE FROM sessions WHERE project_id=?", (pid,))
        c.execute("DELETE FROM projects WHERE id=?", (pid,))
    return True


# ---------- 会话与步骤 ----------
def save_session(sid: str, project_id: str, task: str, target: str, state: str) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO sessions (id,project_id,task,target,state,created_at)"
            " VALUES (?,?,?,?,?,COALESCE((SELECT created_at FROM sessions WHERE id=?),?))",
            (sid, project_id, task, target, state, sid, time.time()),
        )


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
