# -*- coding: utf-8 -*-
"""项目仓储：SQLite 持久化项目、会话、执行步骤与漏洞发现。"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
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
CREATE TABLE IF NOT EXISTS chat_messages (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    role        TEXT,
    kind        TEXT DEFAULT '',
    content     TEXT,
    created_at  REAL
);
CREATE TABLE IF NOT EXISTS usage_log (
    id              TEXT PRIMARY KEY,
    ts              REAL,
    session_id      TEXT DEFAULT '',
    project_id      TEXT DEFAULT '',
    provider_id     TEXT DEFAULT '',
    model           TEXT DEFAULT '',
    prompt_tokens   INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    duration_ms     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_steps_session ON steps(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_facts_project ON facts(project_id);
CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage_log(ts);
CREATE INDEX IF NOT EXISTS idx_usage_project ON usage_log(project_id);
"""


def _connect() -> sqlite3.Connection:
    """建立连接并设置并发相关 PRAGMA。

    - WAL：Agent 后台每步都写 steps，与接口的读请求是并发的；默认 rollback journal
      下写锁会阻塞读，容易出现 "database is locked"。
    - busy_timeout：拿不到锁时等待而不是立刻抛错（连接串的 timeout 与 PRAGMA 双保险）。
    - synchronous=NORMAL：WAL 下兼顾安全与写入吞吐。
    journal_mode 是数据库的持久属性，重复设置无副作用。
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
    except sqlite3.Error:
        pass
    return conn


@contextmanager
def _db():
    """数据库连接上下文：正常提交、异常回滚，**并且一定关闭连接**。

    注意：`with sqlite3.connect(...) as c:` 只提交/回滚事务，并不会关闭连接
    （官方文档明确说明 context manager 不关闭连接）。此前正是用这种写法，
    连接依赖 CPython 引用计数回收，写法上易被误解为「已关闭」。
    """
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _db() as c:
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
    with _db() as c:
        c.execute(
            "INSERT INTO projects (id,name,target,note,created_at) VALUES (?,?,?,?,?)",
            (pid, name, target, note, time.time()),
        )
    return {"id": pid, "name": name, "target": target, "note": note}


def list_projects() -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT p.*, (SELECT COUNT(*) FROM sessions s WHERE s.project_id=p.id) AS session_count,"
            " (SELECT COUNT(*) FROM findings f WHERE f.project_id=p.id) AS finding_count"
            " FROM projects p ORDER BY p.created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_project(pid: str) -> dict | None:
    with _db() as c:
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
    with _db() as c:
        cur = c.execute(f"UPDATE projects SET {sets} WHERE id=?", (*patch.values(), pid))
        if cur.rowcount == 0:
            return None
    return get_project(pid)


def delete_project(pid: str) -> bool:
    """删除项目及其全部派生数据。

    补清理此前遗漏的两处：
      · chat_messages —— 按 session_id 关联，删会话时不会跟着走，会留下孤儿消息；
      · usage_log —— 保留调用记录本身（计费/统计口径不应因删项目而变），
        只把 project_id 置空，去掉指向已删项目的悬空引用。
    同时去掉原先对 projects 表的重复 DELETE（先用 SELECT 判存在）。
    """
    with _db() as c:
        if not c.execute("SELECT 1 FROM projects WHERE id=?", (pid,)).fetchone():
            return False
        sids = [r["id"] for r in c.execute(
            "SELECT id FROM sessions WHERE project_id=?", (pid,)).fetchall()]
        c.execute("DELETE FROM steps WHERE session_id IN (SELECT id FROM sessions WHERE project_id=?)", (pid,))
        for sid in sids:
            c.execute("DELETE FROM chat_messages WHERE session_id=?", (sid,))
        c.execute("DELETE FROM sessions WHERE project_id=?", (pid,))
        c.execute("DELETE FROM findings WHERE project_id=?", (pid,))
        c.execute("DELETE FROM facts WHERE project_id=?", (pid,))
        c.execute("DELETE FROM intel WHERE project_id=?", (pid,))
        c.execute("UPDATE usage_log SET project_id='' WHERE project_id=?", (pid,))
        c.execute("DELETE FROM projects WHERE id=?", (pid,))
    return True


# ---------- 会话与步骤 ----------
def save_session(sid: str, project_id: str, task: str, target: str, state: str,
                 parent_id: str | None = None, title: str | None = None,
                 context: list | None = None, status: str | None = None,
                 summary: str | None = None) -> None:
    """保存/更新会话。树相关列（parent_id/title/context/status/summary）只在显式
    传入时更新，避免普通落库把分支元数据冲掉。"""
    with _db() as c:
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
    with _db() as c:
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
    with _db() as c:
        r = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    return dict(r) if r else None


def list_tree(project_id: str) -> list[dict]:
    """项目内全部会话（按创建时间正序，前端按 parent_id 组装成树）。"""
    with _db() as c:
        rows = c.execute(
            "SELECT id,parent_id,title,task,target,state,status,summary,created_at,"
            " (SELECT COUNT(*) FROM steps st WHERE st.session_id=sessions.id) AS step_count"
            " FROM sessions WHERE project_id=? ORDER BY created_at ASC",
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_session_tree(sid: str) -> dict:
    """彻底删除一条线索及其所有后代（子分支），并级联清理步骤、对话历史、用量记录。

    返回 {deleted_ids: [sid, ...], count: N}。
    """
    with _db() as c:
        # 1) 收集待删节点（含后代）
        to_delete: list[str] = []
        queue = [sid]
        while queue:
            cur = queue.pop(0)
            if cur in to_delete:
                continue
            to_delete.append(cur)
            rows = c.execute(
                "SELECT id FROM sessions WHERE parent_id=?", (cur,)
            ).fetchall()
            queue.extend([r["id"] for r in rows])

        if not to_delete:
            return {"deleted_ids": [], "count": 0}

        # 2) 级联删除
        placeholders = ",".join("?" * len(to_delete))
        c.execute(f"DELETE FROM steps WHERE session_id IN ({placeholders})", to_delete)
        c.execute(f"DELETE FROM chat_messages WHERE session_id IN ({placeholders})", to_delete)
        c.execute(f"DELETE FROM usage_log WHERE session_id IN ({placeholders})", to_delete)
        c.execute(f"DELETE FROM sessions WHERE id IN ({placeholders})", to_delete)

    return {"deleted_ids": to_delete, "count": len(to_delete)}


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
    with _db() as c:
        cur = c.execute(f"UPDATE sessions SET {sets} WHERE id=?", (*patch.values(), sid))
        if cur.rowcount == 0:
            return None
    return get_session_row(sid)


def save_summary(sid: str, summary: str) -> None:
    """保存会话结论摘要（成果回流：供其他线索的上下文注入与前端小地图展示）。"""
    with _db() as c:
        c.execute("UPDATE sessions SET summary=? WHERE id=?", (summary[:1000], sid))


def search_history(project_id: str, keyword: str, limit: int = 8) -> list[dict]:
    """跨线索检索：在项目内所有会话的工具输出/参数/目标中搜关键词。

    供内置工具 search_history 使用，实现「新对话调取历史对话内容」。
    """
    kw = (keyword or "").strip()
    if not kw or not project_id:
        return []
    like = f"%{kw}%"
    with _db() as c:
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
    with _db() as c:
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
    with _db() as c:
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
    with _db() as c:
        s = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            return None
        steps = [dict(r) for r in c.execute(
            "SELECT * FROM steps WHERE session_id=? ORDER BY created_at ASC", (sid,)
        ).fetchall()]
    return {"session": dict(s), "steps": steps}


# ---------- 对话历史（线索回放用） ----------
def save_chat_message(sid: str, role: str, content: str, kind: str = "") -> None:
    """持久化一条对话消息：role=user/assistant；kind=reasoning/answer（assistant 侧细分）。

    供「切换线索时回放历史对话」使用；单条截断 8000 字符防膨胀。
    """
    text = (content or "").strip()
    if not text:
        return
    with _db() as c:
        c.execute(
            "INSERT INTO chat_messages (id,session_id,role,kind,content,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (uuid.uuid4().hex[:12], sid, role, kind, text[:8000], time.time()),
        )


def list_chat_messages(sid: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT role,kind,content,created_at FROM chat_messages"
            " WHERE session_id=? ORDER BY created_at ASC, rowid ASC",
            (sid,),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- Token 用量统计 ----------
def save_usage(provider_id: str, model: str, prompt_tokens: int, completion_tokens: int,
               session_id: str = "", project_id: str = "", duration_ms: int = 0) -> None:
    """记录一次 LLM 调用的 token 用量（仅成功且有 usage 数据的调用）。"""
    with _db() as c:
        c.execute(
            "INSERT INTO usage_log (id,ts,session_id,project_id,provider_id,model,"
            "prompt_tokens,completion_tokens,duration_ms) VALUES (?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex[:12], time.time(), session_id or "", project_id or "",
             provider_id or "", model or "", int(prompt_tokens or 0),
             int(completion_tokens or 0), int(duration_ms or 0)),
        )


def list_usage(project_id: str = "", model: str = "", days: int = 0,
               limit: int = 500) -> list[dict]:
    """明细记录（倒序）。days>0 限定最近 N 天；project_id/model 空串为不过滤。"""
    q = "SELECT * FROM usage_log WHERE 1=1"
    vals: list = []
    if project_id:
        q += " AND project_id=?"
        vals.append(project_id)
    if model:
        q += " AND model=?"
        vals.append(model)
    if days > 0:
        q += " AND ts>=?"
        vals.append(time.time() - days * 86400)
    q += " ORDER BY ts DESC LIMIT ?"
    vals.append(max(1, min(limit, 5000)))
    with _db() as c:
        rows = c.execute(q, vals).fetchall()
    return [dict(r) for r in rows]


def clear_usage(days: int = 0) -> int:
    """清空用量记录；days>0 只删最近 N 天之外的……即保留最近 N 天，删除更早的。"""
    with _db() as c:
        if days > 0:
            cur = c.execute("DELETE FROM usage_log WHERE ts<?", (time.time() - days * 86400,))
        else:
            cur = c.execute("DELETE FROM usage_log")
    return cur.rowcount


# ---------- 漏洞发现 ----------
def add_finding(project_id: str, title: str, severity: str, target: str,
                detail: str = "", evidence: str = "") -> dict:
    fid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO findings (id,project_id,title,severity,target,detail,evidence,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (fid, project_id, title, severity, target, detail, evidence, time.time()),
        )
    return {"id": fid, "project_id": project_id, "title": title, "severity": severity, "target": target}


def list_findings(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC", (project_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_finding(fid: str) -> bool:
    with _db() as c:
        c.execute("DELETE FROM findings WHERE id=?", (fid,))
    return True


# ---------- 已证客观事实（facts） ----------
def add_fact(project_id: str, content: str, source: str = "manual") -> dict:
    """记录一条「已证实的客观事实」（凭据/漏洞/敏感路径等）。source: manual | agent。"""
    content = content.strip()
    if not content:
        return {}
    fid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO facts (id,project_id,content,source,created_at) VALUES (?,?,?,?,?)",
            (fid, project_id, content, source, time.time()),
        )
    return {"id": fid, "project_id": project_id, "content": content, "source": source,
            "created_at": time.time()}


def list_facts(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM facts WHERE project_id=? ORDER BY created_at DESC", (project_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_fact(fid: str) -> bool:
    with _db() as c:
        c.execute("DELETE FROM facts WHERE id=?", (fid,))
    return True


# ---------- 项目情报库 ----------
def get_intel(project_id: str) -> dict:
    with _db() as c:
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
    with _db() as c:
        c.execute(
            "INSERT OR REPLACE INTO intel (project_id,data,updated_at) VALUES (?,?,?)",
            (project_id, json.dumps(data, ensure_ascii=False), time.time()),
        )
    return data


def delete_intel(project_id: str) -> bool:
    with _db() as c:
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
