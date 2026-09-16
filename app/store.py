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
    session_id  TEXT DEFAULT '',
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
    session_id  TEXT DEFAULT '',
    step_id     TEXT DEFAULT '',
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
-- 因果图（线索树的「因果图」视图）：节点与边按项目隔离。
-- node_type / label 的取值与归一化在 app/graph.py 里。
-- 注意：这两张表曾被一次更新整段漏掉（app/store.py 被替换成不含因果图持久化的版本），
-- 结果是 app/graph.py 里所有 store.upsert_causal_node 之类的调用直接 AttributeError，
-- 前端「因果图」标签页整个 500。故此处保留，且 test_graph.py 守着不许再掉。
CREATE TABLE IF NOT EXISTS causal_nodes (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    node_type   TEXT,
    title       TEXT DEFAULT '',
    description TEXT DEFAULT '',
    status      TEXT DEFAULT 'PENDING',
    confidence  REAL DEFAULT 0.5,
    severity    TEXT DEFAULT '',
    session_id  TEXT DEFAULT '',
    source_step TEXT DEFAULT '',
    data        TEXT DEFAULT '{}',
    created_at  REAL,
    updated_at  REAL
);
CREATE TABLE IF NOT EXISTS causal_edges (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    source_id   TEXT,
    target_id   TEXT,
    label       TEXT,
    strength    TEXT DEFAULT 'contingent',
    description TEXT DEFAULT '',
    created_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_steps_session ON steps(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_facts_project ON facts(project_id);
CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage_log(ts);
CREATE INDEX IF NOT EXISTS idx_usage_project ON usage_log(project_id);
CREATE INDEX IF NOT EXISTS idx_cnodes_project ON causal_nodes(project_id);
CREATE INDEX IF NOT EXISTS idx_cedges_project ON causal_edges(project_id);
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
            # 是否 split_task 派生的并行子任务。必须落库：子任务内禁 L2/L3 是安全闸门，
            # 只存内存的话，服务重启或被 adopt 后标记丢失、闸门就静默失效了。
            ("subtask", "INTEGER DEFAULT 0"),
        ):
            if col not in cols:
                c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {ddl}")
        # facts / findings 的溯源列（旧库升级）：必须补齐，否则【静默退化】——
        # 因果图的 Evidence→KeyFact（靠 facts.step_id）与 KeyFact→Vulnerability
        # 的同线索关联（靠 facts/findings.session_id）会全部连不出边，
        # 界面不报错，只是图里只剩孤立的点，很难被察觉。
        for tbl, col, ddl in (
            ("facts", "session_id", "TEXT DEFAULT ''"),
            ("facts", "step_id", "TEXT DEFAULT ''"),
            ("findings", "session_id", "TEXT DEFAULT ''"),
        ):
            exist = {r["name"] for r in c.execute(f"PRAGMA table_info({tbl})").fetchall()}
            if col not in exist:
                c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {ddl}")
        # 服务重启后内存里的运行态会话已丢，落库的 running 状态会永远卡住，
        # 这里统一标记为 interrupted，避免前端显示「执行中」的僵尸会话。
        # awaiting_confirm 同理（确认通道随进程消失，不可能再有人回应）。
        c.execute("UPDATE sessions SET state='interrupted' "
                  "WHERE state IN ('running','awaiting_confirm')")


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
        # 因果图必须跟着删：causal_nodes/causal_edges 按 project_id 关联，
        # 不删的话项目删了图还在，下次同一个 pid 重建时会把旧节点捞回来
        # （图里出现"上一个项目"的幽灵节点）。
        c.execute("DELETE FROM causal_edges WHERE project_id=?", (pid,))
        c.execute("DELETE FROM causal_nodes WHERE project_id=?", (pid,))
        c.execute("UPDATE usage_log SET project_id='' WHERE project_id=?", (pid,))
        c.execute("DELETE FROM projects WHERE id=?", (pid,))
    return True


# ---------- 会话与步骤 ----------
def save_session(sid: str, project_id: str, task: str, target: str, state: str,
                 parent_id: str | None = None, title: str | None = None,
                 context: list | None = None, status: str | None = None,
                 summary: str | None = None, subtask: bool | None = None) -> None:
    """保存/更新会话。树相关列（parent_id/title/context/status/summary/subtask）
    只在显式传入时更新，避免普通落库把分支元数据冲掉。"""
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
        if subtask is not None:
            sets.append("subtask=?")
            vals.append(1 if subtask else 0)
        if row:
            vals.append(sid)
            c.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE id=?", vals)
        else:
            c.execute(
                "INSERT INTO sessions (id,project_id,task,target,state,created_at,"
                "parent_id,title,status,context,summary,subtask) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, project_id, task, target, state, time.time(),
                 parent_id or "", title or "", status or "active",
                 json.dumps(context or [], ensure_ascii=False), summary or "",
                 1 if subtask else 0),
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
    """彻底删除一条线索及其所有后代（子分支），并级联清理步骤、对话历史。

    **刻意不删 usage_log**：那是 token 消耗与调用的审计记录。若随会话一起删掉，
    就等于「删掉线索即可抹掉自己烧过多少钱、调过多少次模型」，成本审计失去可信度。
    这里把 session_id 置空，保留计数与时间戳（总量不丢），只是不再归属到已删会话。

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

        # 2) 级联删除（用量记录除外，见上）
        placeholders = ",".join("?" * len(to_delete))
        c.execute(f"DELETE FROM steps WHERE session_id IN ({placeholders})", to_delete)
        c.execute(f"DELETE FROM chat_messages WHERE session_id IN ({placeholders})", to_delete)
        c.execute(f"UPDATE usage_log SET session_id=NULL WHERE session_id IN ({placeholders})",
                  to_delete)
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
    """跨线索检索：在项目内的**工具执行 + 已证事实 + 项目情报**里搜关键词。

    供内置工具 search_history 使用，实现「新对话调取历史对话内容」。

    覆盖面（此前只搜 steps 一张表，比工具描述承诺的范围小得多，模型搜不到就会
    「以为没查过」而重新查一遍）：
      · steps —— 工具输出 / 参数 / 目标 / 工具名（工具执行记忆）
      · facts —— 已证事实正文（note_fact 记下的结论性记忆）
      · intel —— 项目情报库 JSON（跨会话沉淀的子域 / IP / API / 技术栈）
    事实与情报都带 kind 标记，调用方按类型渲染，模型才能分辨
    「这是工具原文，还是已证结论，还是沉淀过的资产清单」。
    """
    kw = (keyword or "").strip()
    if not kw or not project_id:
        return []
    like = f"%{kw}%"
    out: list[dict] = []
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
        for r in rows:
            d = dict(r)
            d["kind"] = "step"
            text = d.get("output") or ""
            pos = text.find(kw)
            if pos >= 0:
                start = max(0, pos - 120)
                d["snippet"] = ("…" if start else "") + text[start:pos + 220].strip() + "…"
            else:
                d["snippet"] = text[:220].strip()
            out.append(d)

        for r in c.execute(
            "SELECT id, content, session_id, step_id, created_at FROM facts"
            " WHERE project_id=? AND content LIKE ? ORDER BY created_at DESC LIMIT ?",
            (project_id, like, limit),
        ).fetchall():
            d = dict(r)
            d["kind"] = "fact"
            text = d.get("content") or ""
            pos = text.find(kw)
            start = max(0, pos - 60) if pos >= 0 else 0
            d["snippet"] = text[start:start + 300].strip()
            out.append(d)

        for r in c.execute(
            "SELECT data, updated_at FROM intel WHERE project_id=?", (project_id,)
        ).fetchall():
            try:
                data = json.loads(r["data"] or "{}")
            except Exception:
                data = {}
            if not isinstance(data, dict):
                continue
            for k, vals in data.items():
                if not isinstance(vals, list):
                    continue
                hit = [str(v) for v in vals if kw.lower() in str(v).lower()]
                if hit:
                    out.append({
                        "kind": "intel", "key": k, "matches": hit[:10],
                        "total": len(vals), "created_at": r["updated_at"],
                        "snippet": "、".join(hit[:10]),
                    })
    return out[: max(limit, 12)]


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
                detail: str = "", evidence: str = "", session_id: str = "") -> dict:
    fid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO findings (id,project_id,title,severity,target,detail,evidence,"
            "session_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (fid, project_id, title, severity, target, detail, evidence, session_id,
             time.time()),
        )
    return {"id": fid, "project_id": project_id, "title": title, "severity": severity,
            "target": target, "detail": detail, "evidence": evidence,
            "session_id": session_id}


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
def add_fact(project_id: str, content: str, source: str = "manual",
             session_id: str = "", step_id: str = "") -> dict:
    """记录一条「已证实的客观事实」（凭据/漏洞/敏感路径等）。source: manual | agent。

    session_id / step_id 是**因果图的连边依据**，不是可选装饰：
    带 step_id 才能连出 Evidence --REVEALS--> KeyFact，带 session_id 才能把
    同一条线索下的 KeyFact 与 Vulnerability 关联起来。丢了它们图不会报错，
    只会静默退化成一堆孤点，所以调用方必须尽量传。
    """
    content = content.strip()
    if not content:
        return {}
    fid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO facts (id,project_id,content,source,session_id,step_id,created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (fid, project_id, content, source, session_id, step_id, time.time()),
        )
    return {"id": fid, "project_id": project_id, "content": content, "source": source,
            "session_id": session_id, "step_id": step_id, "created_at": time.time()}


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


# ---------- 因果图（线索树的「因果图」视图：证据推理链） ----------
# 这一整段在 2026-09-16 那次更新里被漏掉了（app/store.py 被整体换成不含因果图
# 持久化的版本，而 app/graph.py 没被替换）。缺了它们，graph.py 里每一个
# store.upsert_causal_node / list_causal_nodes 调用都直接 AttributeError，
# 前端点「因果图」就是 500，且【服务启动、攻击图、其它接口都正常】——
# 属于典型的静默缺件。这里按本地谱系原样恢复，连接统一走 _db()（提交并关闭）。
def list_causal_nodes(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM causal_nodes WHERE project_id=? ORDER BY created_at ASC",
            (project_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["data"] = json.loads(d.get("data") or "{}")
        except (TypeError, ValueError):
            d["data"] = {}
        out.append(d)
    return out


def list_causal_edges(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM causal_edges WHERE project_id=? ORDER BY created_at ASC",
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_causal_node(project_id: str, node_id: str) -> dict | None:
    with _db() as c:
        r = c.execute(
            "SELECT * FROM causal_nodes WHERE project_id=? AND id=?", (project_id, node_id)
        ).fetchone()
    if not r:
        return None
    d = dict(r)
    try:
        d["data"] = json.loads(d.get("data") or "{}")
    except (TypeError, ValueError):
        d["data"] = {}
    return d


def upsert_causal_node(project_id: str, node: dict) -> dict:
    """按 id 插入或局部更新一个因果节点（未给字段保持不变）。"""
    node_id = (node.get("id") or "").strip()
    if not node_id:
        raise ValueError("因果节点缺少 id")
    now = time.time()
    exist = get_causal_node(project_id, node_id)
    payload = json.dumps(node.get("data") or {}, ensure_ascii=False)
    if exist is None:
        with _db() as c:
            c.execute(
                "INSERT INTO causal_nodes"
                " (id,project_id,node_type,title,description,status,confidence,severity,"
                "  session_id,source_step,data,created_at,updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (node_id, project_id, node.get("node_type", "Evidence"),
                 node.get("title", ""), node.get("description", ""),
                 node.get("status", "PENDING"), float(node.get("confidence", 0.5)),
                 node.get("severity", ""), node.get("session_id", ""),
                 node.get("source_step", ""), payload, now, now),
            )
    else:
        sets, vals = [], []
        for col in ("node_type", "title", "description", "status", "severity",
                    "session_id", "source_step"):
            if node.get(col) is not None:
                sets.append(f"{col}=?")
                vals.append(node[col])
        if node.get("confidence") is not None:
            sets.append("confidence=?")
            vals.append(float(node["confidence"]))
        if node.get("data"):
            sets.append("data=?")
            vals.append(payload)
        if sets:
            sets.append("updated_at=?")
            vals.extend([now, project_id, node_id])
            with _db() as c:
                c.execute(
                    f"UPDATE causal_nodes SET {', '.join(sets)}"
                    " WHERE project_id=? AND id=?", tuple(vals))
    return get_causal_node(project_id, node_id)


def update_causal_confidence(project_id: str, node_id: str,
                             confidence: float, status: str) -> dict | None:
    with _db() as c:
        c.execute(
            "UPDATE causal_nodes SET confidence=?, status=?, updated_at=?"
            " WHERE project_id=? AND id=?",
            (float(confidence), status, time.time(), project_id, node_id),
        )
    return get_causal_node(project_id, node_id)


def add_causal_edge(project_id: str, source_id: str, target_id: str, label: str,
                    strength: str = "contingent", description: str = "") -> dict:
    """加一条因果边。同一 (source,target,label) 已存在则更新，不重复插入。"""
    with _db() as c:
        row = c.execute(
            "SELECT id FROM causal_edges WHERE project_id=? AND source_id=?"
            " AND target_id=? AND label=?",
            (project_id, source_id, target_id, label),
        ).fetchone()
        if row:
            c.execute("UPDATE causal_edges SET strength=?, description=? WHERE id=?",
                      (strength, description, row["id"]))
            eid = row["id"]
        else:
            eid = uuid.uuid4().hex[:12]
            c.execute(
                "INSERT INTO causal_edges"
                " (id,project_id,source_id,target_id,label,strength,description,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (eid, project_id, source_id, target_id, label, strength,
                 description, time.time()),
            )
    return {"id": eid, "project_id": project_id, "source_id": source_id,
            "target_id": target_id, "label": label, "strength": strength,
            "description": description}


def delete_causal_node(project_id: str, node_id: str) -> bool:
    """删节点时一并删掉挂在它上面的边，避免留下悬空边（前端会画不出来）。"""
    with _db() as c:
        c.execute(
            "DELETE FROM causal_edges WHERE project_id=? AND (source_id=? OR target_id=?)",
            (project_id, node_id, node_id),
        )
        cur = c.execute(
            "DELETE FROM causal_nodes WHERE project_id=? AND id=?", (project_id, node_id))
    return cur.rowcount > 0


def delete_causal_nodes_by_prefix(project_id: str, prefix: str) -> int:
    """按 id 前缀清理（例如删除某条 fact 时同步清掉 fact:<id> 节点）。"""
    with _db() as c:
        rows = c.execute(
            "SELECT id FROM causal_nodes WHERE project_id=? AND id LIKE ?",
            (project_id, prefix + "%"),
        ).fetchall()
        ids = [r["id"] for r in rows]
        for nid in ids:
            c.execute(
                "DELETE FROM causal_edges WHERE project_id=? AND (source_id=? OR target_id=?)",
                (project_id, nid, nid),
            )
        if ids:
            c.execute(
                f"DELETE FROM causal_nodes WHERE project_id=? AND id IN"
                f" ({','.join('?' * len(ids))})",
                (project_id, *ids),
            )
    return len(ids)


def clear_causal(project_id: str) -> None:
    with _db() as c:
        c.execute("DELETE FROM causal_edges WHERE project_id=?", (project_id,))
        c.execute("DELETE FROM causal_nodes WHERE project_id=?", (project_id,))


def get_step(step_id: str) -> dict | None:
    """按 id 取一条执行步骤（因果图按 step_id 溯源时要用）。"""
    with _db() as c:
        r = c.execute("SELECT * FROM steps WHERE id=?", (step_id,)).fetchone()
    return dict(r) if r else None


def list_project_steps(project_id: str, limit: int = 400) -> list[dict]:
    """项目内全部执行步骤（带所属会话），供因果图派生 Evidence 节点用。"""
    with _db() as c:
        rows = c.execute(
            "SELECT st.id, st.session_id, st.tool_alias, st.tool_name, st.target,"
            " st.status, st.output, st.created_at"
            " FROM steps st JOIN sessions s ON s.id=st.session_id"
            " WHERE s.project_id=? ORDER BY st.created_at ASC LIMIT ?",
            (project_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


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
