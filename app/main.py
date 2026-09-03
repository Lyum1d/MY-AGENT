# -*- coding: utf-8 -*-
"""FastAPI 后端：对话驱动 + SSE 实时输出 + 执行计划可视化。"""
from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, report, store
from .agent import agent, sessions
from .executor import executor
from .llm import current_backend_name, get_backend, set_backend
from .registry import registry

app = FastAPI(title="SRC 渗透 Agent", version="0.1.0")

registry.load()


# ---------- 请求模型 ----------
class RunRequest(BaseModel):
    message: str
    project_id: str = ""


class ConfirmRequest(BaseModel):
    approved: bool


class ProjectRequest(BaseModel):
    name: str
    target: str = ""
    note: str = ""


class FindingRequest(BaseModel):
    title: str
    severity: str = "中危"
    target: str = ""
    detail: str = ""
    evidence: str = ""


class ModelRequest(BaseModel):
    backend: str


# ---------- 前端 ----------
@app.get("/")
async def index():
    return FileResponse(config.WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(config.WEB_DIR)), name="static")


# ---------- 状态 ----------
@app.get("/api/health")
async def health():
    # 用当前运行时选中的后端做健康检查，不再硬绑本地 Ollama
    backend = get_backend()
    llm = await backend.health()
    return {
        "toolbox": str(config.TOOLBOX_ROOT),
        "toolbox_exists": config.TOOLBOX_ROOT.exists(),
        "registry": registry.stats(),
        "llm": llm,
        "current_backend": backend.name,
        "deepseek_enabled": bool(config.DEEPSEEK_API_KEY),
        "models": {"ollama": config.OLLAMA_MODEL, "deepseek": config.DEEPSEEK_MODEL},
    }


# ---------- 模型切换 ----------
@app.get("/api/models")
async def get_models():
    """列出可选后端与当前选择，供前端渲染下拉框。"""
    return {
        "current": current_backend_name(),
        "items": [
            {
                "name": "ollama",
                "label": "本地模型",
                "model": config.OLLAMA_MODEL,
                "available": True,
                "note": "无需联网，数据不出本机；决策较慢（13-25s/步）",
            },
            {
                "name": "deepseek",
                "label": "云端模型",
                "model": config.DEEPSEEK_MODEL,
                "available": bool(config.DEEPSEEK_API_KEY),
                "note": "" if config.DEEPSEEK_API_KEY else "需设置环境变量 DEEPSEEK_API_KEY",
            },
        ],
    }


@app.post("/api/models")
async def switch_model(req: ModelRequest):
    """切换 Agent 决策后端（ollama / deepseek），立即生效并持久化。"""
    try:
        b = set_backend(req.backend)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "current": b.name, "model": getattr(b, "model", "")}


@app.get("/api/tools")
async def list_tools(kind: str = "all"):
    """kind: all | scriptable | launchable | web"""
    if kind == "scriptable":
        items = registry.scriptable_tools()
    elif kind == "launchable":
        items = registry.launchable_tools()
    elif kind == "web":
        items = registry.web_tools()
    else:
        items = registry.tools
    return {"items": [t.to_dict() for t in items], "count": len(items)}


@app.post("/api/tools/launch/{alias}")
async def launch_tool(alias: str):
    """一键启动图形界面工具（不取回输出）。"""
    tool = registry.get_by_alias(alias)
    if not tool:
        raise HTTPException(404, f"工具不存在：{alias}")
    if not tool.executable:
        raise HTTPException(400, f"该工具没有可执行文件（可能是网页工具）：{tool.name}")
    return await executor.launch(tool)


# ---------- 项目 ----------
@app.get("/api/projects")
async def get_projects():
    return {"items": store.list_projects()}


@app.post("/api/projects")
async def new_project(req: ProjectRequest):
    return store.create_project(req.name, req.target, req.note)


@app.delete("/api/projects/{pid}")
async def remove_project(pid: str):
    return {"ok": store.delete_project(pid)}


@app.get("/api/projects/{pid}")
async def project_detail(pid: str):
    proj = store.get_project(pid)
    if not proj:
        raise HTTPException(404, "项目不存在")
    return {
        "project": proj,
        "findings": store.list_findings(pid),
        "sessions": store.list_sessions(pid),
    }


@app.post("/api/projects/{pid}/findings")
async def add_finding(pid: str, req: FindingRequest):
    return store.add_finding(pid, req.title, req.severity, req.target, req.detail, req.evidence)


@app.delete("/api/projects/{pid}/findings/{fid}")
async def remove_finding(pid: str, fid: str):
    return {"ok": store.delete_finding(fid)}


@app.get("/api/projects/{pid}/report")
async def get_report(pid: str):
    return {"markdown": report.render_project_report(pid)}


@app.post("/api/projects/{pid}/report/export")
async def export_report(pid: str):
    path = report.export_report(pid)
    return {"path": path}


# ---------- 会话与 Agent ----------
@app.post("/api/sessions")
async def create_session(project_id: str = ""):
    s = sessions.create(project=project_id)
    return {"session_id": s.id}


@app.post("/api/sessions/{sid}/run")
async def run_session(sid: str, req: RunRequest):
    s = sessions.get(sid)
    if not s:
        raise HTTPException(404, "会话不存在")
    if s.state == "running":
        raise HTTPException(409, "该会话正在执行中")

    s.project = req.project_id
    asyncio.create_task(_run_agent(s, req.message, req.project_id))
    return {"ok": True, "session_id": sid}


async def _run_agent(session, message: str, project_id: str):
    """后台执行 Agent，并在结束后落库。"""
    try:
        await agent.run(session, message)
    except Exception as e:
        await session.emit({"type": "error", "data": f"Agent 异常：{e}"})
        await session.emit({"type": "done", "state": "error"})
    finally:
        store.save_session(session.id, project_id, message, session.target, session.state)
        for st in session.steps:
            store.save_step(session.id, agent._step_dict(st))


@app.get("/api/sessions/{sid}/stream")
async def stream_session(sid: str):
    """SSE：实时推送思考、命令、输出、确认请求与结论。"""
    s = sessions.get(sid)
    if not s:
        raise HTTPException(404, "会话不存在")

    async def gen() -> AsyncIterator[str]:
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(s.events.get(), timeout=30)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
                if ev.get("type") == "done":
                    break
        except asyncio.CancelledError:
            return

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    })


@app.post("/api/sessions/{sid}/confirm")
async def confirm_step(sid: str, req: ConfirmRequest):
    s = sessions.get(sid)
    if not s:
        raise HTTPException(404, "会话不存在")
    await s.control.put({"approved": req.approved})
    return {"ok": True}


@app.get("/api/sessions/{sid}")
async def session_state(sid: str):
    s = sessions.get(sid)
    if s:
        return {
            "id": s.id,
            "state": s.state,
            "target": s.target,
            "steps": [agent._step_dict(x) for x in s.steps],
        }
    # 回退到持久化层：服务重启后内存会话已清空，但 store 里仍有记录
    rec = store.get_session(sid)
    if not rec:
        raise HTTPException(404, "会话不存在")
    sess = rec["session"]
    return {
        "id": sess["id"],
        "state": sess.get("state"),
        "target": sess.get("target"),
        "steps": rec["steps"],
    }
