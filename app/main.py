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

from . import config, providers, report, store
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


class ProjectUpdateRequest(BaseModel):
    """项目重命名 / 改目标：只传要改的字段，未传的保持原值。"""
    name: str | None = None
    target: str | None = None
    note: str | None = None


class FindingRequest(BaseModel):
    title: str
    severity: str = "中危"
    target: str = ""
    detail: str = ""
    evidence: str = ""


class FactRequest(BaseModel):
    content: str


class ModelRequest(BaseModel):
    backend: str


class SettingsLLMRequest(BaseModel):
    backend: str  # deepseek | anthropic
    base_url: str = ""
    api_key: str = ""
    model: str = ""


class ProviderRequest(BaseModel):
    """供应商配置。id 为空=新建；api_key 为打码值（含 …）视为不修改。"""
    id: str = ""
    name: str = ""
    type: str = "openai"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    thinking: bool | None = None
    local: bool | None = None
    enabled: bool | None = None
    timeout: int | None = None


class UseProviderRequest(BaseModel):
    id: str
    auto_route: bool | None = None      # 漏洞类任务是否自动路由云端
    auto_route_id: str | None = None    # 自动路由目标供应商 id


# ---------- 前端 ----------
@app.get("/")
async def index():
    return FileResponse(config.WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(config.WEB_DIR)), name="static")


# ---------- 状态 ----------
@app.get("/api/health")
async def health():
    # 用当前运行时选中的供应商做健康检查，不再硬绑本地 Ollama
    backend = get_backend()
    llm = await backend.health()
    cur = providers.current()
    return {
        "toolbox": str(config.TOOLBOX_ROOT),
        "toolbox_exists": config.TOOLBOX_ROOT.exists(),
        "registry": registry.stats(),
        "llm": llm,
        "current_backend": backend.name,
        "current_provider": cur["id"],
        "current_model": cur.get("model", ""),
        "deepseek_enabled": bool((providers.get("deepseek") or {}).get("api_key")),
        "anthropic_enabled": bool((providers.get("anthropic") or {}).get("api_key")),
        "provider_count": len(providers.list_providers()),
        "models": {p["id"]: p["model"] for p in providers.list_providers()},
    }


# ---------- 模型切换 ----------
@app.get("/api/models")
async def get_models():
    """列出所有已配置供应商与当前选择，供前端渲染下拉框。"""
    items = []
    for p in providers.list_providers():
        note = "本地私有部署，数据不出机器" if p["local"] else (
            "" if p["has_key"] else "需在「设置」填写 API Key")
        items.append({
            "name": p["id"],
            "label": p["name"],
            "model": p["model"],
            "type": p["type"],
            "local": p["local"],
            "builtin": p["builtin"],
            "available": p["configured"] and p["enabled"],
            "note": note,
        })
    return {"current": current_backend_name(), "items": items}


# ---------- LLM 设置（旧版兼容：DeepSeek Key / Anthropic 端点） ----------
def _mask(key: str) -> str:
    return providers.mask(key)


@app.get("/api/settings/llm")
async def get_llm_settings():
    """返回当前云端通道配置状态（密钥只回显打码）。"""
    ds = providers.get("deepseek") or {}
    anth = providers.get("anthropic") or {}
    return {
        "deepseek": {
            "has_key": bool(ds.get("api_key")),
            "key_file": str(config.LLM_PROVIDERS_FILE),
            "key_masked": providers.mask(ds.get("api_key", "")),
        },
        "anthropic": {
            "configured": bool(anth.get("base_url") and anth.get("api_key")),
            "base_url": anth.get("base_url", ""),
            "model": anth.get("model", ""),
            "has_key": bool(anth.get("api_key")),
            "key_masked": providers.mask(anth.get("api_key", "")),
            "file": str(config.LLM_PROVIDERS_FILE),
        },
    }


@app.post("/api/settings/llm")
async def save_llm_settings(req: SettingsLLMRequest):
    """写入云端通道配置（落到统一供应商配置里）。空字段表示保留原值。"""
    if req.backend == "deepseek":
        if not req.api_key.strip():
            raise HTTPException(400, "DeepSeek 需要填写 API Key")
        providers.upsert({"id": "deepseek", "api_key": req.api_key.strip()})
        return {"ok": True, "backend": "deepseek", "configured": True}
    if req.backend == "anthropic":
        cur = providers.get("anthropic") or {}
        base_url = (req.base_url.strip() or cur.get("base_url") or "").rstrip("/")
        api_key = req.api_key.strip() or cur.get("api_key", "")
        model = req.model.strip() or cur.get("model", "") or config.DEFAULT_ANTHROPIC_MODEL
        if not base_url or not api_key:
            raise HTTPException(400, "Base URL 与 API Key 均必填（模型可留空用默认）")
        providers.upsert({"id": "anthropic", "base_url": base_url,
                          "api_key": api_key, "model": model})
        return {"ok": True, "backend": "anthropic", "configured": True,
                "model": model, "base_url": base_url}
    raise HTTPException(400, "backend 仅支持 deepseek / anthropic")


# ---------- 通用 LLM 供应商管理 ----------
@app.get("/api/llm/presets")
async def list_presets():
    """厂商预设模板：OpenAI / DeepSeek / 通义 / GLM / Kimi / 火山 / 硅基流动 ……"""
    return {"items": providers.presets()}


@app.get("/api/llm/providers")
async def list_provider_api():
    c = providers.cfg()
    return {
        "items": providers.list_providers(),
        "current": c["current"],
        "auto_route": bool(c.get("auto_route", True)),
        "auto_route_id": c.get("auto_route_id", "deepseek"),
        "store_file": str(config.LLM_PROVIDERS_FILE),
    }


@app.post("/api/llm/providers")
async def create_or_update_provider(req: ProviderRequest):
    """新增（无 id）或更新（有 id）供应商。密钥打码回传，原文只落用户目录。"""
    data = req.model_dump(exclude_none=False)
    if not req.id and not (req.name or "").strip():
        raise HTTPException(400, "请填写供应商名称")
    try:
        p = providers.upsert(data)
    except Exception as e:
        raise HTTPException(500, f"保存失败：{e}")
    return {"ok": True, "provider": {k: v for k, v in p.items() if k != "api_key"}
            | {"has_key": bool(p.get("api_key")), "key_masked": providers.mask(p.get("api_key", ""))}}


@app.delete("/api/llm/providers/{pid}")
async def delete_provider(pid: str):
    if pid in providers.BUILTIN_IDS:
        raise HTTPException(400, "内置供应商不可删除，可在编辑里停用或点「恢复默认」")
    if not providers.delete(pid):
        raise HTTPException(404, "供应商不存在")
    return {"ok": True}


@app.post("/api/llm/providers/{pid}/reset")
async def reset_provider(pid: str):
    if pid not in providers.BUILTIN_IDS:
        raise HTTPException(400, "只有内置供应商支持恢复默认")
    return {"ok": providers.reset_builtin(pid)}


@app.post("/api/llm/providers/{pid}/use")
async def use_provider(pid: str, req: UseProviderRequest | None = None):
    """切换当前决策供应商（可同时设置漏洞类任务的自动路由目标）。"""
    if req and req.auto_route is not None:
        providers.set_auto_route(req.auto_route, req.auto_route_id or "")
    try:
        p = providers.set_current(pid)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "current": p["id"], "model": p.get("model", "")}


@app.post("/api/llm/providers/{pid}/test")
async def test_provider(pid: str):
    """连通性 + function calling 能力探测。会真实消耗极少量 token。"""
    p = providers.get(pid)
    if not p:
        raise HTTPException(404, "供应商不存在")
    backend = get_backend(pid)
    try:
        r = await backend.probe()
    except Exception as e:
        raise HTTPException(502, f"探测失败：{e}")
    return {"ok": r.get("chat", False), "id": pid,
            "chat": r.get("chat", False), "tools": r.get("tools", False),
            "models": r.get("models", []), "reply": r.get("reply", ""),
            "error": r.get("error", ""), "hint": r.get("hint", "")}


@app.get("/api/llm/providers/{pid}/models")
async def provider_models(pid: str):
    """拉取该供应商的可用模型列表（部分网关不开放 /models，失败会返回原因）。"""
    p = providers.get(pid)
    if not p:
        raise HTTPException(404, "供应商不存在")
    try:
        models = await get_backend(pid).list_models()
    except Exception as e:
        return {"ok": False, "models": [], "error": str(e)}
    return {"ok": True, "models": models, "current": p.get("model", "")}


@app.post("/api/models")
async def switch_model(req: ModelRequest):
    """切换 Agent 决策供应商（ollama / deepseek / 任意自定义 id），立即生效并持久化。"""
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
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(400, "项目名称不能为空")
    return store.create_project(name, (req.target or "").strip(), (req.note or "").strip())


@app.put("/api/projects/{pid}")
async def edit_project(pid: str, req: ProjectUpdateRequest):
    """重命名 / 改目标 / 改备注（只传要改的字段）。"""
    if req.name is not None and not req.name.strip():
        raise HTTPException(400, "项目名称不能为空")
    proj = store.update_project(
        pid,
        name=req.name.strip() if req.name is not None else None,
        target=req.target.strip() if req.target is not None else None,
        note=req.note.strip() if req.note is not None else None,
    )
    if not proj:
        raise HTTPException(404, "项目不存在")
    return proj


@app.delete("/api/projects/{pid}")
async def remove_project(pid: str):
    ok = store.delete_project(pid)
    if not ok:
        raise HTTPException(404, "项目不存在或已删除")
    return {"ok": True, "deleted": pid}


@app.get("/api/projects/{pid}")
async def project_detail(pid: str):
    proj = store.get_project(pid)
    if not proj:
        raise HTTPException(404, "项目不存在")
    return {
        "project": proj,
        "findings": store.list_findings(pid),
        "facts": store.list_facts(pid),
        "sessions": store.list_sessions(pid),
    }


@app.post("/api/projects/{pid}/facts")
async def add_fact(pid: str, req: FactRequest):
    return store.add_fact(pid, req.content, source="manual")


@app.delete("/api/projects/{pid}/facts/{fid}")
async def remove_fact(pid: str, fid: str):
    return {"ok": store.delete_fact(fid)}


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
