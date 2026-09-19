# -*- coding: utf-8 -*-
"""FastAPI 后端：对话驱动 + SSE 实时输出 + 执行计划可视化。"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import AsyncIterator
from urllib.parse import urlparse, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, providers, report, scope, store, usage
from . import graph, ratelimit, secretbox
from . import difftest, flowtest
from .importers import common as importers_common
from .agent import agent, sessions
from .executor import executor
from .llm import current_backend_name, get_backend, set_backend
from .registry import registry

app = FastAPI(title="SRC 渗透 Agent", version="0.1.0")

logger = logging.getLogger(__name__)

registry.load()


# ---------- 本地访问防护 ----------
# 本服务能调度命令行工具与任意 Python 代码（L3），所以即便只监听 127.0.0.1，
# 也必须在应用层挡住「同一浏览器里的其他网页」发来的请求（CSRF）和 DNS 重绑定：
#   1) Host 校验：仅本机绑定时，Host 必须是回环名。恶意站点把自有域名解析到
#      127.0.0.1（DNS rebinding）后，浏览器发出的请求 Host 是攻击者域名，这里直接拒。
#   2) 来源校验：带 Origin / Referer 的请求，其主机必须与 Host 一致，否则判定为跨站并拒绝。
#      浏览器对跨站 POST（含表单）一定会带上 Origin，因此这条能拦住「打开恶意网页
#      就往 localhost 发请求」的路径。
# CLI 客户端（curl / 测试脚本）通常不带这两个头，因此不受影响。
# 注意：这里没有引入访问令牌，非浏览器本地客户端仍无鉴权；如需更强，可在此基础上
# 增加 X-Auth-Token 校验（前端统一在 fetch 时带上）。
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _host_only(netloc: str) -> str:
    """取 netloc 的主机部分（去掉端口，保留 IPv6 方括号）。"""
    s = (netloc or "").strip().lower()
    if not s:
        return ""
    if s.startswith("["):
        return s.split("]", 1)[0] + "]"
    return s.split(":", 1)[0]


def _loopback_bind() -> bool:
    return (config.HOST or "").strip().lower() in _LOOPBACK_HOSTS


@app.middleware("http")
async def remote_access_token_guard(request, call_next):
    """非回环绑定时，全站要求 Bearer 访问令牌（006 血统，与 run.py 的守卫成对）。

    上面那道 local_request_guard 只在「绑回环」时生效；一旦 HOST=0.0.0.0 它整条失效，
    而本服务能调度命令行扫描工具、还能执行任意 Python 代码，等于把一台扫描
    跳板机交给整个网段。因此远程模式（ALLOW_REMOTE=1）下必须带 SRC_AGENT_TOKEN，
    否则一律 401。回环绑定完全不受影响，本地前端 / CLI 无需任何改动。
    """
    if not _loopback_bind():
        if not config.ACCESS_TOKEN:
            return JSONResponse(
                {"detail": "服务绑定了非回环地址但未设置 SRC_AGENT_TOKEN，已拒绝所有请求。"},
                status_code=401)
        if request.headers.get("authorization") != f"Bearer {config.ACCESS_TOKEN}":
            return JSONResponse(
                {"detail": "未授权：缺少或错误的访问令牌。"}, status_code=401)
    response = await call_next(request)
    # 前端静态资源禁用启发式强缓存（2026-09-18 线索图黑块事故）：
    # Chromium 对无 Cache-Control 的静态资源会启发式缓存，服务端更新文件后
    # 浏览器仍直接吃本地缓存（不发请求、不看 ETag）——表现为「新版页面 +
    # 旧版 CSS」混合渲染：图节点全黑块、弹窗布局错乱。no-cache 保留 ETag
    # 协商缓存（文件没变走 304，不吃流量），变了立即生效。
    if request.url.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-cache"
    return response



@app.middleware("http")
async def local_request_guard(request, call_next):
    host = request.headers.get("host", "")
    # 1) DNS 重绑定防护：仅本机绑定时才强制 Host 为回环名
    if _loopback_bind() and _host_only(host) not in _LOOPBACK_HOSTS:
        return JSONResponse(
            {"detail": f"拒绝非本机 Host 的访问（Host: {host}）。本服务仅限本机使用。"},
            status_code=403)
    # 2) 跨站请求防护：来源主机必须与 Host 一致
    source = request.headers.get("origin") or request.headers.get("referer") or ""
    if source:
        try:
            src_host = _host_only(urlparse(source).netloc)
        except Exception:
            src_host = ""
        if src_host != _host_only(host):
            return JSONResponse(
                {"detail": "拒绝跨站请求：请求来源与本站不一致。"}, status_code=403)
    return await call_next(request)


# ---------- 请求模型 ----------
class RunRequest(BaseModel):
    message: str
    project_id: str = ""


class ConfirmRequest(BaseModel):
    """高危步骤的放行/拒绝（双闸门：一次性 token + 步骤归属 step_id）。

    step_id 必填：确认通道是「一次一步」的交互式队列，若不绑定步骤身份，
    任何时刻投递的确认（陈旧点击、重放、脚本伪造）都会躺在队列里被**下一个**
    高危步骤消费掉，等于绕过 L2/L3 授权闸门。
    token：由 need_confirm 事件下发的一次性令牌，必须原样回传；缺失/不匹配 409。
    args：用户在确认框里改过的参数。None = 未修改，按原参数执行。
          只允许改 args（命令/参数串），不允许改工具与风险等级——闸门的判定依据
          不能由被审对象提供，否则等于把红线交给被审查方自己填。
    auth_ack：L3 二次确认（书面授权确认）。仅在该步骤 risk.double_confirm 为真时
          要求为 True；此前这个勾选只存在于前端 JS 里、后端从不校验，直接 POST
          {"approved": true} 即可绕过整道闸门，现在改由服务端强制。
    """
    approved: bool
    step_id: str = ""
    args: str | None = None
    token: str = ""
    auth_ack: bool = False


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
    session_id: str = ""     # 登记时的线索，用于因果图里和该线索的关键事实连边
    # ---- v012 P1-1 状态模型与结构化字段 ----
    # AI 只能产候选：无论谁调用，不显式传 confirmed 都按 draft 落库，
    # 走 /review 接口人工确认后才进正式报告的「已确认」章节。
    status: str = "draft"
    vuln_type: str = ""      # 漏洞类型（SQL 注入/弱口令/未授权…），驱动修复建议模板
    cwe: str = ""            # 如 CWE-89
    cvss: str = ""           # 如 8.6 或 CVSS:3.1/AV:N/AC:L/...
    impact_scope: str = ""   # 影响范围
    reproduction: str = ""   # 复现步骤（逐条）
    remediation: str = ""    # 修复建议（留空则按 vuln_type 套模板）


class ReviewRequest(BaseModel):
    """人工复核请求（事实/漏洞通用）：action 取值见 store.review_*。"""
    action: str              # facts: verified|rejected|candidate；findings: confirmed|needs_review|closed|draft
    note: str = ""           # 复核备注（findings 专用，落 review_note）


class FactRequest(BaseModel):
    content: str
    session_id: str = ""
    step_id: str = ""        # 产出该事实的工具执行步骤，因果图据此连 Evidence→KeyFact


class CausalUpdateRequest(BaseModel):
    """因果图增量写入：nodes 先落库，edges 再连接（端点不存在会被丢弃）。"""
    nodes: list[dict] = []
    edges: list[dict] = []


class ModelRequest(BaseModel):
    backend: str


class SessionCreateRequest(BaseModel):
    """创建会话。sid 传入时表示「续聊已有会话」（从持久化层恢复，对话树切线索用）。"""
    sid: str = ""
    project_id: str = ""


class BranchRequest(BaseModel):
    """从父会话开新线索：title 线索名；record_ids 要打包带走的步骤 id；extra_note 额外说明。"""
    title: str
    record_ids: list[str] = []
    extra_note: str = ""


class SessionMetaRequest(BaseModel):
    """线索标题/状态更新。status: active | done | abandoned"""
    title: str | None = None
    status: str | None = None


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
    # 授权边界的可视性：fail-closed 的白名单如果配错（为空 / 与实际靶标不符），
    # 现象是「所有工具都被拒」，而排查时最省事的"修复"是关掉 ENFORCE_SCOPE，
    # 那等于把授权红线整体关停且无人察觉。这里把真实状态暴露出来，
    # 让「没配授权」和「校验被关了」这两件事都看得见，而不是靠猜。
    scope_domains = scope.load_scope()
    scope_warn = ""
    if not config.ENFORCE_SCOPE:
        scope_warn = ("授权校验已被关闭（ENFORCE_SCOPE=0）：工具会对**任意目标**执行，"
                      "不受 data/scope.json 约束。仅应在临时排查时使用。")
    elif not scope_domains:
        scope_warn = ("授权白名单为空（data/scope.json 缺失或解析失败）：所有命令行工具、"
                      "HTTP 重放器与 py_exec 都会被拒绝执行。")
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
        # 编排参数也一并暴露：这些值以前只存在于 config.py，用户撞到「N 步就停」时
        # 在界面上看不到生效值、也无从判断是被哪个闸门拦住的。放在 health 里，
        # 前端设置页与排障都能直接读到（改值仍走环境变量，见 README）。
        "orchestration": {
            "execution_mode": config.EXECUTION_MODE,
            "max_steps": config.MAX_STEPS,
            "budget_remind_at": config.BUDGET_REMIND_AT,
            "failure_switch_threshold": config.FAILURE_SWITCH_THRESHOLD,
            "failure_stop_threshold": config.FAILURE_STOP_THRESHOLD,
            "think_streak_max": config.THINK_STREAK_MAX,
            "run_token_budget": config.RUN_TOKEN_BUDGET,
            "history_compress_after_messages": config.HISTORY_COMPRESS_AFTER_MESSAGES,
            "history_keep_recent": config.HISTORY_KEEP_RECENT,
            "subtask_max_concurrency": config.SUBTASK_MAX_CONCURRENCY,
            "subtask_max_steps": config.SUBTASK_MAX_STEPS,
        },
        "enforce_scope": bool(config.ENFORCE_SCOPE),
        "scope_domains": scope_domains,
        "scope_warning": scope_warn,
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
async def launch_tool(alias: str, confirm: bool = False):
    """一键启动图形界面工具（不取回输出）。

    历史实现只校验「文件存在」就直接 spawn，完全不看风险分级——
    而这里能启动的工具包含本属 L2/L3 的可编排工具，等价于绕过整套风险闸门
    执行本机程序（L3 的 py_exec 反倒要用户二次确认，此处却不要，属明显不一致）。
    现对齐同一条规则：L2/L3 必须带 confirm=true 才放行（前端二次确认后传参）。
    """
    tool = registry.get_by_alias(alias)
    if not tool:
        raise HTTPException(404, f"工具不存在：{alias}")
    if not tool.executable:
        raise HTTPException(400, f"该工具没有可执行文件（可能是网页工具）：{tool.name}")
    risk = registry.risk_of(tool.alias) or {}
    if not risk.get("auto", False) and not confirm:
        raise HTTPException(
            409,
            f"「{tool.name}」风险等级 {risk.get('level', '?')}（{risk.get('name', '需确认')}），"
            f"启动前需要显式确认：请带上 confirm=true 重试。",
        )
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
    rec = store.add_fact(pid, req.content, source="manual",
                         session_id=req.session_id, step_id=req.step_id)
    if rec:
        graph.on_fact_added(pid, rec)      # 因果图同步长出「关键事实」节点
    return rec


@app.delete("/api/projects/{pid}/facts/{fid}")
async def remove_fact(pid: str, fid: str):
    # v010 P1-3：删除前校验项目存在 + 记录归属（store 层 WHERE 双条件兜底），
    # 跨项目的 fid 一律 404，不再「拿着别人的 ID 就能删别人的数据」。
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    ok = store.delete_fact(pid, fid)
    if not ok:
        raise HTTPException(404, "事实不存在或不属于该项目")
    graph.on_fact_deleted(pid, fid)
    return {"ok": True}


@app.post("/api/projects/{pid}/findings")
async def add_finding(pid: str, req: FindingRequest):
    # v012 P1-1：status 只接受合法值；remediation 留空时按 vuln_type 套修复建议模板
    if req.status not in ("draft", "needs_review", "confirmed", "closed"):
        raise HTTPException(400, "status 仅支持 draft/needs_review/confirmed/closed")
    remediation = req.remediation or report.remediation_for(req.vuln_type)
    rec = store.add_finding(pid, req.title, req.severity, req.target,
                            req.detail, req.evidence, session_id=req.session_id,
                            status=req.status, vuln_type=req.vuln_type, cwe=req.cwe,
                            cvss=req.cvss, impact_scope=req.impact_scope,
                            reproduction=req.reproduction, remediation=remediation)
    graph.on_finding_added(pid, rec)
    return rec


@app.post("/api/projects/{pid}/findings/{fid}/review")
async def review_finding(pid: str, fid: str, req: ReviewRequest):
    """人工复核漏洞（v012 P1-1）：确认后方可进正式报告的「已确认漏洞」章节。

    v017.4 硬闸门：action=confirmed 时五项 checklist 必须全部勾选——
    「可重复/权限差异明确/最小复现链/只读或无损害/影响可证明」缺任何一项
    都拒绝确认（400），防止半证据漏洞流进正式报告。
    """
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    if req.action == "confirmed" and not store.checks_complete(fid):
        raise HTTPException(
            400, "五项复核清单未完成（可重复/权限差异/复现链/只读或无损害/影响可证明），"
                 "请先在复核清单中逐项确认后再执行确认。")
    rec = store.review_finding(pid, fid, req.action, req.note)
    if rec is None:
        raise HTTPException(404, "漏洞发现不存在或不属于该项目")
    return rec


@app.post("/api/projects/{pid}/facts/{fid}/review")
async def review_fact(pid: str, fid: str, req: ReviewRequest):
    """人工复核事实（v012 P1-1）：candidate 可转 verified/rejected。"""
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    rec = store.review_fact(pid, fid, req.action)
    if rec is None:
        raise HTTPException(404, "事实不存在或不属于该项目")
    return rec


@app.delete("/api/projects/{pid}/findings/{fid}")
async def remove_finding(pid: str, fid: str):
    # v010 P1-3：同 remove_fact——项目存在性 + 记录归属双重校验
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    ok = store.delete_finding(pid, fid)
    if not ok:
        raise HTTPException(404, "漏洞发现不存在或不属于该项目")
    graph.on_finding_deleted(pid, fid)
    return {"ok": True}


# ---------- 线索图（攻击图 / 因果图） ----------
# 这 4 个路由在 2026-09-16 拉取上游（Lyum1d/MY-AGENT）时被整体覆盖掉了，
# 而本地自研的 app/graph.py 与 web/graph.js 都没被替换 —— 结果 graph.py 成了
# 没人调用的孤儿模块，前端「线索图」视图连同入口一起消失。这里恢复路由。
@app.get("/api/projects/{pid}/graph/attack")
async def get_attack_graph(pid: str):
    """攻击图：项目为根，每条线索一个节点，边表示分支父子关系。"""
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return graph.build_attack_graph(pid)


@app.get("/api/projects/{pid}/graph/causal")
async def get_causal_graph(pid: str):
    """因果图：证据 → 关键事实 → 漏洞 的推理链。"""
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return graph.build_causal_graph(pid)


@app.post("/api/projects/{pid}/graph/causal")
async def update_causal_graph(pid: str, req: CausalUpdateRequest):
    """写入因果节点与边（Agent 或人工补充线索用）。

    边 label 会归一化（FALSIFIES→CONTRADICTS 等），
    SUPPORTS/CONTRADICTS 会触发目标节点的置信度传播。
    """
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return graph.apply_updates(pid, req.model_dump())


@app.post("/api/projects/{pid}/graph/causal/derive")
async def derive_causal_graph(pid: str):
    """从已有的工具执行、已证事实、漏洞发现派生整张因果图（会先清空重建）。"""
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return graph.derive(pid)


@app.get("/api/projects/{pid}/report")
async def get_report(pid: str):
    return {"markdown": report.render_project_report(pid)}

@app.post("/api/projects/{pid}/report/export")
async def export_report(pid: str):
    path = report.export_report(pid)
    return {"path": path}


# ---------- Token 用量统计 ----------
@app.get("/api/usage/summary")
async def usage_summary():
    """三档汇总（今日/本月/累计）+ 分模型 + 分项目聚合。费用为按单价表的估算值。"""
    return usage.summary()


@app.get("/api/usage/daily")
async def usage_daily(days: int = 30):
    """按天聚合（最近 N 天，空天补 0），供趋势图。"""
    return {"items": usage.daily(max(1, min(days, 90)))}


@app.get("/api/usage/list")
async def usage_list(project_id: str = "", model: str = "", days: int = 0, limit: int = 300):
    """逐条调用明细（倒序）。"""
    return {"items": store.list_usage(project_id=project_id, model=model,
                                      days=days, limit=min(limit, 2000))}


class UsagePriceItem(BaseModel):
    input: float = 0.0
    output: float = 0.0


class UsagePricesRequest(BaseModel):
    prices: dict[str, UsagePriceItem]  # key: 模型名或 provider/model；单位 元/百万 token


@app.get("/api/usage/prices")
async def usage_prices_get():
    return {"items": usage._load_prices(), "defaults": usage.DEFAULT_PRICES}


@app.post("/api/usage/prices")
async def usage_prices_set(req: UsagePricesRequest):
    """覆盖保存单价表（人民币 元/百万 token；输入/输出分开）。"""
    usage.save_prices({k: v.model_dump() for k, v in req.prices.items()})
    return {"ok": True, "items": usage._load_prices()}


@app.post("/api/usage/prices/reset")
async def usage_prices_reset():
    usage.reset_prices()
    return {"ok": True, "items": usage._load_prices()}


@app.post("/api/usage/clear")
async def usage_clear(days: int = 0):
    """清空用量记录；days>0 表示只删除 N 天前的旧记录（保留最近 N 天）。"""
    deleted = store.clear_usage(days=max(0, days))
    return {"ok": True, "deleted": deleted}


@app.get("/api/usage/export.csv")
async def usage_export():
    """导出全部明细为 CSV（Excel 友好，UTF-8 BOM）。"""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["时间", "项目", "会话", "供应商", "模型", "输入tokens", "输出tokens", "耗时ms"])
    name_map = {p["id"]: p["name"] for p in store.list_projects()}
    for r in store.list_usage(limit=5000):
        w.writerow([
            datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
            name_map.get(r["project_id"], r["project_id"] or "未关联项目"),
            r["session_id"], r["provider_id"], r["model"],
            r["prompt_tokens"], r["completion_tokens"], r["duration_ms"],
        ])
    from fastapi.responses import Response
    return Response(content="\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=usage_export.csv"})


# ---------- 会话与 Agent ----------
@app.post("/api/sessions")
async def create_session(req: SessionCreateRequest | None = None):
    """新建会话；body 带 sid 时改为「恢复已有会话」继续聊（对话树切换线索）。"""
    if req and req.sid:
        s = sessions.adopt(req.sid)
        if not s:
            raise HTTPException(404, "会话不存在")
        if req.project_id:
            s.project = req.project_id
        return {"session_id": s.id, "adopted": True}
    s = sessions.create(project=(req.project_id if req else "") or "")
    return {"session_id": s.id}


def _branch_records(sid: str, req: BranchRequest) -> tuple[str, str, list[str]]:
    """汇集开分支要打包的记录：选中的步骤摘要 + 额外说明。返回 (project_id, 父任务, 记录列表)。"""
    s = sessions.get(sid)
    row = store.get_session_row(sid)
    project_id = (s.project if s else "") or (row.get("project_id") or "" if row else "")
    task = (row.get("task") or "") if row else ""
    # 步骤合并持久化层与内存会话（同 id 以内存为准）：
    # 内存会话可能在 adopt 后没跑过新步骤，store 里反而更全
    steps: list[dict] = []
    if row:
        rec = store.get_session(sid)
        steps = rec["steps"] if rec else []
    if s:
        mem = {agent._step_dict(st)["id"]: agent._step_dict(st) for st in s.steps}
        by_id = {st["id"]: st for st in steps}
        by_id.update(mem)
        steps = list(by_id.values())
    by_id = {st["id"]: st for st in steps}
    records: list[str] = []
    for rid in req.record_ids:
        st = by_id.get(rid)
        if not st:
            continue
        output = (st.get("output") or "").strip()[:400]
        records.append(
            f"[{st.get('tool_name') or st.get('tool_alias')} → {st.get('target') or '-'}]"
            f"{' 参数: ' + st['args'] if st.get('args') else ''}"
            f"{(' 输出摘要: ' + output) if output else ''}"
        )
    if req.extra_note.strip():
        records.insert(0, req.extra_note.strip()[:500])
    if not records and task:
        records.append(f"上级任务：{task[:200]}")
    if not records:
        records.append("（上级对话未提供具体记录）")
    return project_id, task, records


@app.post("/api/sessions/{sid}/branch")
async def create_branch_api(sid: str, req: BranchRequest):
    """开新线索：把选中记录打包写入新会话的 context，新线索独立推进。"""
    title = (req.title or "").strip()
    if not title:
        raise HTTPException(400, "请填写线索名称")
    if not sessions.get(sid) and not store.get_session_row(sid):
        raise HTTPException(404, "父会话不存在")
    project_id, _task, records = _branch_records(sid, req)
    branch = store.create_branch(sid, project_id, title, records)
    return {"ok": True, "session_id": branch["id"], "title": branch["title"],
            "records": records}


@app.get("/api/projects/{pid}/tree")
async def project_tree(pid: str):
    """项目的会话树（前端小地图数据源）。"""
    return {"items": store.list_tree(pid)}


@app.delete("/api/sessions/{sid}")
async def delete_session(sid: str):
    """彻底删除一条线索分支（含其下所有子分支）及关联数据。"""
    if not store.get_session_row(sid):
        raise HTTPException(404, "会话不存在")
    # 运行中的会话不能删：Agent 协程还持有该 Session 对象，每步都会 store.save_step，
    # 删掉之后它会继续往已删除的 session_id 上写，留下没人能清理的孤儿行。
    s = sessions.get(sid)
    if s and s.state in ("running", "awaiting_confirm"):
        raise HTTPException(409, f"该线索正在执行中（{s.state}），请先等它结束或停止后再删除")
    result = store.delete_session_tree(sid)
    # 同步清理内存中的运行态会话
    for dsid in result.get("deleted_ids", []):
        sessions.remove(dsid)
    # 若当前活动线索被删，前端下次交互会重新选择；这里不做强制跳转
    return {"ok": True, "deleted": result["count"], "ids": result["deleted_ids"]}


@app.put("/api/sessions/{sid}/meta")
async def update_session_meta(sid: str, req: SessionMetaRequest):
    """线索改名/改状态（active | done | abandoned）。"""
    try:
        row = store.update_session_meta(sid, title=req.title, status=req.status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not row:
        raise HTTPException(404, "会话不存在")
    s = sessions.get(sid)
    if s and req.title:
        s.title = row["title"]  # 运行态(state)与线索状态(status)是两回事，互不影响
    return {"ok": True, "session": row}


@app.post("/api/sessions/{sid}/run")
async def run_session(sid: str, req: RunRequest):
    s = sessions.get(sid)
    if not s:
        raise HTTPException(404, "会话不存在")
    # awaiting_confirm 也必须挡：此时 Agent 协程还活着，再起一个会与它**共用**
    # 同一个 events/control 队列 —— 两个循环抢同一条确认队列、事件交叉、步骤双写。
    if s.state in ("running", "awaiting_confirm"):
        raise HTTPException(409, f"该会话正在执行中（{s.state}）")

    # 只在**非空**时覆盖项目归属。原实现无条件赋值，于是前端未选项目（project_id=""）时
    # 会把已有归属抹掉：项目情报库 / 已证事实不再注入系统提示、步骤也不再归属该项目，
    # 现象是「Agent 突然开始重复收集已知信息」，而日志里没有任何异常。
    if req.project_id:
        s.project = req.project_id
    # 传 s.project 而不是 req.project_id：_run_agent 结束时会用它落库，
    # 传原始请求值的话，空 project_id 会把库里的项目归属一并写空（内存保住了、库里没了）。
    asyncio.create_task(_run_agent(s, req.message, s.project))
    return {"ok": True, "session_id": sid}


async def _run_agent(session, message: str, project_id: str):
    """后台执行 Agent，并在结束后落库。"""
    try:
        await agent.run(session, message)
    except Exception as e:
        await session.emit({"type": "error", "data": f"Agent 异常：{e}"})
        await session.emit({"type": "done", "state": "error"})
    finally:
        # 记忆沉淀必须放 finally：原先「情报库」与「结论摘要」只在 run() 的正常收尾路径写，
        # 模型调用一旦报错（402 / 限流 / 超时）就整轮跳过 —— 实测有一轮 3 步全部成功、
        # 产出 57 条存活子域，情报库仍然是 0 行，而且没有任何提示。
        # 而同期写入的「已证事实 + 因果图」走的是执行中同步落库，反而留住了，
        # 于是同一次中断里一半记忆活着、一半没了。
        # merge_intel 按类去重，重复调用是安全的（run() 正常收尾时已经调过一次）。
        try:
            agent._persist_intel(session)
            if session.state == "error":
                agent.persist_interrupted(session, reason="模型调用失败或任务异常结束")
        except Exception:
            logger.exception("记忆沉淀失败（不影响步骤落库）")
        store.save_session(session.id, project_id, message, session.target, session.state)
        for st in session.steps:
            store.save_step(session.id, agent._step_dict(st))


@app.get("/api/sessions/{sid}/review")
async def session_review(sid: str):
    """会话复盘：token / 耗时 / 步骤成败 / 失败归因分布 / 情报增量。

    纯读库统计，不调用模型，因此打开复盘不花一分钱 token。
    """
    r = store.session_review(sid)
    if not r.get("title") and not r.get("steps") and not r.get("messages"):
        # 完全没有记录的会话（既无标题也无步骤也无论述）按不存在处理
        if not store.get_session_row(sid):
            raise HTTPException(404, "会话不存在")
    return r


# ---------- 请求库导入（v017.1：Burp XML / HAR） ----------
class ImportCommitRequest(BaseModel):
    """commit 与 preview 使用同样的文件内容——服务端重新解析（避免大 JSON 回传），

    两轮解析结果一致；commit 只入库 scope_status=allowed 且未标记 duplicate 的
    记录（除非 include_duplicates=True）。
    """
    filename: str
    content_base64: str
    include_duplicates: bool = False


@app.post("/api/projects/{pid}/imports/preview")
async def imports_preview(pid: str, req: ImportCommitRequest):
    """导入预览：解析 + scope 过滤 + 去重统计，**不入库**。

    返回每条记录的脱敏摘要与 scope_status，由用户确认后再 commit。
    """
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    try:
        records, stat = importers_common.parse_import_file(req.filename, req.content_base64)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "stat": stat,
        "requests": [
            {k: rec.get(k) for k in ("method", "url", "normalized_url", "scope_status",
                                     "object_candidates", "tags", "status_code",
                                     "content_type")}
            for rec in records[:500]   # 预览截断，防止超大导入拖死前端
        ],
        "truncated": len(records) > 500,
    }


@app.post("/api/projects/{pid}/imports/commit")
async def imports_commit(pid: str, req: ImportCommitRequest):
    """确认入库：只收 scope_status=allowed 的记录（rejected 仅保留统计）。

    scope 校验在预览与 commit 各做一次（同一代码路径），执行阶段（v017.3
    差分执行）还会再校验一次——导入/执行双重闸门。
    """
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    try:
        records, stat = importers_common.parse_import_file(req.filename, req.content_base64)
    except ValueError as e:
        raise HTTPException(400, str(e))
    inserted = 0
    for rec in records:
        if rec["scope_status"] != "allowed":
            continue
        if "duplicate" in rec.get("tags", []) and not req.include_duplicates:
            continue
        store.add_request(pid, rec)
        inserted += 1
    return {"stat": stat, "inserted": inserted}


@app.get("/api/projects/{pid}/requests")
async def list_requests(pid: str, scope_status: str = "", method: str = "",
                        limit: int = 200):
    """请求库列表（脱敏副本；凭据永远只是占位符）。"""
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return {"items": store.list_requests(pid, scope_status=scope_status,
                                         method=method, limit=limit)}


@app.delete("/api/projects/{pid}/requests/{rid}")
async def delete_request(pid: str, rid: str):
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    if not store.delete_request(pid, rid):
        raise HTTPException(404, "请求不存在或不属于该项目")
    return {"ok": True}


# ---------- 测试身份库（v017.2） ----------
class IdentityRequest(BaseModel):
    """创建身份。headers/cookies 明文仅出现在本请求体内（HTTPS/回环本地），
    服务端 seal 后落库，**任何响应都不回显明文**。"""
    label: str
    role: str = "user"
    tenant: str = ""
    headers: dict = {}
    cookies: dict = {}
    check_url: str = ""      # 有效性检查用的目标 URL（必须在本项目 scope 内）
    notes: str = ""


def _mask_summary(d: dict) -> dict:
    """身份凭据摘要：只保留键名 + 值长度，供前端确认「存了什么」而不泄露值。"""
    return {k: f"<set:{len(str(v))}>" for k, v in (d or {}).items()}


@app.post("/api/projects/{pid}/identities")
async def add_identity(pid: str, req: IdentityRequest):
    """登记测试身份（匿名身份 headers/cookies 留空即可）。

    凭据经 DPAPI（CurrentUser 作用域）加密后落库；解密唯一出口在
    app/secretbox.py。若 check_url 非空，必须是本项目授权范围内的 URL。
    """
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    if not secretbox.available():
        raise HTTPException(500, "当前环境不支持 DPAPI，凭据受保护存储不可用，已拒绝保存")
    label = (req.label or "").strip()
    if not label:
        raise HTTPException(400, "label 不能为空")
    if req.check_url:
        denied = scope.check_scope(req.check_url)
        if denied:
            raise HTTPException(400, f"check_url 不在授权范围内：{denied}")
    headers_enc = secretbox.seal_dict(req.headers) or ""
    cookies_enc = secretbox.seal_dict(req.cookies) or ""
    if (req.headers or req.cookies) and not (headers_enc or cookies_enc):
        raise HTTPException(500, "凭据加密失败，已拒绝保存（不会明文落盘）")
    rec = store.add_identity(pid, label, role=req.role, tenant=req.tenant,
                             headers_enc=headers_enc, cookies_enc=cookies_enc,
                             source="manual", check_url=req.check_url,
                             notes=req.notes[:500])
    return {**rec, "headers_summary": _mask_summary(req.headers),
            "cookies_summary": _mask_summary(req.cookies)}


@app.get("/api/projects/{pid}/identities")
async def list_identities(pid: str):
    """身份列表——只含标签/角色/状态/最近检查时间，**无任何凭据字段**。"""
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return {"items": store.list_identities(pid)}


@app.delete("/api/projects/{pid}/identities/{iid}")
async def delete_identity(pid: str, iid: str):
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    if not store.delete_identity(pid, iid):
        raise HTTPException(404, "身份不存在或不属于该项目")
    return {"ok": True}


@app.post("/api/projects/{pid}/identities/{iid}/check")
async def check_identity(pid: str, iid: str):
    """身份有效性检查：解密凭据 → 注入单发只读请求 → 按 HTTP 状态判活。

    红线：scope 校验（check_url 必须在白名单内）、限速、只读方法、
    响应**只取状态码与耗时**（不回传响应体——防止把受保护页面内容
    连同判断一起写进日志/前端）。凭据失效把身份标记为 expired。
    """
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    rec = store.get_identity(pid, iid)
    if not rec:
        raise HTTPException(404, "身份不存在或不属于该项目")
    if rec["status"] == "disabled":
        raise HTTPException(400, "身份已禁用")
    check_url = rec.get("check_url") or ""
    if not check_url:
        raise HTTPException(400, "该身份未配置 check_url，无法自动检查")
    denied = scope.check_scope(check_url)
    if denied:
        store.update_identity_status(pid, iid, "invalid")
        raise HTTPException(400, f"check_url 不在授权范围内，身份已标记 invalid：{denied}")
    headers = secretbox.unseal_dict(rec.get("headers_enc"))
    cookies = secretbox.unseal_dict(rec.get("cookies_enc"))
    if headers is None and cookies is None and (rec.get("headers_enc") or rec.get("cookies_enc")):
        # 密文存在但解不开：换用户/损坏——标记失效，绝不带残缺凭据继续
        store.update_identity_status(pid, iid, "invalid")
        raise HTTPException(409, "凭据解密失败（可能因换 Windows 用户或密文损坏），身份已标记 invalid")
    import time as _t
    await ratelimit.acquire(urlsplit(check_url).netloc or "default",
                            config.TOOL_MIN_INTERVAL, config.GLOBAL_MIN_INTERVAL)
    merged_headers = {k: v for k, v in (headers or {}).items()}
    t0 = _t.monotonic()
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                     timeout=15.0) as client:
            r = await client.get(check_url, headers=merged_headers,
                                 cookies=cookies or None)
        status_code = r.status_code
    except Exception as e:
        raise HTTPException(502, f"检查请求失败：{type(e).__name__}")
    latency = round(_t.monotonic() - t0, 2)
    # 401/403 = 凭据失效；407（代理要求认证）也算失效信号
    ok = status_code not in (401, 403, 407)
    store.update_identity_status(pid, iid, "active" if ok else "expired",
                                 last_checked_at=_t.time())
    return {"ok": ok, "status_code": status_code, "latency": latency,
            "status": "active" if ok else "expired"}


# ---------- 只读身份差分（v017.3） ----------
class DiffRunRequest(BaseModel):
    """对请求库中的一条请求执行身份/对象差分。

    baseline_identity_id：基准身份（应能正常访问自己的对象）；
    target_field/target_location/target_value：替换对象字段（如 userId=20002），
      value 由用户从响应/页面中取得，系统不做邻号猜测；
    with_anonymous：是否追加「无凭据」对照（未授权检测）；
    repeat：变体重复次数（默认 2——两次一致才算稳定候选）。
    """
    request_id: str
    baseline_identity_id: str
    target_field: str
    target_location: str = "query"
    target_value: str
    with_anonymous: bool = True
    repeat: int = 2


def _identity_creds(rec: dict) -> tuple[dict, dict]:
    """解密身份凭据；失败返回 ({}, {}) 并由调用方按 invalid 处理。"""
    headers = secretbox.unseal_dict(rec.get("headers_enc")) or {}
    cookies = secretbox.unseal_dict(rec.get("cookies_enc")) or {}
    return headers, cookies


def _build_exec_headers(lib_rec: dict, id_headers: dict, id_cookies: dict) -> tuple[dict, dict]:
    """合成执行用头：身份凭据接管敏感头，其余非敏感头沿用请求库记录。"""
    headers = {}
    for k, v in (lib_rec.get("headers") or {}).items():
        if isinstance(v, str) and v.startswith("<redacted:"):
            continue      # 占位头：由身份凭据接管；身份没提供就丢弃（不带假凭据）
        headers[k] = v
    headers.update(id_headers or {})
    cookies = dict(id_cookies or {})
    # 请求库 cookie 占位不进执行（真 Cookie 由身份提供）
    return headers, cookies


@app.post("/api/projects/{pid}/diff-run")
async def diff_run(pid: str, req: DiffRunRequest):
    """只读身份差分：基准 → 变体（对象替换）→ 匿名对照 → 重复验证。

    判定保守（app/difftest.classify）：只有「变体 200 且返回可证明的对象
    数据且重复一致」才给 suspect_idor 候选建议；结果需人工复核后才能
    confirmed（v012 状态模型，本接口绝不直接写 confirmed）。
    """
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    lib_rec = next((r for r in store.list_requests(pid, limit=1000)
                    if r["id"] == req.request_id), None)
    if not lib_rec:
        raise HTTPException(404, "请求不存在或不属于该项目")
    base_rec = store.get_identity(pid, req.baseline_identity_id)
    if not base_rec:
        raise HTTPException(404, "基准身份不存在或不属于该项目")
    if req.target_location not in ("query", "path", "body"):
        raise HTTPException(400, "target_location 仅支持 query/path/body")
    repeat = max(1, min(int(req.repeat or 2), 4))

    base_headers, base_cookies = _identity_creds(base_rec)
    if (base_rec.get("headers_enc") or base_rec.get("cookies_enc")) and \
            not base_headers and not base_cookies:
        store.update_identity_status(pid, req.baseline_identity_id, "invalid")
        raise HTTPException(409, "基准身份凭据解密失败，已标记 invalid")
    ex_h, ex_c = _build_exec_headers(lib_rec, base_headers, base_cookies)

    steps: list[dict] = []

    async def _run(tag: str, url: str, body: str) -> dict:
        ev = await difftest.execute_readonly(url, lib_rec["method"], ex_h, ex_c, body)
        steps.append({"tag": tag, "url": url, "status": ev.get("status_code"),
                      "error": ev.get("error")})
        return ev

    # 1) 基准：A 身份 + 原对象
    baseline = await _run("baseline", lib_rec["url"], lib_rec.get("body") or "")

    # 2) 变体：同一身份 + 目标对象（重复 repeat 次，取稳定性）
    variant_req = difftest.apply_replacement(lib_rec, req.target_field,
                                             req.target_location, req.target_value)
    variant_runs = []
    for i in range(repeat):
        variant_runs.append(await _run(f"variant#{i+1}",
                                       variant_req["url"], variant_req["body"]))
    # 稳定性：各次变体响应规范化后一致
    def _norm_resp(e):
        return difftest._strip_noise(e.get("body_json")) if e.get("body_json") is not None \
            else re.sub(r"\s+", " ", e.get("body_text") or "").strip()
    stable = len({json.dumps(_norm_resp(e), ensure_ascii=False, sort_keys=True,
                             default=str) for e in variant_runs}) == 1

    # 3) 匿名对照（可选）：无凭据 + 原对象
    anon = None
    if req.with_anonymous:
        anon = await difftest.execute_readonly(lib_rec["url"], lib_rec["method"],
                                               {k: v for k, v in
                                                (lib_rec.get("headers") or {}).items()
                                                if not str(v).startswith("<redacted:")},
                                               None, lib_rec.get("body") or "")
        steps.append({"tag": "anonymous", "url": lib_rec["url"],
                      "status": anon.get("status_code"), "error": anon.get("error")})

    verdict = difftest.classify(baseline, variant_runs[0], req.target_value)
    # 重复不一致 → 降级 unstable（不产生候选建议）
    if verdict["verdict"] == "suspect_idor" and not stable:
        verdict = {"verdict": "unstable",
                   "reason": f"变体重复 {repeat} 次结果不一致（可能是缓存/随机数据），不产生候选"}
    # 匿名也 200 且有数据 → 附未授权观察（独立信号，不合并结论）
    anon_note = None
    if anon and anon.get("status_code") == 200:
        anon_note = ("匿名请求同样返回 200——请进一步确认该接口是否本应需要登录"
                     "（未授权访问线索，与越权结论分开验证）")

    # 证据链落库（v017.4）：只存脱敏数据，可回溯
    masked = (req.target_value[:2] + "***" + req.target_value[-2:]) \
        if len(req.target_value) > 6 else req.target_value
    run_id = store.add_diff_run(pid, {
        "request_id": req.request_id,
        "baseline_identity": base_rec.get("label", ""),
        "target_field": req.target_field,
        "target_location": req.target_location,
        "target_value_masked": masked,
        "verdict": verdict.get("verdict", ""),
        "reason": verdict.get("reason", ""),
        "stable": stable,
        "steps": steps,
        "variant_url": variant_req["url"],
    })

    # 一键登记候选的预填材料（suspect 时前端直接调 POST /findings）
    finding_draft = None
    if verdict.get("verdict") == "suspect_idor":
        finding_draft = {
            "title": f"疑似越权：基准身份可访问他人对象（{req.target_field}={masked}）",
            "severity": "高危",
            "target": urlsplit(variant_req["url"]).netloc,
            "vuln_type": "水平越权/IDOR",
            "detail": (f"差分判定：{verdict.get('reason', '')}\n\n"
                       f"基准身份 {base_rec.get('label', '')} 请求替换对象"
                       f"（{req.target_field}={masked}，{req.target_location} 位置）后"
                       f"返回了他人对象数据；变体重复 {repeat} 次结果"
                       f"{'一致' if stable else '不一致'}。\n"
                       f"差分记录：{run_id}。请在请求库/Burp 中人工核对响应后补充完整复现链。"),
            "evidence": "\n".join(
                f"{s.get('tag')}: {s.get('status') or s.get('error') or ''} {s.get('url', '')}"
                for s in steps),
            "reproduction": (f"1. 以 {base_rec.get('label', '')} 身份登录；\n"
                             f"2. 访问 {variant_req['url']}；\n"
                             f"3. 响应中包含非本人对象数据（目标 {masked}）；\n"
                             f"4. 重复请求结果一致。"),
        }

    return {
        "run_id": run_id,
        "verdict": verdict,
        "stable": stable,
        "steps": steps,
        "anonymous_note": anon_note,
        "variant_url": variant_req["url"],
        "target": {"field": req.target_field, "location": req.target_location,
                   "value_masked": masked},
        "finding_draft": finding_draft,
        "note": ("suspect_idor 仅为候选建议：请在请求库/Burp 中人工核对响应内容，"
                 "确认对象归属后用「登记漏洞」写入候选（draft），复核确认才进报告。"),
    }


@app.get("/api/projects/{pid}/diff-runs")
async def list_diff_runs(pid: str, limit: int = 50):
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return {"items": store.list_diff_runs(pid, limit=limit)}


# ---------- 流程绕过检测（v017.5） ----------
class FlowRunRequest(BaseModel):
    """流程检查：request_ids 为按流程顺序排列的请求库 ID 序列，

    最后一条是目标步骤。只读流程链（GET/HEAD/OPTIONS）；含写步骤的流程
    需人工在 Burp 验证（模块层方法硬白名单会拒绝执行写请求并中断）。
    """
    request_ids: list[str]
    identity_id: str = ""        # 可空 = 纯匿名流程（检测未授权链路）


@app.post("/api/projects/{pid}/flow-run")
async def flow_run(pid: str, req: FlowRunRequest):
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    if not req.request_ids or len(req.request_ids) < 2:
        raise HTTPException(400, "流程至少需要 2 个步骤（前置 + 目标）")
    all_reqs = {r["id"]: r for r in store.list_requests(pid, limit=1000)}
    seq = []
    for rid in req.request_ids:
        rec = all_reqs.get(rid)
        if not rec:
            raise HTTPException(404, f"请求 {rid} 不存在或不属于该项目")
        seq.append(rec)
    identity_headers, identity_cookies = {}, {}
    identity_label = "anonymous"
    if req.identity_id:
        rec = store.get_identity(pid, req.identity_id)
        if not rec:
            raise HTTPException(404, "身份不存在或不属于该项目")
        identity_headers = secretbox.unseal_dict(rec.get("headers_enc")) or {}
        identity_cookies = secretbox.unseal_dict(rec.get("cookies_enc")) or {}
        identity_label = rec.get("label", "")
        if (rec.get("headers_enc") or rec.get("cookies_enc")) and \
                not identity_headers and not identity_cookies:
            store.update_identity_status(pid, req.identity_id, "invalid")
            raise HTTPException(409, "身份凭据解密失败，已标记 invalid")
    result = await flowtest.run_flow_check(seq, identity_headers, identity_cookies)
    run_id = store.add_flow_run(pid, {
        "identity_label": identity_label,
        "step_ids": req.request_ids,
        "verdict": result.get("verdict", ""),
        "reason": result.get("reason", ""),
        "steps": result.get("steps", []),
    })
    finding_draft = None
    if result.get("verdict", "").startswith("suspect_"):
        last_url = seq[-1]["url"]
        is_unauth = result["verdict"] == "suspect_unauthorized"
        finding_draft = {
            "title": ("疑似未授权访问：" if is_unauth else
                      "疑似流程绕过：跳过前置步骤后目标接口仍返回数据"),
            "severity": "高危" if not is_unauth else "高危",
            "target": urlsplit(last_url).netloc,
            "vuln_type": "未授权访问" if is_unauth else "业务流程绕过",
            "detail": (f"流程检查判定：{result.get('reason', '')}\n"
                       f"流程步骤数：{len(seq)}（末步：{last_url}）。\n"
                       f"记录：{run_id}。请人工核响应内容后补全复现链。"),
            "evidence": "\n".join(
                f"{s.get('tag')}: {s.get('status') or s.get('error') or ''} {s.get('url', '')}"
                for s in result.get("steps", [])),
            "reproduction": ("1. 不完成前置步骤（或无凭据）直接访问末步 URL；\n"
                             f"2. {last_url}\n3. 观察响应返回了本应受保护的数据。"),
        }
    return {"run_id": run_id, **result, "finding_draft": finding_draft}


@app.get("/api/projects/{pid}/flow-runs")
async def list_flow_runs(pid: str, limit: int = 50):
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    return {"items": store.list_flow_runs(pid, limit=limit)}


# ---------- 五项复核清单（v017.4） ----------
CHECK_KEYS = ("c1_repeat", "c2_permission_delta", "c3_minimal_chain",
              "c4_readonly_or_safe", "c5_impact_proven")


class ChecklistRequest(BaseModel):
    c1_repeat: bool = False
    c2_permission_delta: bool = False
    c3_minimal_chain: bool = False
    c4_readonly_or_safe: bool = False
    c5_impact_proven: bool = False
    note: str = ""


@app.get("/api/projects/{pid}/findings/{fid}/checklist")
async def get_checklist(pid: str, fid: str):
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    if not any(f["id"] == fid for f in store.list_findings(pid)):
        raise HTTPException(404, "漏洞发现不存在或不属于该项目")
    return store.get_checks(fid) or {k: 0 for k in CHECK_KEYS} | {"note": ""}


@app.put("/api/projects/{pid}/findings/{fid}/checklist")
async def set_checklist(pid: str, fid: str, req: ChecklistRequest):
    if not store.get_project(pid):
        raise HTTPException(404, "项目不存在")
    if not any(f["id"] == fid for f in store.list_findings(pid)):
        raise HTTPException(404, "漏洞发现不存在或不属于该项目")
    return store.set_checks(fid, req.model_dump(), note=req.note)


@app.get("/api/sessions/{sid}/stream")
async def stream_session(sid: str, request: Request, last_event_id: int = 0):
    """SSE：实时推送思考、命令、输出、确认请求与结论。

    v011 断线重放：客户端带上 `?last_event_id=<已收到的最大 seq>`
    （或标准 EventSource 的 Last-Event-ID 请求头），服务端先把该序号之后的
    历史事件按序回放（id: 行带 seq），再接入实时流——页面刷新/断网重连
    不再丢失中间过程。会话已结束（服务重启后内存无此会话）则只回放历史。
    """
    s = sessions.get(sid)
    if not s:
        # 会话不在内存（服务重启）：只要事件表里还有历史，仍可回放
        stored = store.get_session(sid)
        if not stored:
            raise HTTPException(404, "会话不存在")
        s = None
    else:
        stored = None

    # EventSource 重连自动带 Last-Event-ID 头；query 参数作为显式入口（取更大者）
    header_leid = request.headers.get("Last-Event-ID") or ""
    try:
        last_event_id = max(int(last_event_id or 0), int(header_leid))
    except ValueError:
        pass

    async def gen() -> AsyncIterator[str]:
        replay_upto = int(last_event_id or 0)
        # 1) 历史回放：仅当客户端带了游标（重连）才补发增量；
        #    全新连接（游标 0）保持旧行为——从当前实时事件开始，不倒腾历史。
        if replay_upto > 0:
            for ev in store.list_events(sid, since_seq=replay_upto):
                seq = ev.pop("_seq", 0)
                replay_upto = max(replay_upto, seq)
                yield f"id: {seq}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
                if ev.get("type") == "done":
                    return
        if s is None:
            # 纯历史会话（服务重启后内存无此会话）：回放完历史即结束
            yield f"data: {json.dumps({'type': 'done', 'state': 'stored'}, ensure_ascii=False)}\n\n"
            return
        # 2) 实时流：跳过回放期间已补发的 seq，避免重复
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(s.events.get(), timeout=30)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                seq = ev.get("_seq") or 0
                if seq and seq <= replay_upto:
                    continue
                payload = {k: v for k, v in ev.items() if k != "_seq"}
                if seq:
                    yield f"id: {seq}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                else:
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                if ev.get("type") == "done":
                    break
        except asyncio.CancelledError:
            return

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    })


@app.post("/api/sessions/{sid}/cancel")
async def cancel_session(sid: str):
    """取消正在执行的任务（v011 P1-5，软取消）。

    在步骤边界与确认等待处生效：正在执行的工具步骤会跑完（单步本有总时长
    上限），随后的循环立即收尾——半程成果照常沉淀（persist_interrupted）。
    对空闲/已结束的会话返回 409。
    """
    s = sessions.get(sid)
    if not s:
        raise HTTPException(404, "会话不存在")
    if s.state not in ("running", "awaiting_confirm"):
        raise HTTPException(409, f"当前状态为 {s.state}，无需取消")
    s.cancel_event.set()
    await s.emit({"type": "reasoning", "data": "（用户已请求取消，将在当前步骤完成后停止…）"})
    return {"ok": True, "session_id": sid, "state": "cancelling"}


@app.post("/api/sessions/{sid}/confirm")
async def confirm_step(sid: str, req: ConfirmRequest):
    """回应「当前这一步」的高危确认（双闸门合并版：一次性 token + 步骤归属 step_id）。

    只应是「正在等待确认」的那个步骤的回应，因此处处都要对上：
      · 会话确实处于 awaiting_confirm 且登记了 pending_step_id；
      · 一次性 token 与会话登记的一致（拒绝陈旧点击 / 重放 / 脚本伪造）；
      · 请求 step_id 与会话正在等待的步骤一致（归属校验）；
      · 队列里没有积压的未消费确认（正常一轮只有一个待确认步骤）。
    L3 放行还必须带 auth_ack（书面授权确认）；拒绝（approved=False）任何等级都不拦。
    任一不符直接 409/400，绝不"先塞进队列等以后用"——那正是绕过闸门的方式。
    """
    s = sessions.get(sid)
    if not s:
        raise HTTPException(404, "会话不存在")
    if s.state != "awaiting_confirm" or not s.pending_step_id:
        raise HTTPException(409, "当前没有等待确认的步骤")
    pend = s.pending_confirm
    if not pend:
        raise HTTPException(409, "确认已过期或已处理，请重新发起")
    if not req.token or req.token != pend["token"]:
        raise HTTPException(409, "确认令牌无效（可能来自上一轮确认），已拒绝")
    if not req.step_id or req.step_id != s.pending_step_id:
        raise HTTPException(409, f"确认与当前等待的步骤不匹配（当前：{s.pending_step_id}）")
    if not s.control.empty():
        raise HTTPException(409, "已有待处理的确认，请勿重复提交")
    # 只有「放行」才需要书面授权勾选。拒绝（approved=False）任何风险等级都不该被
    # 授权确认拦住——原实现把校验放在放行判定之前，导致 L3 只能同意不能拒绝：
    # 前端拒绝时 auth_ack=False，服务端直接 400，用户根本没有「不执行」这个选项。
    if req.approved and pend.get("double_confirm") and not req.auth_ack:
        raise HTTPException(400, "该步骤为 L3 高危，必须显式确认已获得书面授权后方可放行")
    await s.control.put({
        "approved": req.approved,
        "args": req.args,
        "token": req.token,
        # 归属校验：_confirm_round 会比对 step_id（与一次性 token 双保险）
        "step_id": s.pending_step_id,
    })
    # 一次性令牌：用掉即作废。不清掉的话，在「端点已入队」到「_await_confirm 被唤醒
    # 并清理」之间有个窗口，同一令牌再 POST 一次会再入队一条。
    s.pending_confirm = None
    return {"ok": True}


@app.get("/api/sessions/{sid}")
async def session_state(sid: str):
    chat = store.list_chat_messages(sid)  # 对话历史（新旧会话通用，旧会话为空列表）
    s = sessions.get(sid)
    if s:
        # pending_confirm：把「正在等确认的那一步」一并回传。
        # 确认框只由 SSE 的 need_confirm 事件渲染，页面刷新/断线重连后事件已经过去，
        # 用户会看到「执行中」却永远等不到可点的按钮，最后只能超时。
        # 前端据此重绘确认框，才能把「确认必须绑步骤」这条约束闭环。
        pending = None
        if s.state == "awaiting_confirm" and s.pending_step_id:
            for st in s.steps:
                if st.id == s.pending_step_id:
                    # v022 修复（测试组 021 整改报告 P1-2）：一并回传 token 与 second。
                    # 此前只回传 step/risk——页面刷新后前端重绘的确认框没有令牌，
                    # 提交必然 409「确认令牌无效」，用户只能干等 600s 超时。
                    # 本接口只在本机回环暴露且经会话归属校验，token 短时一次性，
                    # 经 state 往返的风险可控（远程模式另有全站 Bearer 闸门）。
                    pend = s.pending_confirm or {}
                    pending = {"step": agent._step_dict(st),
                               "risk": st.risk or registry.risk_of(st.tool_alias) or {},
                               "token": pend.get("token", ""),
                               "second": bool(pend.get("double_confirm"))}
                    break
        return {
            "id": s.id,
            "state": s.state,
            "target": s.target,
            "steps": [agent._step_dict(x) for x in s.steps],
            "parent_id": s.parent_id,
            "title": s.title,
            "records": s.records,
            "summary": s.summary,
            "chat": chat,
            "pending_confirm": pending,
        }
    # 回退到持久化层：服务重启后内存会话已清空，但 store 里仍有记录
    rec = store.get_session(sid)
    if not rec:
        raise HTTPException(404, "会话不存在")
    sess = rec["session"]
    try:
        records = json.loads(sess.get("context") or "[]")
    except Exception:
        records = []
    return {
        "id": sess["id"],
        "state": sess.get("state"),
        "target": sess.get("target"),
        "steps": rec["steps"],
        "parent_id": sess.get("parent_id") or "",
        "title": sess.get("title") or "",
        "records": records if isinstance(records, list) else [],
        "summary": sess.get("summary") or "",
        "chat": chat,
    }
