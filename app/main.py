# -*- coding: utf-8 -*-
"""FastAPI 后端：对话驱动 + SSE 实时输出 + 执行计划可视化。"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import AsyncIterator
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, providers, report, scope, store, usage
from . import graph
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
    """高危步骤的放行/拒绝。

    step_id 必填：确认通道是「一次一步」的交互式队列，若不绑定步骤身份，
    任何时刻投递的确认（陈旧点击、重放、脚本伪造）都会躺在队列里被**下一个**
    高危步骤消费掉，等于绕过 L2/L3 授权闸门。
    """
    approved: bool
    step_id: str = ""


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
    ok = store.delete_fact(fid)
    graph.on_fact_deleted(pid, fid)
    return {"ok": ok}


@app.post("/api/projects/{pid}/findings")
async def add_finding(pid: str, req: FindingRequest):
    rec = store.add_finding(pid, req.title, req.severity, req.target,
                            req.detail, req.evidence, session_id=req.session_id)
    graph.on_finding_added(pid, rec)
    return rec


@app.delete("/api/projects/{pid}/findings/{fid}")
async def remove_finding(pid: str, fid: str):
    ok = store.delete_finding(fid)
    graph.on_finding_deleted(pid, fid)
    return {"ok": ok}


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
    """回应「当前这一步」的高危确认。

    只应是「正在等待确认」的那个步骤的回应，因此三处都要对上：
      · 会话确实处于 awaiting_confirm；
      · 请求带 step_id，且与会话正在等待的步骤一致（拒绝陈旧/重放/伪造）；
      · 队列里没有积压的未消费确认（正常一轮只有一个待确认步骤）。
    任一不符直接 409，绝不"先塞进队列等以后用"——那正是绕过闸门的方式。
    """
    s = sessions.get(sid)
    if not s:
        raise HTTPException(404, "会话不存在")
    if s.state != "awaiting_confirm" or not s.pending_step_id:
        raise HTTPException(409, "当前没有等待确认的步骤")
    if not req.step_id or req.step_id != s.pending_step_id:
        raise HTTPException(409, f"确认与当前等待的步骤不匹配（当前：{s.pending_step_id}）")
    if not s.control.empty():
        raise HTTPException(409, "已有待处理的确认，请勿重复提交")
    await s.control.put({"approved": req.approved, "step_id": req.step_id})
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
                    pending = {"step": agent._step_dict(st),
                               "risk": st.risk or registry.risk_of(st.tool_alias) or {}}
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
