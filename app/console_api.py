# -*- coding: utf-8 -*-
"""配置控制台后端（v050 P1）：`/api/console/*`。

## 定位

现有 80 个接口里**没有任何配置写入能力** —— 授权白名单、工具分级、运行参数
只能手工改文件。本模块是控制台的配置侧 API，`main.py` 只加三行把它挂上。

## 三条设计红线（都有具体理由，不是风格问题）

### 1. 口令 fail-closed

这个界面能改**授权白名单**。若「未设置口令 = 不校验」，等于把授权红线挂在一个
默认敞开的网页上。所以：未配置口令时 **console 路由一律 403**，
并明确告诉人怎么配。宁可「配了才能用」，不可「没配就能用」。

### 2. 二次确认服务端强制，不是前端装饰

高危写入（白名单增删改）走**两段式**：
`preview` 算 diff 并签发一次性 `confirm_token`，`commit` **必须带这个 token**。
直接把 `commit` 打到 API 上没有 token 会被拒 —— 否则「二次确认」只是前端的
一个 `confirm()` 弹窗，绕过前端即可写。token 5 分钟过期：
「确认」的语义是「我刚看过这份 diff」，隔夜再提交就不算确认。

### 3. 乐观锁：防「控制台与手工编辑互相覆盖」

`commit` 需带 `expect_sha256`。与磁盘现值不符 → `409` 并回显差异。
本项目既有人手工改 `scope.json` 的习惯，不做这层就会出现
「控制台基于旧内容写入 → 手工刚加的那条被静默抹掉」。

## 与现有接口的关系

**不新造任何既有通道**。确认框、SSE 流等仍走 `/api/sessions/*`（P3 实时监控页会直接
复用，不重新实现）—— 那些接口里的确认双闸门（token + step_id + auth_ack）是安全核心，
重写一遍就是绕过它。
"""
from __future__ import annotations

import hmac
import json
import logging
import re as _re
import secrets
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import config, config_io, scope, scope_migrate

logger = logging.getLogger(__name__)

router = APIRouter()

COOKIE_NAME = "console_token"
# 进程级随机密钥：重启即让所有登录票据失效（本地工具，这个代价可接受且更安全）
_SECRET = secrets.token_bytes(32)
# 一次性确认票据：token -> {face, action, payload, exp}
_CONFIRMS: dict[str, dict] = {}


# ============================================================ 口令与票据
def _flat_yaml(path) -> dict:
    """读扁平 `key: value` 配置（本机 config.yaml）。

    复用 `app/fofa.py` 里已经写好并测过的解析器（它自己也是在没有 pyyaml 时的兜底）。
    **不另写一份** —— 同一个原理落两份实现，迟早漂移（v047/v048 各踩过一次）。
    """
    try:
        from .fofa import _parse_flat_yaml
        return _parse_flat_yaml(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:                                    # noqa: BLE001
        return {}


def console_password() -> str:
    """控制台口令：环境变量优先，其次本机 config.yaml 的 consolePassword。"""
    pw = (config.CONSOLE_PASSWORD or "").strip()
    if pw:
        return pw
    try:
        return str(_flat_yaml(config.APP_DIR / "config.yaml")
                   .get("consolePassword") or "").strip()
    except Exception:                                    # noqa: BLE001
        return ""


def _make_token() -> str:
    exp = int(time.time()) + config.CONSOLE_TOKEN_TTL
    sig = hmac.new(_SECRET, str(exp).encode(), "sha256").hexdigest()
    return f"{exp}.{sig}"


def _token_valid(tok: str) -> bool:
    try:
        exp_s, sig = tok.split(".", 1)
        exp = int(exp_s)
    except Exception:                                    # noqa: BLE001
        return False
    if exp < time.time():
        return False
    want = hmac.new(_SECRET, exp_s.encode(), "sha256").hexdigest()
    return hmac.compare_digest(sig, want)


def _authed(request: Request) -> bool:
    return _token_valid(request.cookies.get(COOKIE_NAME, ""))


def require_auth(request: Request) -> None:
    """依赖：所有 `/api/console/*`（除 login/logout/session）都挂它。

    两种情况分开报，因为要人做的事不同：
      · 没配口令 → 403 + 「怎么配」（fail-closed，不是 401）
      · 配了但没登录/票据过期 → 401 + 「去登录」
    """
    if not console_password():
        raise HTTPException(403, (
            "控制台口令未设置，已拒绝访问（fail-closed）。这个界面能修改授权白名单，"
            "因此不允许在未设口令时开放。"
            "设置方式：环境变量 AGENT_CONSOLE_PASSWORD，"
            "或在本机 config.yaml 写 consolePassword: <你的口令>。"))
    if not _authed(request):
        raise HTTPException(401, "未登录或登录已过期，请重新登录。")


class LoginRequest(BaseModel):
    password: str = ""


@router.post("/login")
async def login(req: LoginRequest, response: Response):
    want = console_password()
    if not want:
        # 与 require_auth 同口径：没配口令就不给登录入口，而不是「空口令也能进」
        raise HTTPException(403, (
            "控制台口令未设置，无法登录。请设置环境变量 AGENT_CONSOLE_PASSWORD "
            "或在本机 config.yaml 写 consolePassword。"))
    if not hmac.compare_digest((req.password or "").strip(), want):
        config_io.audit("auth", "login_failed", level="mid", actor="anonymous",
                        note="口令错误")
        raise HTTPException(401, "口令错误。")
    response.set_cookie(
        COOKIE_NAME, _make_token(), max_age=config.CONSOLE_TOKEN_TTL,
        httponly=True, samesite="strict", path="/")
    config_io.audit("auth", "login_ok", level="low")
    return {"ok": True, "expires_in": config.CONSOLE_TOKEN_TTL}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/session")
async def session(request: Request):
    """不需要鉴权：登录页要能问「我该不该显示登录框」。"""
    return {"authenticated": _authed(request),
            "password_configured": bool(console_password())}


# ============================================================ 总览
@router.get("/overview")
async def overview(request: Request):
    """体检卡片数据。**只读**。

    价值在于「一眼看出哪条防线没配上」—— 这些项单看都不报错，组合起来才危险。
    例：`ENFORCE_SCOPE=0` 而白名单非空（以为受约束、其实没有）；
    空白名单（所有工具被拒，但现象是「Agent 突然什么都做不了」）。
    """
    require_auth(request)
    from .registry import registry

    domains = scope.load_scope()
    entries = scope.load_scope_targets()
    raw = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    # ⚠️ 「结构化条目数」必须数 **raw["targets"] 的条数**，不能数 `load_scope_targets()` 的长度：
    # 后者是 domains（旧写法）+ targets（结构化）**合并后**的视图，同一个 host 会各出一条，
    # 于是 7 个 host 显示成「结构化 14 条」—— 实测看到过这个误导，故显式取 raw 计数。
    n_structured = len([t for t in (raw.get("targets") or []) if isinstance(t, dict)])

    # 白名单告警：每一条都对应一种「看起来配了、其实没防住」的情况
    warns: list[dict] = []
    if not domains:
        warns.append({"level": "high", "text":
                      "授权白名单为空 —— 所有命令行工具、HTTP 重放器与 py_exec 都会被拒绝执行。"})
    if not config.ENFORCE_SCOPE:
        warns.append({"level": "high", "text":
                      "ENFORCE_SCOPE=0：授权校验已关闭，工具会对任意目标执行（等同关停红线）。"})
    needs_review = [t.get("host") for t in (raw.get("targets") or [])
                    if isinstance(t, dict) and t.get("needs_review")]
    if needs_review:
        warns.append({"level": "mid", "text":
                      f"{len(needs_review)} 条授权条目缺少 cid 或授权主体，等待人工复核"
                      "（在「授权白名单」页逐条补齐）。"})
    if not console_password():
        warns.append({"level": "high", "text":
                      "控制台口令未设置 —— 本页接口会被拒绝（fail-closed）。"
                      "请设置 AGENT_CONSOLE_PASSWORD 或 config.yaml 的 consolePassword。"})

    tools = registry.stats()
    interactive = [t.alias for t in registry.interactive_tools()]
    # 工具分级分布 + 进模型清单数（用于「一眼看出哪一类工具最多/有没有异常」）
    levels: dict[str, int] = {}
    for t in registry.tools:
        lv = (registry.risk_of(t.alias) or {}).get("level", "?")
        levels[lv] = levels.get(lv, 0) + 1

    prov = []
    try:
        from . import providers
        for p in providers.list_providers():
            g = providers.get(p["id"]) or {}
            prov.append({"id": p["id"], "name": p.get("name", ""),
                         "local": bool(g.get("local")),
                         "has_key": bool(g.get("api_key")),
                         "enabled": bool(g.get("enabled")),
                         "model": g.get("model", ""),
                         "current": p["id"] == providers.current().get("id")})
    except Exception:                                    # noqa: BLE001
        logger.debug("读供应商失败", exc_info=True)

    mcp = {}
    try:
        # 复用 main 里的实现（延迟导入避免循环）—— 不另写一份，否则两边会漂移
        from .main import _mcp_health
        mcp = await _mcp_health()
    except Exception as e:                               # noqa: BLE001
        mcp = {"available": False, "note": f"状态读取失败：{e}"}

    fp = {}
    try:
        from .fofa import _load_fofa_conf
        c = _load_fofa_conf() or {}
        fp = {"configured": bool(c.get("email") and c.get("key")),
              "email_masked": config_io.mask_host(str(c.get("email") or ""), 2, 6)
              if c.get("email") else ""}
    except Exception:                                    # noqa: BLE001
        fp = {"configured": False, "email_masked": ""}

    return {
        "ok": True,
        "scope": {
            "count": len(domains),          # 主机数（合并视图，已去重）
            "structured": n_structured,     # raw["targets"] 条数（见上方注释）
            "enforce": bool(config.ENFORCE_SCOPE),
            "needs_review": len(needs_review),
            "file": config_io.file_state(config.SCOPE_FILE),
        },
        "tools": tools,
        "tool_levels": levels,
        "interactive_tools": interactive,
        "providers": prov,
        "mcp": mcp,
        "timeouts": config.timeout_profile(),
        "orchestration": {
            "execution_mode": config.EXECUTION_MODE,
            "max_steps": config.MAX_STEPS,
            "run_token_budget": config.RUN_TOKEN_BUDGET,
            "task_constraints_enabled": config.TASK_CONSTRAINTS_ENABLED,
            "py_exec_grade_enabled": config.PY_EXEC_GRADE_ENABLED,
        },
        "fofa": fp,
        "console": {"password_configured": bool(console_password()),
                    "confirm_ttl": config.CONSOLE_CONFIRM_TTL},
        "warnings": warns,
    }


# ============================================================ 授权白名单
def _scope_view() -> dict:
    raw = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    domains = scope.load_scope()
    targets = raw.get("targets")
    if not isinstance(targets, list):
        targets = None
    return {
        "file": config_io.file_state(config.SCOPE_FILE),
        "domains": domains,
        "targets": targets,
        "note": str(raw.get("_说明") or ""),
        # 一致性：domains 与 targets 是否对得上（手工编辑常见的不一致）
        "consistent": (targets is None) or (
            sorted(scope.load_scope()) ==
            sorted({str(t.get("host", "")).lower() for t in targets
                    if isinstance(t, dict) and t.get("host")})),
        "effective": [{"host": e["host"],
                       "ports": sorted(e["ports"]) if e["ports"] else None,
                       "schemes": sorted(e["schemes"]) if e["schemes"] else None}
                      for e in scope.load_scope_targets()],
    }


@router.get("/scope")
async def scope_get(request: Request):
    require_auth(request)
    return {"ok": True, "data": _scope_view()}


@router.post("/scope/plan")
async def scope_plan(request: Request):
    """迁移预演：把当前 `domains` + `_说明` 反解为结构化 `targets`，**不写盘**。"""
    require_auth(request)
    raw = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    new, report = scope_migrate.plan(raw)
    return {"ok": True, "preview": new, "report": report,
            "problems": scope_migrate.validate(new),
            "expect_sha256": config_io.sha256_short(config.SCOPE_FILE)}


class ScopeVerifyRequest(BaseModel):
    host: str = ""


@router.post("/scope/verify")
async def scope_verify(req: ScopeVerifyRequest, request: Request):
    """对单个 host 干跑 `check_scope()`，回显「会放行还是会拒」。

    这是本页最有价值的小功能：让人**在改之前**看到「这条授权到底会不会生效」。
    完全只读 —— 只做本地字符串匹配，**不发任何目标流量**。
    """
    require_auth(request)
    host = (req.host or "").strip()
    if not host:
        raise HTTPException(400, "host 不能为空")
    reason = scope.check_scope(host)
    return {"ok": True, "host": host, "allowed": reason is None,
            "reason": reason or "在授权白名单内，会放行。"}


class ScopeCommitRequest(BaseModel):
    confirm_token: str = ""
    expect_sha256: str = ""
    targets: list[dict] = []
    note_append: str = ""


def _issue_confirm(face: str, action: str, payload: Any, sha: str) -> str:
    tok = secrets.token_urlsafe(18)
    _CONFIRMS[tok] = {"face": face, "action": action, "payload": payload,
                      "sha": sha, "exp": time.time() + config.CONSOLE_CONFIRM_TTL}
    _prune_confirms()
    return tok


def _prune_confirms() -> None:
    now = time.time()
    for k in [k for k, v in _CONFIRMS.items() if v["exp"] < now]:
        _CONFIRMS.pop(k, None)


def _consume_confirm(token: str, face: str) -> dict:
    _prune_confirms()
    rec = _CONFIRMS.get(token or "")
    if not rec:
        raise HTTPException(400, (
            "确认票据无效或已过期（有效期 "
            f"{config.CONSOLE_CONFIRM_TTL // 60} 分钟）。"
            "请重新走一次「预览 → 确认提交」。"
            "提示：二次确认是服务端强制的 —— 没有票据直接提交会被拒绝。"))
    if rec["face"] != face:
        raise HTTPException(400, "确认票据与操作面不匹配。")
    _CONFIRMS.pop(token, None)                           # 一次性
    return rec


@router.post("/scope/preview")
async def scope_preview(req: ScopeCommitRequest, request: Request):
    """算出改动 diff + 影响 + 风险等级，签发一次性确认票据。"""
    require_auth(request)
    cur = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    before_hosts = set(scope.load_scope())
    after_hosts = {str(t.get("host", "")).strip().lower()
                   for t in req.targets if isinstance(t, dict) and t.get("host")}

    new = dict(cur)
    new["targets"] = req.targets
    new["domains"] = [h for h in (cur.get("domains") or [])
                      if isinstance(h, str) and h.strip().lower() in after_hosts]
    for h in sorted(after_hosts):
        if h not in new["domains"]:
            new["domains"].append(h)

    problems = scope_migrate.validate(new)
    if not after_hosts:
        problems.append("提交后白名单为空 —— 所有工具都会被拒绝执行。")
    if problems:
        # 校验不过就不签发票据：不给「先拿到票据再慢慢想办法」的余地
        raise HTTPException(400, "校验未通过：" + "；".join(problems))

    added = sorted(after_hosts - before_hosts)
    removed = sorted(before_hosts - after_hosts)
    level = "high" if (added or removed) else "low"

    sha = config_io.sha256_short(config.SCOPE_FILE)
    tok = _issue_confirm("scope", "write", new, sha)
    return {
        "ok": True,
        "level": level,
        "requires_confirm": True,
        "added": added,
        "removed": removed,
        "unchanged": len(before_hosts & after_hosts),
        "warnings": ([f"将新增 {len(added)} 条授权"] if added else [])
                    + ([f"将移除 {len(removed)} 条授权"] if removed else [])
                    + (["授权校验当前处于关闭状态（ENFORCE_SCOPE=0），写白名单不会产生实际约束"]
                       if not config.ENFORCE_SCOPE else []),
        "confirm_token": tok,
        "expect_sha256": sha,
        "confirm_ttl": config.CONSOLE_CONFIRM_TTL,
    }


@router.post("/scope/commit")
async def scope_commit(req: ScopeCommitRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "scope")

    # 乐观锁：盘上内容变了就停（防「控制台与手工编辑互相覆盖」）
    cur_sha = config_io.sha256_short(config.SCOPE_FILE)
    if req.expect_sha256 and cur_sha and cur_sha != req.expect_sha256:
        raise HTTPException(409, (
            "scope.json 在你预览之后被改动过（可能是手工编辑），已拒绝写入以免覆盖。"
            f"盘上当前哈希 {cur_sha} ≠ 你确认时的 {req.expect_sha256}。"
            "请刷新页面重新预览。"))

    before = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    new = rec["payload"]
    if req.note_append:
        new = dict(new)
        new["_说明"] = str(new.get("_说明") or "") + "\n\n" + req.note_append.strip()

    res = config_io.write_json_atomic(config.SCOPE_FILE, new)
    if not res["ok"]:
        raise HTTPException(500, f"写入失败（已回滚到写前状态）：{res['error']}")
    config_io.audit("scope", "write", before={"domains": before.get("domains")},
                    after={"domains": new.get("domains"),
                           "targets": len(new.get("targets") or [])},
                    level="high", note=req.note_append or "控制台提交授权白名单")
    return {"ok": True, "file": config_io.file_state(config.SCOPE_FILE),
            "reload": config_io.reload_for("scope"), "backup": res["backup"],
            "data": _scope_view()}


@router.get("/audit")
async def audit_get(request: Request, limit: int = 100, face: str = ""):
    require_auth(request)
    limit = max(1, min(int(limit or 100), 1000))
    return {"ok": True, "items": config_io.read_audit(limit=limit, face=face),
            "file": config_io.file_state(config_io.AUDIT_FILE)}


@router.get("/audit/export")
async def audit_export(request: Request, mask: int = 1):
    """导出审计 CSV。**默认脱敏** —— 举证材料常要发给别人（平台/导师/队友），
    默认脱敏能避免「为了举证把授权靶标清单整份发出去」。要全量请显式 `mask=0`。"""
    require_auth(request)
    rows = config_io.read_audit(limit=1000)
    hosts = _collect_hosts(rows)
    lines = ["time,face,action,level,actor,note,before,after"]
    for r in rows:
        b = json.dumps(r.get("before"), ensure_ascii=False)
        a = json.dumps(r.get("after"), ensure_ascii=False)
        if mask:
            b, a = _mask_json(b, hosts), _mask_json(a, hosts)
        cells = [str(r.get("time", "")), str(r.get("face", "")),
                 str(r.get("action", "")), str(r.get("level", "")),
                 str(r.get("actor", "")), str(r.get("note", "")), b, a]
        lines.append(",".join('"' + c.replace('"', '""') + '"' for c in cells))
    return PlainTextResponse("\n".join(lines) + "\n",
                             media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition":
                                      "attachment; filename=console_audit.csv"})


def _mask_json(s: str, hosts: list[str]) -> str:
    """把 JSON 文本里出现的授权主机做掩码。

    ⚠️ v050 实测踩到的坑：最初我用「长得像域名的串」这条正则去匹配并掩码，
    结果 `new.test` 这种**标签很短**的域名匹配不上（正则要求点号前 ≥5 字符），
    → **默认脱敏失效，完整域名照样导出**。而这条检查恰好写在测试里，
    一跑就抓到了 —— 所以这里改成**按已知主机精确替换**：
    主机列表直接从审计记录本身扫出来，不靠正则猜「什么像域名」。

    仍然保留一条宽松兜底正则，用于那些**没被记进 domains 列表**的散落域名
    （例如 note 里手写的），避免出现「主表脱敏了、备注里漏了」。
    """
    known = sorted({h for h in hosts if h}, key=len, reverse=True)
    for h in known:
        s = s.replace(h, config_io.mask_host(h))
    # 兜底：点号前 ≥3 字符的域名形态（覆盖 note 里手写的）
    def rep(m):
        return config_io.mask_host(m.group(1))
    return _re.sub(r"([A-Za-z0-9][A-Za-z0-9.-]{2,}\.[A-Za-z]{2,})", rep, s)


def _collect_hosts(records: list[dict]) -> list[str]:
    """从审计记录的 before/after 里扫出所有字符串值，挑出像主机的那些。

    为什么不做成「读当前 scope.json」：审计是**历史**——某条主机可能已经被移出白名单，
    但它仍留在旧记录里，仍需脱敏。所以只能从记录本身扫。
    """
    pat = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$")
    out: set[str] = set()

    def walk(v):
        if isinstance(v, str):
            if pat.match(v.strip()):
                out.add(v.strip())
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
    for r in records:
        walk(r.get("before"))
        walk(r.get("after"))
        walk(r.get("extra"))
    return sorted(out, key=len, reverse=True)
