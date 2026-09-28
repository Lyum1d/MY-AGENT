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

    ⚠️ 这里**只做转发**，实现在文件末尾的 `console_api_flat_yaml()`。
    曾经的写法是在本函数里直接 `from .fofa import _parse_flat_yaml` 再调，
    结果 P2 新增 secrets 接口时又写了一份同功能的函数 —— **同一个原理两份实现**，
    正是本项目反复踩过的那类问题（v047/v048/v050）。现在只留一份，本函数是别名。
    """
    return console_api_flat_yaml(path)


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


# ============================================================ 工具与分级（P2）
# 写入面是**两个文件**，键口径还不一样：
#   · `data/risk_grades.json`  —— 键是**工具名**（中文名），存 level + reason
#   · `data/tool_overrides.json` —— 键是 **alias**，存 disabled/timeout/caps/旗标/caveat
# 所以预览要同时报两个文件的哈希，提交要同时带两个（否则可能只把一半改动落盘）。
GRADES_FILE_NAME = "risk_grades.json"
OVERRIDES_FILE_NAME = "tool_overrides.json"

# 控制台允许改的覆写字段（白名单）。**不能让它写任意键** ——
# tool_overrides 里还有 network_control / stdin_input 这类字段，
# 手改它们会绕过速率声明与交互式处理，属于「闸门参数」，不该从工具页随手改。
OVERRIDE_EDITABLE = ("disabled", "reason", "timeout", "caveat", "caps",
                     "target_type", "allowed_flags", "value_flags",
                     "disallowed_flags", "ignore_exit_code", "interactive",
                     "interactive_reason")


def _grades_path():
    return config.DATA_DIR / GRADES_FILE_NAME


def _overrides_path():
    return config.DATA_DIR / OVERRIDES_FILE_NAME


@router.get("/tools")
async def tools_get(request: Request):
    """全部工具（含不可编排的），带分级、覆写、是否进模型清单、文件是否存在。"""
    require_auth(request)
    from .registry import registry

    in_model = {t.alias for t in registry.usable_scriptable()}
    ov_raw = config_io.read_json(_overrides_path(), default={}) or {}
    gr_raw = config_io.read_json(_grades_path(), default={}) or {}
    items = []
    for t in registry.tools:
        ov = ov_raw.get(t.alias) or {}
        g = gr_raw.get(t.name) or {}
        items.append({
            "alias": t.alias, "name": t.name, "category": t.category,
            "type": t.type, "scriptable": t.scriptable,
            "level": t.risk_level, "level_reason": t.risk_reason,
            "level_in_grades": bool(g),
            "has_override": bool(ov),
            "disabled": t.disabled, "disabled_reason": t.disabled_reason,
            "interactive": t.interactive, "interactive_reason": t.interactive_reason,
            "caps": list(t.caps),
            "timeout": t.tool_timeout or 0,
            "target_type": t.target_type,
            "allowed_flags": list(t.allowed_flags),
            "disallowed_flags": list(t.disallowed_flags),
            "value_flags": list(t.value_flags),
            "ignore_exit_code": t.ignore_exit_code,
            "caveat_chars": len(t.caveat or ""),
            "executable": bool(t.executable),
            "in_model_list": t.alias in in_model,
            # 只显示长度不显示内容：caveat 可能很长，整表回传会让页面噎住；
            # 需要看全文时由 /tools/detail 单独取。
        })
    return {"ok": True, "items": items,
            "files": {"grades": config_io.file_state(_grades_path()),
                      "overrides": config_io.file_state(_overrides_path())},
            "editable_fields": list(OVERRIDE_EDITABLE),
            "levels": [{"level": k, "name": v["name"], "policy": v["policy"]}
                       for k, v in config.RISK_LEVELS.items()],
            "note": ("分级写 risk_grades.json（按工具名）；"
                     "禁用/超时/caps/旗标写 tool_overrides.json（按 alias）。"
                     "两者是不同文件，控制台会一起做乐观锁与回滚。")}


class ToolEditRequest(BaseModel):
    alias: str = ""
    overrides: dict | None = None      # None = 不改这个文件
    grade: dict | None = None          # None = 不改这个文件
    confirm_token: str = ""
    expect_sha256: dict = {}


def _tool_edit_diff(alias: str, overrides: dict | None, grade: dict | None) -> dict:
    """算出「改前 → 改后」的差异，并做字段级校验。返回 {diff, problems, payload, to_write}。"""
    from .registry import registry

    problems: list[str] = []
    diff: list[dict] = []
    t = registry.get_by_alias(alias) if alias else None

    ov_raw = config_io.read_json(_overrides_path(), default={}) or {}
    gr_raw = config_io.read_json(_grades_path(), default={}) or {}
    new_ov = dict(ov_raw)
    new_gr = dict(gr_raw)
    to_write: list[tuple] = []

    if overrides is not None:
        if not t:
            problems.append(f"未知工具 alias：{alias}")
        bad = [k for k in overrides if k not in OVERRIDE_EDITABLE]
        if bad:
            problems.append(
                f"不允许从工具页修改这些字段：{bad}（它们属于闸门参数，"
                "改它们会绕过速率声明或交互式处理）")
        if not problems:
            cur = dict(ov_raw.get(alias) or {})
            for k, v in overrides.items():
                old = t and getattr(t, {
                    "timeout": "tool_timeout"}.get(k, k), None)
                if (cur.get(k) if k in cur else old) != v:
                    diff.append({"file": OVERRIDES_FILE_NAME, "key": f"{alias}.{k}",
                                 "before": cur.get(k, old), "after": v})
                cur[k] = v
            if not cur.get("reason") and (cur.get("disabled") or overrides.get("disabled")):
                problems.append("禁用工具必须填 reason（写清「为什么不可用」，否则后来人只能猜）")
            if not problems:
                new_ov[alias] = cur
                to_write.append((_overrides_path(), new_ov))

    if grade is not None:
        if not t:
            problems.append("未知工具，无法改分级")
        lvl = grade.get("level")
        if lvl not in config.RISK_LEVELS:
            problems.append(f"非法风险等级：{lvl!r}（允许 {list(config.RISK_LEVELS)}）")
        if not str(grade.get("reason") or "").strip():
            problems.append("改分级必须填 reason（分级依据要留痕）")
        if t and not t.scriptable:
            problems.append(
                f"「{t.name}」不可编排（图形界面/网页工具），分级只对可编排工具生效 —— "
                "改它不会有任何效果")
        if not problems:
            cur_g = dict(gr_raw.get(t.name) or {})
            for k in ("level", "reason"):
                if cur_g.get(k) != grade.get(k):
                    diff.append({"file": GRADES_FILE_NAME, "key": f"{t.name}.{k}",
                                 "before": cur_g.get(k), "after": grade.get(k)})
            cur_g.update({"level": lvl, "reason": grade.get("reason", "")})
            cur_g.setdefault("type", t.type)
            cur_g.setdefault("category", t.category)
            cur_g.setdefault("path", str(t.rel_path or ""))
            new_gr[t.name] = cur_g
            to_write.append((_grades_path(), new_gr))

    if not to_write and not problems:
        problems.append("没有任何改动")
    return {"diff": diff, "problems": problems, "to_write": to_write,
            "files": [p.name for p, _ in to_write], "tool": t.name if t else ""}


@router.post("/tools/detail")
async def tools_detail(req: ToolEditRequest, request: Request):
    """取单个工具的完整 caveat 等长字段（列表页不回传全文，避免页面噎住）。"""
    require_auth(request)
    from .registry import registry
    t = registry.get_by_alias(req.alias)
    if not t:
        raise HTTPException(404, "未知工具 alias")
    return {"ok": True, "alias": t.alias, "name": t.name,
            "caveat": t.caveat or "", "description": t.description or "",
            "risk_reason": t.risk_reason or "",
            "network_control": t.network_control or {}}


@router.post("/tools/preview")
async def tools_preview(req: ToolEditRequest, request: Request):
    require_auth(request)
    r = _tool_edit_diff(req.alias, req.overrides, req.grade)
    if r["problems"]:
        raise HTTPException(400, "校验未通过：" + "；".join(r["problems"]))
    hashes = {"grades": config_io.sha256_short(_grades_path()),
              "overrides": config_io.sha256_short(_overrides_path())}
    tok = _issue_confirm("tools", "write",
                         {"alias": req.alias, "overrides": req.overrides,
                          "grade": req.grade}, hashes["overrides"] + hashes["grades"])
    level = "high" if any(d["key"].endswith((".level", ".disabled")) for d in r["diff"]) \
        else "mid"
    return {"ok": True, "diff": r["diff"], "files": r["files"], "tool": r["tool"],
            "level": level, "requires_confirm": True, "confirm_token": tok,
            "expect_sha256": hashes, "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/tools/commit")
async def tools_commit(req: ToolEditRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "tools")
    # 乐观锁：两个文件都要核对（任一被手工改过就停）
    for name, path in (("overrides", _overrides_path()), ("grades", _grades_path())):
        want = (req.expect_sha256 or {}).get(name, "")
        cur = config_io.sha256_short(path)
        if want and cur and cur != want:
            raise HTTPException(409, (
                f"{path.name} 在你预览之后被改动过（可能手工编辑），已拒绝写入以免覆盖。"
                f"盘上当前 {cur} ≠ 你确认时的 {want}。请刷新页面重新预览。"))

    r = _tool_edit_diff(rec["payload"]["alias"], rec["payload"]["overrides"],
                        rec["payload"]["grade"])
    if r["problems"]:
        raise HTTPException(400, "校验未通过（预览后可能已有变化）：" + "；".join(r["problems"]))
    res = config_io.write_many_atomic(r["to_write"])
    if not res["ok"]:
        raise HTTPException(500, (
            f"写入失败（{res['failed']}）：{res['error']}。"
            f"已回滚：{res['rolled_back'] or '（无需回滚）'}"))
    config_io.audit("tools", "write",
                    before={"alias": rec["payload"]["alias"]},
                    after={"diff": r["diff"], "files": res["written"]},
                    level="high", note=f"工具 {r['tool']} 改动 {len(r['diff'])} 项")
    reload_info = config_io.reload_for("tools")
    return {"ok": True, "diff": r["diff"], "written": res["written"],
            "reload": reload_info,
            "files": {"grades": config_io.file_state(_grades_path()),
                      "overrides": config_io.file_state(_overrides_path())}}


# ============================================================ 运行参数（P2）
@router.get("/params")
async def params_get(request: Request):
    """分组列出可调参数：当前值 / 默认值 / 来源 / 取值域 / 说明。

    刻意返回 `excluded`：被**有意排除**的参数连理由一起给出。
    否则「参数表里怎么没有 HOST」会被当成漏了，下一个人会想补上它。
    """
    require_auth(request)
    from . import param_spec as ps
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    groups = []
    for g in ps.groups():
        items = []
        for s in g["items"]:
            k = s["key"]
            items.append({**s,
                          "value": getattr(config, k, None),
                          "default": ps.default_value(k),
                          "env": ps.env_name(k),
                          "source": ps.source_of(k, ov)})
        groups.append({"group": g["group"], "items": items})
    return {"ok": True, "groups": groups,
            "excluded": ps.EXCLUDED,
            "overrides": (ov.get("params") or {}),
            "warnings": config.param_warnings(),
            "file": config_io.file_state(config_io.OVERRIDES_FILE),
            "hot": True,
            "note": ("改动**立即生效，不用重启**（全项目 0 处 `from .config import X`、"
                     "220 处 `config.X` 属性访问）。写入 data/runtime_overrides.json，"
                     "删掉某个键即回到环境变量/默认值。")}


class ParamsRequest(BaseModel):
    values: dict = {}
    confirm_token: str = ""
    expect_sha256: str = ""
    reset: list[str] = []


@router.post("/params/preview")
async def params_preview(req: ParamsRequest, request: Request):
    require_auth(request)
    from . import param_spec as ps
    values = {k: v for k, v in (req.values or {}).items()}
    problems = ps.validate(values) if values else []
    if not values and not req.reset:
        problems = ["没有任何改动"]
    if problems:
        raise HTTPException(400, "校验未通过：" + "；".join(problems))
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    cur = ov.get("params") or {}
    diff = []
    for k, v in values.items():
        if getattr(config, k, None) != v:
            diff.append({"key": k, "before": getattr(config, k, None), "after": v,
                         "default": ps.default_value(k)})
    for k in (req.reset or []):
        if k in cur:
            diff.append({"key": k, "before": getattr(config, k, None),
                         "after": ps.default_value(k), "default": ps.default_value(k)})
    if not diff:
        raise HTTPException(400, "没有任何实际变化")
    sha = config_io.sha256_short(config_io.OVERRIDES_FILE)
    tok = _issue_confirm("params", "write",
                         {"values": values, "reset": req.reset or []}, sha)
    # 关闸门类改动按高危（它们直接改变防护强度）
    danger = any(ps.spec_of(d["key"]) and ps.spec_of(d["key"]).get("danger")
                 for d in diff)
    return {"ok": True, "diff": diff, "level": "high" if danger else "mid",
            "requires_confirm": True, "confirm_token": tok,
            "expect_sha256": sha, "confirm_ttl": config.CONSOLE_CONFIRM_TTL,
            "warnings": config.param_warnings()}


@router.post("/params/commit")
async def params_commit(req: ParamsRequest, request: Request):
    require_auth(request)
    from . import param_spec as ps
    rec = _consume_confirm(req.confirm_token, "params")
    cur_sha = config_io.sha256_short(config_io.OVERRIDES_FILE)
    if req.expect_sha256 and cur_sha and cur_sha != req.expect_sha256:
        raise HTTPException(409, (
            "runtime_overrides.json 在你预览之后被改动过，已拒绝写入以免覆盖。"
            "请刷新页面重新预览。"))
    values = dict(rec["payload"]["values"])
    # reset 项从覆盖文件里删掉（回到 env/默认），不是写成默认值
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    merged = dict(ov.get("params") or {})
    for k in rec["payload"]["reset"]:
        merged.pop(k, None)
    merged.update(values)
    res = config_io.save_overrides(merged)
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    applied = config_io.apply_overrides(config)
    config_io.audit("params", "write", before={"params": ov.get("params")},
                    after={"params": merged, "applied": applied},
                    level="high", note=f"改动 {len(values)} 项 / 复位 {len(rec['payload']['reset'])} 项")
    return {"ok": True, "applied": applied,
            "values": {s["key"]: getattr(config, s["key"], None)
                       for s in ps.SPECS},
            "warnings": config.param_warnings(),
            "file": config_io.file_state(config_io.OVERRIDES_FILE)}


@router.post("/params/reset")
async def params_reset(request: Request):
    """清空全部运行时覆盖（回到环境变量/默认值）。高危，需确认票据。

    单独开一个入口是因为它**不是「把值改成默认」而是「删掉覆盖」** ——
    对「被环境变量设过」的参数，这两者结果不同：删掉覆盖会回到环境变量的值，
    写成默认值则会**覆盖掉环境变量**。所以必须分开做，不能靠前端「填默认值」模拟。
    """
    require_auth(request)
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    if not (ov.get("params") or {}):
        return {"ok": True, "applied": [], "note": "本来就没有运行时覆盖。"}
    res = config_io.write_json_atomic(config_io.OVERRIDES_FILE,
                                     {"_说明": "（已清空）", "params": {}})
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    # v052（复审报告 P2-A）：**必须**补这一步。原来只写了文件、没应用 ——
    # 于是把 ENFORCE_SCOPE 之类的闸门参数覆盖成关闭之后，再 reset，
    # 本进程的 config.ENFORCE_SCOPE 仍是 False，而总览页读的正是它 →
    # **界面显示「红线已关」而文件已经清空**，是最典型的「改了没生效 + 误导」。
    # `apply_overrides` 现在会先还原 `_ORIGINALS` 里那些已撤销的覆盖，所以复位是**即时**的。
    applied = config_io.apply_overrides(config)
    config_io.audit("params", "reset_all", before={"params": ov.get("params")},
                    after={"params": {}, "restored": applied},
                    level="high", note="清空全部运行时覆盖")
    return {"ok": True, "backup": res["backup"], "restored": applied,
            "values": {k: getattr(config, k, None)
                       for k in (ov.get("params") or {})},
            "warnings": config.param_warnings(),
            "note": ("已清空并**即时还原**：" + ("、".join(applied) if applied else "无覆盖项")
                     + "。回到环境变量/默认值，**不需要重启**。")}


# ============================================================ 合规红线与模板（P2）
def _rules_path():
    return config.DATA_DIR / "rules" / "compliance-redlines.md"


@router.get("/rules")
async def rules_get(request: Request):
    require_auth(request)
    text = config_io.read_text(_rules_path())
    sections = []
    cur = {"title": "（开头，不属于任何章节）", "start": 0}
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("## "):
            sections.append({**cur, "end": i})
            cur = {"title": ln[3:].strip(), "start": i}
    sections.append({**cur, "end": len(lines)})
    for s in sections:
        s["chars"] = len("\n".join(lines[s["start"]:s["end"]]))
    return {"ok": True, "text": text, "sections": sections,
            "file": config_io.file_state(_rules_path()),
            "note": "红线注入系统提示，**下一轮生效**（系统提示每轮重建）。"}


class RulesRequest(BaseModel):
    text: str = ""
    confirm_token: str = ""
    expect_sha256: str = ""


@router.post("/rules/preview")
async def rules_preview(req: RulesRequest, request: Request):
    require_auth(request)
    old = config_io.read_text(_rules_path())
    new = req.text or ""
    if new == old:
        raise HTTPException(400, "内容没有变化")
    if not new.strip():
        raise HTTPException(400, "不允许把合规红线清空 —— 它会注入系统提示，清空等于移除纪律约束")
    sha = config_io.sha256_short(_rules_path())
    tok = _issue_confirm("rules", "write", {"text": new}, sha)
    import difflib
    d = list(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                  lineterm="", n=0))
    return {"ok": True, "level": "mid", "requires_confirm": True,
            "confirm_token": tok, "expect_sha256": sha,
            "stats": {"before_chars": len(old), "after_chars": len(new),
                      "before_lines": len(old.splitlines()),
                      "after_lines": len(new.splitlines())},
            "hunks": len([x for x in d if x.startswith("@@")]),
            "preview": "\n".join(d[:120]),
            "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/rules/commit")
async def rules_commit(req: RulesRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "rules")
    cur = config_io.sha256_short(_rules_path())
    if req.expect_sha256 and cur and cur != req.expect_sha256:
        raise HTTPException(409, "红线文件在你预览之后被改动过，已拒绝写入。请重新预览。")
    old = config_io.read_text(_rules_path())
    res = config_io.write_text_atomic(_rules_path(), rec["payload"]["text"])
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    config_io.audit("rules", "write",
                    before={"chars": len(old)}, after={"chars": len(rec["payload"]["text"])},
                    level="mid", note="编辑合规红线")
    return {"ok": True, "backup": res["backup"],
            "reload": config_io.reload_for("rules"),
            "file": config_io.file_state(_rules_path())}


def _templates_path():
    return config.DATA_DIR / "invocation_templates.json"


@router.get("/templates")
async def templates_get(request: Request):
    require_auth(request)
    raw = config_io.read_json(_templates_path(), default={}) or {}
    items = [{"alias": k, **(v if isinstance(v, dict) else {})}
             for k, v in raw.items() if not k.startswith("_")]
    # 加载期发现的问题（例如手工改写导致缺 {exe}）—— 让界面直接显示，
    # 否则「模板被静默忽略」只留在日志里，等于没发现。
    try:
        from .executor import template_problems
        problems = template_problems()
    except Exception:                                        # noqa: BLE001
        problems = []
    return {"ok": True, "items": items,
            "target_form": raw.get("_target_form", ""),
            "note": raw.get("_说明", ""),
            "problems": problems,
            "file": config_io.file_state(_templates_path()),
            "targets": ["url", "host", "domain", "raw", "asis"]}


class TemplatesRequest(BaseModel):
    items: list[dict] = []
    confirm_token: str = ""
    expect_sha256: str = ""


@router.post("/templates/preview")
async def templates_preview(req: TemplatesRequest, request: Request):
    require_auth(request)
    raw = dict(config_io.read_json(_templates_path(), default={}) or {})
    old_items = {k: v for k, v in raw.items() if not k.startswith("_")}
    problems: list[str] = []
    new_items: dict = {}
    for it in req.items:
        a = str(it.get("alias") or "").strip()
        if not a:
            problems.append("存在没有 alias 的条目")
            continue
        cmd = str(it.get("cmd") or "").strip()
        if "{exe}" not in cmd:
            problems.append(f"{a}：cmd 必须含 {{exe}}（否则根本不知道执行什么）")
        tgt = str(it.get("target") or "raw").strip()
        if tgt not in ("url", "host", "domain", "raw", "asis"):
            problems.append(f"{a}：target={tgt!r} 不是合法取值")
        new_items[a] = {"cmd": cmd, "target": tgt}
    if problems:
        raise HTTPException(400, "校验未通过：" + "；".join(problems))
    added = sorted(set(new_items) - set(old_items))
    removed = sorted(set(old_items) - set(new_items))
    changed = sorted(k for k in set(new_items) & set(old_items)
                     if new_items[k] != old_items[k])
    if not (added or removed or changed):
        raise HTTPException(400, "没有任何改动")
    new_raw = {k: v for k, v in raw.items() if k.startswith("_")}
    new_raw.update(new_items)
    sha = config_io.sha256_short(_templates_path())
    tok = _issue_confirm("invocation_templates", "write", {"raw": new_raw}, sha)
    return {"ok": True, "level": "mid", "requires_confirm": True,
            "confirm_token": tok, "expect_sha256": sha,
            "added": added, "removed": removed, "changed": changed,
            "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/templates/commit")
async def templates_commit(req: TemplatesRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "invocation_templates")
    cur = config_io.sha256_short(_templates_path())
    if req.expect_sha256 and cur and cur != req.expect_sha256:
        raise HTTPException(409, "调用模板文件在你预览之后被改动过，已拒绝写入。")
    res = config_io.write_json_atomic(_templates_path(), rec["payload"]["raw"])
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    config_io.audit("invocation_templates", "write",
                    before={"count": len(req.items)}, after={"count": len(req.items)},
                    level="mid", note="编辑调用模板")
    return {"ok": True, "backup": res["backup"],
            "reload": config_io.reload_for("invocation_templates"),
            "file": config_io.file_state(_templates_path())}


def _config_yaml_path():
    return config.APP_DIR / "config.yaml"

# 控制台允许改的密钥键（白名单）。**其余键一律原样保留** ——
# config.yaml 是被 app/fofa.py 用自写的扁平解析器读的，乱动键名/结构会让它读不到，
# 而表现是「填了却没生效」。所以只允许改这几个已知键的值，格式与其它行都不动。
SECRET_KEYS = ("fofaEmail", "fofaKey", "ceyeApi", "ceyeDomain", "consolePassword")


@router.get("/secrets")
async def secrets_get(request: Request):
    require_auth(request)
    data = console_api_flat_yaml(_config_yaml_path())
    out = []
    for k in SECRET_KEYS:
        v = str(data.get(k) or "")
        out.append({"key": k, "has_value": bool(v),
                    "masked": (config_io.mask_host(v, 2, 4) if v else ""),
                    "is_secret": k in ("fofaKey", "ceyeApi", "consolePassword")})
    return {"ok": True, "items": out,
            "file": config_io.file_state(_config_yaml_path()),
            "note": ("读取时只回显是否已填与打码值，**不下发明文**。"
                     "写入只替换这些键的值，其它行与注释原样保留 —— "
                     "config.yaml 由 app/fofa.py 用自写的扁平解析器读，"
                     "改了键名或结构会导致「填了却没生效」。")}


class SecretsRequest(BaseModel):
    values: dict = {}
    confirm_token: str = ""
    expect_sha256: str = ""


@router.post("/secrets/commit")
async def secrets_commit(req: SecretsRequest, request: Request):
    """写 config.yaml。低危（不改结构），但**不需要票据**是刻意的：
    它不改变防护强度，且改错了只影响 FOFA 能不能用，一眼能看出来。"""
    require_auth(request)
    bad = [k for k in (req.values or {}) if k not in SECRET_KEYS]
    if bad:
        raise HTTPException(400, f"不允许写这些键：{bad}（只允许 {list(SECRET_KEYS)}）")
    path = _config_yaml_path()
    old_text = config_io.read_text(path)
    lines = old_text.splitlines()
    done: set[str] = set()
    out_lines = []
    for ln in lines:
        s = ln.strip()
        if ":" in s and not s.startswith("#"):
            k = s.split(":", 1)[0].strip()
            if k in (req.values or {}):
                out_lines.append(f"{k}: {_yaml_scalar(req.values[k])}")
                done.add(k)
                continue
        out_lines.append(ln)
    for k, v in (req.values or {}).items():
        if k not in done:
            out_lines.append(f"{k}: {_yaml_scalar(v)}")
    res = config_io.write_text_atomic(path, "\n".join(out_lines).rstrip("\n") + "\n")
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    config_io.audit("secrets", "write",
                    before={"keys": sorted(req.values.keys())},
                    after={"kept": sorted(done)},
                    level="mid",
                    note="更新 config.yaml 密钥（值不写入审计）")
    return {"ok": True, "backup": res["backup"],
            "reload": config_io.reload_for("secrets"),
            "file": config_io.file_state(path)}


def _yaml_scalar(v) -> str:
    """写回扁平 yaml 的值。字符串一律加引号并转义，避免含 `:` 或 `#` 时把行拆坏。"""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def console_api_flat_yaml(path) -> dict:
    """读扁平 `key: value`（复用 fofa.py 那份解析器，不另写一份）。"""
    try:
        from .fofa import _parse_flat_yaml
        if not path.exists():
            return {}
        return _parse_flat_yaml(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:                                        # noqa: BLE001
        return {}
