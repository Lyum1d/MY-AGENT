# -*- coding: utf-8 -*-
"""内置工具层：不依赖工具箱子进程的 Agent 原生能力。

1. run_replay   —— HTTP 重放器：对授权目标发起受控 HTTP 请求并回传完整响应。
                  默认只读（GET/HEAD/OPTIONS），写入方法硬禁用；域名白名单
                  （data/scope.json）强制生效；全局限速。
2. run_nuclei   —— 官方 nuclei CLI 的托管运行器（若已安装到 data/bin/nuclei.exe）。

设计原则：这是 Agent 目前唯一能「对单个 URL 精确发请求」的工具，
是把挖洞能力从信息收集推进到漏洞验证的关键。
"""
from __future__ import annotations

import asyncio
import json
import re
import shlex
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import httpx

from . import config

_UA = "SRC-Agent-Replay/1.0 (authorized bug-bounty test)"
_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
_LAST_REQ = 0.0
_RATE_LOCK = asyncio.Lock()


# ---------- 域名白名单 ----------
def _load_scope() -> list[str]:
    """读取授权域名白名单。文件不存在时以 jiaoyu.cn 为默认并自动创建。"""
    p = config.SCOPE_FILE
    if not p.exists():
        try:
            p.write_text(json.dumps({
                "_说明": "HTTP 重放器只允许请求这些域名及其子域。新增授权目标时编辑此文件。",
                "domains": ["jiaoyu.cn"],
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        return ["jiaoyu.cn"]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return [d for d in data.get("domains", []) if isinstance(d, str) and d.strip()]
    except Exception:
        return []


def _host_allowed(host: str, scope: list[str]) -> bool:
    host = host.lower()
    for d in scope:
        d = d.lower().strip()
        if not d:
            continue
        if host == d or host.endswith("." + d):
            return True
    return False


# ---------- 限速 ----------
async def _rate_limit() -> None:
    global _LAST_REQ
    async with _RATE_LOCK:
        wait = config.REPLAY_MIN_INTERVAL - (time.time() - _LAST_REQ)
        if wait > 0:
            await asyncio.sleep(wait)
        _LAST_REQ = time.time()


# ---------- 参数解析 ----------
def _parse_args(args: str) -> tuple[str, list[tuple[str, str]], dict[str, str], int, str | None]:
    """解析 curl 风格参数。返回 (method, extra_query, headers, timeout, error)。"""
    method, headers, query = "GET", [], []
    timeout = 12
    try:
        tokens = shlex.split(args or "")
    except ValueError:
        return method, query, {}, timeout, "args 引号不匹配，无法解析"
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-X", "--method") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
        elif t == "-X" or t == "--method":
            return method, query, {}, timeout, "-X 缺少方法名"
        elif re.match(r"^-X[ A-Z]", t) and len(t) > 2 and not t.startswith("-X="):
            method = t[2:].upper()
            i += 1
        elif t in ("-H", "--header") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if ":" in raw:
                k, v = raw.split(":", 1)
                headers.append((k.strip(), v.strip()))
            i += 2
        elif t in ("-d", "--data", "--param") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if "=" in raw:
                k, v = raw.split("=", 1)
                query.append((k.strip(), v.strip()))
            i += 2
        elif t == "--timeout" and i + 1 < len(tokens):
            try:
                timeout = min(max(int(re.sub(r"[^0-9]", "", tokens[i + 1]) or 12), 2), 20)
            except Exception:
                pass
            i += 2
        elif t.startswith("-"):
            # 未知旗标：跳过但不报错（模型偶尔臆造）
            i += 2 if (i + 1 < len(tokens) and not tokens[i + 1].startswith("-")) else 1
        else:
            i += 1
    return method, query, dict(headers), timeout, None


# ---------- 主入口 ----------
async def run_replay(url: str, args: str = ""):
    """HTTP 重放器事件流。事件格式与 executor.run 一致。"""
    url = (url or "").strip().strip("'\"")
    yield {"type": "tool", "data": "HTTP 重放器"}

    # 1. URL 合法性
    if not re.match(r"^https?://", url):
        yield {"type": "error", "data": "target 必须是完整 URL（带 http:// 或 https://）"}
        yield {"type": "exit", "code": 1}
        return

    parsed = urlparse(url)
    host = parsed.hostname or ""
    scope = _load_scope()
    if not _host_allowed(host, scope):
        yield {"type": "error",
               "data": f"域名 {host} 不在授权白名单内（data/scope.json）。"
                       f"当前白名单：{', '.join(scope) or '(空)'}。"
                       f"仅允许测试已获书面授权的目标。"}
        yield {"type": "exit", "code": 1}
        return

    method, extra_query, headers, timeout, err = _parse_args(args)
    if err:
        yield {"type": "error", "data": err}
        yield {"type": "exit", "code": 1}
        return
    if method not in _ALLOWED_METHODS:
        yield {"type": "error",
               "data": f"方法 {method} 已禁用：重放器只允许只读方法 {'/'.join(sorted(_ALLOWED_METHODS))}。"
                       f"写入类请求必须人工确认后在控制台外执行。"}
        yield {"type": "exit", "code": 1}
        return

    # 2. 追加查询参数
    if extra_query:
        q = parse_qsl(parsed.query, keep_blank_values=True) + extra_query
        url = urlunparse(parsed._replace(query=urlencode(q)))

    req_headers = {"User-Agent": _UA, **headers}
    shown = f"{method} {url}"
    if headers:
        shown += " | " + " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
    yield {"type": "command", "data": shown}

    # 3. 发请求（限速 + 信任环境关闭，防系统代理劫持）
    await _rate_limit()
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                     timeout=float(timeout)) as client:
            r = await client.request(method, url, headers=req_headers)
    except Exception as e:
        yield {"type": "error", "data": f"请求失败：{e}"}
        yield {"type": "exit", "code": 1}
        return

    # 4. 结构化回传
    lines = [
        f"HTTP {r.status_code} {r.reason_phrase}",
        f"Content-Type: {r.headers.get('content-type', '-')}  "
        f"Length: {r.headers.get('content-length', len(r.content))}  "
        f"Server: {r.headers.get('server', '-')}",
    ]
    interesting = ("location", "www-authenticate", "allow", "access-control-allow-origin",
                   "x-powered-by", "content-security-policy")
    for k in interesting:
        if r.headers.get(k):
            lines.append(f"{k}: {r.headers[k]}")
    set_cookies = [v.split(";")[0] for k, v in r.headers.items() if k.lower() == "set-cookie"]
    if set_cookies:
        lines.append("set-cookie: " + " | ".join(set_cookies[:6]))

    body = r.text
    is_json = "json" in (r.headers.get("content-type") or "").lower()
    if is_json:
        try:
            body = json.dumps(r.json(), ensure_ascii=False, indent=1)
        except Exception:
            pass
    if len(body) > config.REPLAY_MAX_BODY:
        body = body[: config.REPLAY_MAX_BODY] + f"\n…（响应体共 {len(r.text)} 字符，已截断）"
    lines.append("--- response body ---")
    lines.append(body if body.strip() else "（空响应体）")

    for ln in "\n".join(lines).splitlines():
        yield {"type": "output", "data": ln}
    # HTTP 4xx/5xx 是测试结果而非执行失败，退出码仍为 0
    yield {"type": "exit", "code": 0}


# ---------- nuclei 托管运行 ----------
async def run_nuclei(tool, target: str, args: str = ""):
    """运行 data/bin/nuclei.exe（若存在）。与 executor 相同的事件流格式。"""
    exe = tool.executable
    yield {"type": "tool", "data": "Nuclei CLI"}
    if not exe:
        yield {"type": "error", "data": "nuclei 未安装：请将 nuclei.exe 放到 data/bin/ 下"}
        yield {"type": "exit", "code": 1}
        return
    target = (target or "").strip().strip("'\"")
    if not re.match(r"^https?://", target):
        yield {"type": "error", "data": "target 必须是完整 URL（带 http:// 或 https://）"}
        yield {"type": "exit", "code": 1}
        return
    try:
        extra = shlex.split(args or "")
    except ValueError:
        yield {"type": "error", "data": "args 引号不匹配"}
        yield {"type": "exit", "code": 1}
        return

    cmd = [exe, "-u", target, "-silent", "-no-color"] + extra
    yield {"type": "command", "data": " ".join(cmd)}

    total = tool.tool_timeout or config.TOOL_TIMEOUT
    deadline = time.time() + total
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as e:
        yield {"type": "error", "data": f"无法启动 nuclei：{e}"}
        yield {"type": "exit", "code": 1}
        return

    buf = ""
    lines = 0
    truncated = False
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            proc.kill()
            yield {"type": "error", "data": f"nuclei 超过总时长上限（{total}s），已终止"}
            break
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(4096),
                                           timeout=min(remaining, config.TOOL_IDLE_TIMEOUT))
        except asyncio.TimeoutError:
            proc.kill()
            yield {"type": "error", "data": f"nuclei 超过 {config.TOOL_IDLE_TIMEOUT}s 无输出，已终止"}
            break
        if not chunk:
            break
        buf += chunk.decode("utf-8", errors="replace")
        while True:
            m = re.search(r"\r\n|\n|\r", buf)
            if not m:
                break
            line, buf = buf[: m.start()], buf[m.end():]
            if not line.strip():
                continue
            lines += 1
            if lines > config.MAX_OUTPUT_LINES:
                truncated = True
                continue
            yield {"type": "output", "data": line}
    if buf.strip():
        yield {"type": "output", "data": buf}
    try:
        await asyncio.wait_for(proc.wait(), timeout=10)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
    if truncated:
        yield {"type": "output", "data": f"（输出超过 {config.MAX_OUTPUT_LINES} 行，已截断）"}
    yield {"type": "exit", "code": proc.returncode or 0}
