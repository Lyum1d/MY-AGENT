# -*- coding: utf-8 -*-
"""py_exec 受控网络通道（v023.2）：脚本 ↔ 宿主的请求代理桥。

背景（v023 实测事故）：封禁由 `py_exec` 脚本内部 `for` 循环直接发请求造成——
外层限速管不住脚本进程里的循环。治理思路是**把网络能力从脚本进程收回宿主**：

    脚本进程                          宿主进程（本模块）
    ─────────                        ─────────────────
    safe_http_request(url)  ──写请求文件──▶  扫描请求队列
                                            → TrafficGovernor 许可
                                              （scope/预算/并发/暂停态）
                                            → httpx 实际发送
    读响应文件（同步轮询）  ◀─写响应文件──  写脱敏结果

为什么用文件队列而不是管道/HTTP：
  · 脚本是同步代码，`await` 不可用；文件轮询零依赖、跨进程稳；
  · 宿主与脚本只需共享一个工作目录（本来就是 py_exec 的沙箱 workdir）；
  · 请求文件原子改名出现（tmp → 正式名），避免读到半个文件。

诚实说明局限：脚本进程**仍可**自行 `import requests` 直连目标——本模块是
「防误触」而不是「防对抗」：静态检测拒绝最危险模式（网络库 + 循环），
真实的使用者是 Agent 而非攻击者。彻底阻断需要防火墙级隔离（超出本版本范围）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

import httpx

from . import config, traffic

logger = logging.getLogger("src_agent.pyexec_bridge")

# 桥接目录名（在工作目录内）
BRIDGE_DIR = ".srcagent_traffic"
REQ_DIR = "req"
RESP_DIR = "resp"

# 脚本侧模块源码：写入沙箱 workdir，脚本 `import srcagent` 或直接调用即可。
# 注意：这里必须是**同步**实现——py_exec 跑的是普通 Python 脚本。
SCRIPT_MODULE_SOURCE = '''# -*- coding: utf-8 -*-
"""src-agent 受控网络接口（由宿主自动注入，勿手工修改）。

用法：
    from srcagent import safe_http_request
    r = safe_http_request("https://authorized.example/api", method="GET")
    print(r["status_code"], r["text"][:200])

所有请求都由宿主进程的流量调度器发出：scope 白名单、滑动窗口预算、
目标并发与暂停状态全部生效。脚本自身的循环不会绕过这些限制——
预算耗尽时返回 {"error": "TRAFFIC_BUDGET_EXCEEDED"}。
"""
import json as _json
import os as _os
import time as _time
import uuid as _uuid

_BRIDGE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".srcagent_traffic")
_REQ = _os.path.join(_BRIDGE, "req")
_RESP = _os.path.join(_BRIDGE, "resp")


def safe_http_request(url, method="GET", headers=None, cookies=None,
                      body="", timeout=25):
    """受控 HTTP 请求（同步）。返回 dict：
    {status_code, headers, text, error, elapsed}。error 非空表示请求未完成。
    """
    rid = _uuid.uuid4().hex[:12]
    payload = {
        "id": rid, "url": url, "method": (method or "GET").upper(),
        "headers": headers or {}, "cookies": cookies or {},
        "body": body or "", "created_at": _time.time(),
    }
    tmp = _os.path.join(_REQ, rid + ".tmp")
    final = _os.path.join(_REQ, rid + ".json")
    with open(tmp, "w", encoding="utf-8") as f:
        _json.dump(payload, f, ensure_ascii=False)
    _os.replace(tmp, final)          # 原子出现，宿主不会读到半个文件
    resp_path = _os.path.join(_RESP, rid + ".json")
    deadline = _time.time() + float(timeout)
    while _time.time() < deadline:
        if _os.path.exists(resp_path):
            try:
                with open(resp_path, "r", encoding="utf-8") as f:
                    data = _json.load(f)
            except (OSError, ValueError):
                data = {"error": "响应文件读取失败"}
            try:
                _os.remove(resp_path)
            except OSError:
                pass
            return data
        _time.sleep(0.1)
    return {"error": "TIMEOUT_WAITING_HOST_BRIDGE",
            "hint": "宿主未在超时内响应；目标可能已暂停或预算耗尽"}


def get(url, **kw):
    """便捷封装：GET。"""
    return safe_http_request(url, method="GET", **kw)


def post(url, body="", **kw):
    """便捷封装：POST（写方法需人工确认闸门放行后才会由宿主执行）。"""
    return safe_http_request(url, method="POST", body=body, **kw)
'''


def prepare_workdir(workdir: Path) -> Path:
    """在工作目录里铺好桥接目录与脚本侧模块，返回模块路径。"""
    bridge = workdir / BRIDGE_DIR
    (bridge / REQ_DIR).mkdir(parents=True, exist_ok=True)
    (bridge / RESP_DIR).mkdir(parents=True, exist_ok=True)
    mod = workdir / "srcagent.py"
    mod.write_text(SCRIPT_MODULE_SOURCE, encoding="utf-8")
    return mod


class ScriptBridge:
    """宿主侧桥接任务：服务脚本发出的受控请求。"""

    def __init__(self, workdir: Path, *, project_id: str = "", tool_alias: str = "py_exec",
                 max_requests: int = 0, session_id: str = "") -> None:
        self.workdir = Path(workdir)
        self.req_dir = self.workdir / BRIDGE_DIR / REQ_DIR
        self.resp_dir = self.workdir / BRIDGE_DIR / RESP_DIR
        self.project_id = project_id
        self.session_id = session_id
        self.tool_alias = tool_alias
        self.max_requests = max_requests or config.PY_EXEC_MAX_REQUESTS
        self.count = 0
        self.blocked_reason = ""      # 目标暂停/封禁时置位 → 主循环终止脚本树
        self.notes: asyncio.Queue = asyncio.Queue()   # 给主 generator 的输出事件
        self._stop = asyncio.Event()
        self._seen: set[str] = set()

    async def run(self) -> None:
        """轮询请求目录。0.2s 粒度——脚本侧单次请求 25s 超时，足够宽裕。

        注意：本任务在后台跑，异常若逃逸会**静默终止桥接**（脚本侧只会看到
        一直超时）——因此每轮 drain 都包 try/except 并记日志，绝不退出循环。
        """
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=0.2)
                break
            except asyncio.TimeoutError:
                pass
            except Exception:
                logger.exception("桥接等待异常（继续）")
            try:
                await self._drain_once()
            except Exception:
                logger.exception("桥接处理请求异常（继续下一轮）")

    async def _drain_once(self) -> None:
        try:
            names = sorted(p.name for p in self.req_dir.iterdir()
                           if p.name.endswith(".json"))
        except OSError:
            return
        for name in names:
            if name in self._seen:
                continue
            self._seen.add(name)
            path = self.req_dir / name
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            await self._handle(payload)

    async def _handle(self, payload: dict) -> None:
        rid = payload.get("id") or ""
        url = payload.get("url") or ""
        method = (payload.get("method") or "GET").upper()
        resp: dict
        # 预算：脚本级上限（宿主侧计数，脚本无法自增绕过）
        if self.count >= self.max_requests:
            resp = {"error": "TRAFFIC_BUDGET_EXCEEDED",
                    "hint": f"单脚本请求上限 {self.max_requests} 已用尽；"
                            "请拆分脚本或改用受控命令工具"}
            await self._write_resp(rid, resp)
            self.blocked_reason = self.blocked_reason or "脚本请求预算耗尽"
            await self.notes.put(
                f"（脚本请求预算耗尽：{self.count}/{self.max_requests}，"
                f"后续 safe_http_request 一律拒绝）")
            return
        if traffic.READONLY_METHODS and method not in traffic.READONLY_METHODS:
            # 写方法：脚本通道不自动放行（计划 4.4：写操作必须走 L2/L3 人工闸门）
            resp = {"error": "WRITE_METHOD_NOT_ALLOWED_IN_SCRIPT",
                    "hint": f"脚本通道只允许 {'/'.join(traffic.READONLY_METHODS)}；"
                            "写操作请用命令行工具走人工确认闸门"}
            await self._write_resp(rid, resp)
            await self.notes.put(f"（脚本尝试 {method} 被拒：写操作须走人工确认闸门）")
            return
        # 调度器许可（scope / 预算 / 并发 / 暂停态 / 审计）
        try:
            permit = await traffic.governor.acquire(
                url, project_id=self.project_id, session_id=self.session_id,
                tool_alias=self.tool_alias, method=method)
        except traffic.TrafficError as e:
            kind = type(e).__name__
            resp = {"error": kind.upper(), "hint": str(e)}
            await self._write_resp(rid, resp)
            self.blocked_reason = self.blocked_reason or str(e)
            await self.notes.put(f"（受控请求被调度拒绝：{e}）")
            return
        self.count += 1
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                         timeout=config.PY_EXEC_REQUEST_TIMEOUT) as client:
                r = await client.request(
                    method, url,
                    headers=payload.get("headers") or {},
                    cookies=payload.get("cookies") or None,
                    content=(payload.get("body") or "").encode("utf-8") or None)
        except Exception as e:
            await traffic.governor.release(permit, error_type=type(e).__name__,
                                           os_error_code=getattr(e, "errno", 0) or 0)
            resp = {"error": f"{type(e).__name__}: {e}"}
            await self._write_resp(rid, resp)
            return
        await traffic.governor.release(permit, status_code=r.status_code,
                                      bytes_in=len(r.content))
        # v023.6（实战反馈）：截断必须显式告知——否则脚本以为自己拿到了完整
        # 响应体，可能漏掉位于页尾的关键证据（实战中 serverPath 就在 64KB 之后）。
        full_len = len(r.content)
        text = r.text
        resp = {"status_code": r.status_code,
                "headers": {k: v for k, v in list(r.headers.items())[:20]},
                "text": text[:65536],
                "elapsed": round(time.monotonic() - t0, 3)}
        if len(text) > 65536:
            resp["truncated"] = True
            resp["total_chars"] = len(text)
            resp["truncation_note"] = (
                f"响应体已截断：仅返回前 65536 字符（原始 {len(text)} 字符，"
                f"{full_len} 字节）。如需页尾内容，请用 Range 头分片获取，"
                "或把响应保存到本地文件后离线解析。")

        await self._write_resp(rid, resp)

    async def _write_resp(self, rid: str, resp: dict) -> None:
        path = self.resp_dir / f"{rid}.json"
        tmp = self.resp_dir / f"{rid}.tmp"
        try:
            tmp.write_text(json.dumps(resp, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            logger.debug("写响应文件失败（脚本可能已退出）", exc_info=True)

    def stop(self) -> None:
        self._stop.set()


def detect_direct_network(code: str) -> dict:
    """静态检测脚本里的直接网络访问。

    返回 {"has_net_lib", "has_loop", "has_url", "risky", "single_shot"}：
      risky       = 网络库 + 循环 + URL（事故模式：脚本循环直连，外层限速无效）
      single_shot = 网络库 + URL 但**无循环**（v023.6 新增：这类请求同样绕过了
                    调度器——不可审计、不受预算与暂停态约束，必须提示）

    定位说明：这是**防误触**检查（阻止 Agent 写出外层管不住的脚本），
    可被刻意绕过（如 __import__ 动态导入）——不是对抗性安全边界。
    """
    import re
    c = code or ""
    net_lib = bool(re.search(r"\b(import\s+(requests|httpx|aiohttp|http\.client)|"
                             r"from\s+(requests|httpx|aiohttp|http)\s+import|"
                             r"urllib\.request|socket\.socket|import\s+socket)\b", c))
    loop = bool(re.search(r"^\s*(for|while)\s", c, re.MULTILINE))
    url = bool(re.search(r"https?://[^\s\"']+", c))
    return {"has_net_lib": net_lib, "has_loop": loop, "has_url": url,
            "risky": net_lib and loop and url,
            "single_shot": net_lib and url and not loop}
