# -*- coding: utf-8 -*-
"""统一流量调度器（v023.1）：所有可控出网请求的唯一入口。

为什么需要它：v022 的 ratelimit 只是「两次请求之间 sleep」，挡不住三类真实风险
（见 v023 计划与 zueb.edu.cn 实测事故）：
  1. 脚本/分支在等待窗口内并发排队，累计突发；
  2. 多个会话/子任务各算各的计时，对同一目标的实际速率是各分量之和；
  3. 出了事没有任何审计，无法回答「到底发了多少请求、什么时候、谁发的」。

本模块提供：滑动窗口预算 + 目标/根域名并发限制 + 可取消等待 + 请求指纹
+ 流量事件落库 + 目标状态（暂停/封禁，为 v023.3 状态机预留）。

安全边界：
- scope 校验仍以 app/scope.py 为准（本模块只做兜底复核）；
- 本模块**不做** WAF 绕过、不做代理/IP 轮换；预算耗尽即拒绝，不自动提高；
- 暂停/封禁状态持久化（落 SQLite），服务重启不清除；
- 等待是可取消的：任务取消或目标暂停后，排队请求不得再发出。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
import time
from collections import deque
from urllib.parse import urlsplit

from . import config, scope

logger = logging.getLogger("src_agent.traffic")

# 目标状态常量（v023.1 只有 NORMAL/PAUSED；v023.3 扩充 CAUTION/COOLDOWN/BLOCKED）
ST_NORMAL = "NORMAL"
ST_PAUSED = "PAUSED"          # 人工或预算触发的暂停
ST_CAUTION = "CAUTION"        # 预留：v023.3
ST_COOLDOWN = "COOLDOWN"      # 预留：v023.3
ST_BLOCKED = "BLOCKED"        # 预留：v023.3

BLOCKING_STATES = {ST_PAUSED, ST_COOLDOWN, ST_BLOCKED}


class TrafficError(Exception):
    """调度拒绝（统一基类，调用方按需细分处理）。"""


class TrafficPaused(TrafficError):
    """目标处于暂停/封禁状态。"""


class TrafficBudgetExceeded(TrafficError):
    """滑动窗口请求预算耗尽。"""


class TrafficCancelled(TrafficError):
    """等待许可期间任务被取消。"""


class TrafficScopeDenied(TrafficError):
    """scope 兜底校验未通过。"""


def _is_loopback_or_private(host: str) -> bool:
    """私有/回环地址判定（用于审计标注，不作为放行依据）。"""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.startswith(("10.", "192.168.", "127.")):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False


class TrafficGovernor:
    """目标级流量调度器（进程内单例，状态落库）。"""

    def __init__(self) -> None:
        # 聚合键 → 已发送时间戳（滑动窗口）。进程内热数据，落库用于重启恢复
        self._sent: dict[str, deque] = {}
        self._fingerprints: dict[str, dict] = {}     # fp → {at, status}
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._root_locks: dict[str, asyncio.Lock] = {}
        self._global_lock: asyncio.Lock | None = None
        self._loop = None                            # 检测事件循环变化（测试/多循环场景）
        self._inflight: dict[str, int] = {}          # root → 在途请求数
        self._queued: dict[str, int] = {}            # root → 排队数
        self._states: dict[str, dict] = {}           # root → 状态（DB 为权威，内存为缓存）
        self._ip_cache: dict[str, tuple[float, str]] = {}
        self._window_loaded: set[str] = set()        # 已从 DB 恢复过窗口的 key
        self._policy_cache: dict[str, dict] = {}     # root → DB 策略覆盖
        self._ip_resolve_enabled = True

    # ---------- 事件循环与锁管理 ----------
    def _ensure_loop(self) -> None:
        """检查事件循环是否变化；变化则重建所有 asyncio 原语。

        背景（v013 教训）：asyncio 原语绑定创建时的事件循环，跨循环使用会抛
        「bound to a different event loop」。服务是单循环，但测试里 asyncio.run()
        每次新建循环——原语必须跟着重建。
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._loop is not loop:
            self._loop = loop
            self._host_locks.clear()
            self._root_locks.clear()
            self._global_lock = asyncio.Lock()

    def _lock(self, store: dict, key: str) -> asyncio.Lock:
        lock = store.get(key)
        if lock is None:
            lock = asyncio.Lock()
            store[key] = lock
        return lock

    # ---------- 聚合键 ----------
    @staticmethod
    def root_domain_of(host: str) -> str:
        """根域名（近似）：取末两段；两段式后缀（.com.cn 等）取末三段。"""
        h = (host or "").split(":")[0].lower()
        if not h:
            return ""
        parts = h.split(".")
        if len(parts) <= 2:
            return h
        two_level = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk",
                     "com.hk", "com.tw", "co.jp", "com.au"}
        if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def resolve_ip(self, host: str) -> str:
        """解析主机 IP（带缓存）。解析失败返回空串——此时按根域名聚合。"""
        if not self._ip_resolve_enabled or not host:
            return ""
        now = time.time()
        cached = self._ip_cache.get(host)
        if cached and now - cached[0] < 300:
            return cached[1]
        try:
            ip = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
        except Exception:
            ip = ""
        self._ip_cache[host] = (now, ip)
        return ip

    # ---------- 状态（DB 权威 + 内存缓存） ----------
    def _load_state(self, root: str, project_id: str) -> dict:
        if root in self._states:
            return self._states[root]
        rec = None
        try:
            from . import store
            rec = store.get_traffic_state(root)
        except Exception:
            logger.debug("读取流量状态失败（首次运行/表未建）", exc_info=True)
        st = rec or {"root_domain": root, "state": ST_NORMAL, "reason": "", "cooldown_until": 0}
        self._states[root] = st
        return st

    def state_of(self, root: str, project_id: str = "") -> dict:
        return self._load_state(root, project_id)

    def pause(self, root: str, reason: str, *, project_id: str = "") -> dict:
        """暂停某根域名（人工操作或预算熔断）。持久化——重启不清除。"""
        st = self._load_state(root, project_id)
        st.update({"state": ST_PAUSED, "reason": reason, "cooldown_until": 0})
        self._persist_state(st, project_id)
        self._audit(root, "", "paused", reason=reason, project_id=project_id)
        return st

    def resume(self, root: str, *, project_id: str = "") -> dict:
        """恢复（人工操作）。v023.1 直接回 NORMAL；v023.3 起需经 MANUAL_PROBE。"""
        st = self._load_state(root, project_id)
        st.update({"state": ST_NORMAL, "reason": "人工恢复"})
        self._persist_state(st, project_id)
        self._audit(root, "", "resumed", reason="人工恢复", project_id=project_id)
        return st

    def _persist_state(self, st: dict, project_id: str) -> None:
        try:
            from . import store
            store.upsert_traffic_state(project_id, st)
        except Exception:
            logger.warning("持久化流量状态失败（内存状态仍生效）", exc_info=True)

    # ---------- 窗口与预算 ----------
    def _recover_window(self, key: str) -> None:
        """首次访问某 key 时从 DB 恢复最近窗口内的发送时间戳（重启恢复）。"""
        if key in self._window_loaded:
            return
        self._window_loaded.add(key)
        dq = self._sent.setdefault(key, deque())
        if dq:
            return
        try:
            from . import store
            rows = store.recent_traffic_sends(key, config.TRAFFIC_WINDOW_SECONDS)
            dq.extend(rows)
        except Exception:
            logger.debug("窗口恢复失败（新库/表未建）", exc_info=True)

    def _prune(self, key: str, now: float) -> deque:
        dq = self._sent.setdefault(key, deque())
        horizon = now - config.TRAFFIC_WINDOW_SECONDS
        while dq and dq[0] < horizon:
            dq.popleft()
        return dq

    def _limits(self, root: str = "") -> dict:
        """有效策略：DB 里该根域名的覆盖（若有）优先，否则用 config 保守默认。

        任何来源都只能更低——测试模式是唯一放大通道且由环境变量显式开启，
        生产环境不设即保守。
        """
        mult = config.TRAFFIC_TEST_MULTIPLIER if config.TRAFFIC_TEST_MODE else 1
        concurrency_bonus = 4 if config.TRAFFIC_TEST_MODE else 1
        lim = {
            "window": config.TRAFFIC_WINDOW_SECONDS,
            "max_requests": config.TRAFFIC_MAX_REQUESTS,
            "burst": config.TRAFFIC_BURST,
            "host_conc": max(1, config.TRAFFIC_HOST_CONCURRENCY),
            "root_conc": max(1, config.TRAFFIC_ROOT_CONCURRENCY),
        }
        if root:
            if root not in self._policy_cache:
                pol = None
                try:
                    from . import store
                    pol = store.get_traffic_policy(root)
                except Exception:
                    logger.debug("读取流量策略失败（用默认档）", exc_info=True)
                self._policy_cache[root] = pol or {}
            pol = self._policy_cache[root] or {}
            if pol.get("window_seconds"):
                lim["window"] = int(pol["window_seconds"])
            if pol.get("max_requests"):
                lim["max_requests"] = int(pol["max_requests"])
            if pol.get("burst_limit"):
                lim["burst"] = int(pol["burst_limit"])
            if pol.get("host_concurrency"):
                lim["host_conc"] = max(1, int(pol["host_concurrency"]))
            if pol.get("root_concurrency"):
                lim["root_conc"] = max(1, int(pol["root_concurrency"]))
        lim["max_requests"] *= mult
        lim["burst"] *= mult
        lim["host_conc"] = max(1, lim["host_conc"] * concurrency_bonus)
        lim["root_conc"] = max(1, lim["root_conc"] * concurrency_bonus)
        return lim

    # ---------- 指纹 ----------
    @staticmethod
    def fingerprint(method: str, url: str, *, body: str = "", identity_id: str = "",
                    variant_id: str = "", headers: dict | None = None) -> str:
        """请求指纹：方法 + 规范化 URL + 敏感头哈希 + body 哈希 + 身份 + 变体。

        只哈希不落原文——指纹表不含凭据内容。
        """
        from .importers.common import normalize_url
        h = {"m": (method or "GET").upper(), "u": normalize_url(url),
             "b": hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest()[:16],
             "i": identity_id or "", "v": variant_id or "",
             "h": hashlib.sha256(json.dumps(sorted((headers or {}).items()),
                                            ensure_ascii=False).encode()).hexdigest()[:16]}
        return hashlib.sha256(json.dumps(h, sort_keys=True).encode()).hexdigest()[:32]

    def cached_observation(self, fp: str) -> dict | None:
        """TTL 内是否已有同指纹成功观察（TTL=0 时永远返回 None）。"""
        if config.TRAFFIC_FP_TTL <= 0 or not fp:
            return None
        rec = self._fingerprints.get(fp)
        if rec and time.time() - rec["at"] < config.TRAFFIC_FP_TTL:
            return rec
        return None

    def put_observation(self, fp: str, status_code: int) -> None:
        if config.TRAFFIC_FP_TTL > 0 and fp:
            self._fingerprints[fp] = {"at": time.time(), "status": status_code}

    # ---------- 许可（核心） ----------
    async def acquire(self, url: str, *, project_id: str = "", session_id: str = "",
                      identity_id: str = "", tool_alias: str = "", method: str = "GET",
                      fingerprint: str = "", cancel_event=None) -> dict:
        """取得一次出网许可。未取得许可前不得发起网络请求。

        阻塞点全部可取消：等待期间若 cancel_event 置位、目标进入暂停/封禁状态，
        立即抛出对应异常（排队请求不会在暂停后继续发出）。
        """
        self._ensure_loop()
        # 1) scope 兜底（授权边界的第一责任方仍是 scope.py；这里防绕过）
        denied = scope.check_scope(url)
        if denied:
            self._audit_raw(url, "rejected", reason=denied, project_id=project_id,
                            session_id=session_id, tool_alias=tool_alias)
            raise TrafficScopeDenied(denied)

        parts = urlsplit(url)
        host = (parts.netloc or "").split("@")[-1]
        root = self.root_domain_of(host)
        ip = self.resolve_ip(host.split(":")[0])
        lim = self._limits(root)

        def _cancelled() -> bool:
            return bool(cancel_event is not None and cancel_event.is_set())

        def _check_state():
            st = self._load_state(root, project_id)
            if st.get("state") in BLOCKING_STATES:
                raise TrafficPaused(
                    f"目标 {root} 当前状态 {st.get('state')}（{st.get('reason') or '无原因'}）——"
                    f"已停止自动请求，需人工恢复")
            if _cancelled():
                raise TrafficCancelled("任务已取消，排队请求不再发出")

        _check_state()
        root_lock = self._lock(self._root_locks, root or "default")
        host_lock = self._lock(self._host_locks, host or "default")

        self._queued[root] = self._queued.get(root, 0) + 1
        try:
            # 2) 根域名串行（同时最多 root_conc 个在途；v023.1 默认 1）
            async with root_lock:
                self._check_pause_during_wait(root, project_id, _cancelled)
                async with host_lock:
                    self._check_pause_during_wait(root, project_id, _cancelled)
                    # 3) 预算：滑动窗口 + 突发
                    self._enforce_budget(root, lim, project_id, session_id,
                                         tool_alias, url)
                    now = time.time()
                    self._prune(root, now).append(now)
                    # 注意：不要对 host 维度重复 append——root 与 host 相同时
                    # setdefault 返回的是同一个 deque，会双计数（v023.1 自测踩坑）
                    if config.TRAFFIC_FP_TTL > 0 and fingerprint:
                        self.put_observation(fingerprint, -1)
                    self._inflight[root] = self._inflight.get(root, 0) + 1
                    permit = {"root": root, "host": host, "resolved_ip": ip,
                              "sent_at": now, "fingerprint": fingerprint,
                              "project_id": project_id, "session_id": session_id,
                              "tool_alias": tool_alias, "url": url, "method": method}
                    self._audit_raw(url, "sent", project_id=project_id,
                                    session_id=session_id, tool_alias=tool_alias,
                                    fingerprint=fingerprint, host=host, root=root, ip=ip)
                    return permit
        finally:
            self._queued[root] = max(0, self._queued.get(root, 0) - 1)

    def _check_pause_during_wait(self, root: str, project_id: str, cancelled) -> None:
        """拿到锁后、真正发送前，再查一次状态与取消（计划 5.4：暂停后不得发出）。"""
        if cancelled():
            raise TrafficCancelled("任务已取消，排队请求不再发出")
        st = self._load_state(root, project_id)
        if st.get("state") in BLOCKING_STATES:
            raise TrafficPaused(f"目标 {root} 已进入 {st.get('state')}，排队请求终止")

    def _enforce_budget(self, root: str, lim: dict, project_id: str, session_id: str,
                        tool_alias: str, url: str) -> None:
        self._recover_window(root)
        now = time.time()
        dq = self._prune(root, now)
        if len(dq) >= lim["max_requests"]:
            reason = (f"目标 {root} 在 {lim['window']}s 窗口内已发 {len(dq)} 个请求，"
                      f"达到预算上限 {lim['max_requests']}——已暂停，不会自动提高额度")
            self.pause(root, reason, project_id=project_id)
            self._audit_raw(url, "rejected", reason=reason, project_id=project_id,
                            session_id=session_id, tool_alias=tool_alias)
            raise TrafficBudgetExceeded(reason)
        recent_burst = sum(1 for t in dq if now - t < 10.0)
        if recent_burst >= lim["burst"]:
            reason = (f"10 秒内已发 {recent_burst} 个请求，达到突发上限 {lim['burst']}"
                      f"（防脚本爆发式请求）")
            self._audit_raw(url, "rejected", reason=reason, project_id=project_id,
                            session_id=session_id, tool_alias=tool_alias)
            raise TrafficBudgetExceeded(reason)

    # ---------- 结果登记与审计 ----------
    async def release(self, permit: dict, *, status_code: int | None = None,
                      bytes_in: int = 0, error_type: str = "", os_error_code: int = 0) -> None:
        """请求结束后登记结果（并发计数递减 + 事件落库 + 状态更新）。"""
        if not permit:
            return
        root = permit.get("root", "")
        self._inflight[root] = max(0, self._inflight.get(root, 0) - 1)
        now = time.time()
        st = self._load_state(root, permit.get("project_id", ""))
        if status_code is not None and 200 <= status_code < 400:
            st["last_success_at"] = now
        elif error_type or (status_code is not None and status_code >= 500):
            st["last_error_at"] = now
            st["last_error_type"] = error_type or f"HTTP {status_code}"
            st["last_error_code"] = os_error_code or 0
        self._persist_state(st, permit.get("project_id", ""))
        if config.TRAFFIC_FP_TTL > 0 and permit.get("fingerprint") and status_code:
            self.put_observation(permit["fingerprint"], status_code)
        self._audit_raw(permit.get("url", ""), "settled",
                        project_id=permit.get("project_id", ""),
                        session_id=permit.get("session_id", ""),
                        tool_alias=permit.get("tool_alias", ""),
                        fingerprint=permit.get("fingerprint", ""),
                        host=permit.get("host", ""), root=root,
                        ip=permit.get("resolved_ip", ""),
                        status_code=status_code, bytes_in=bytes_in,
                        error_type=error_type, os_error_code=os_error_code)

    # ---------- 统计（供状态 API / 前端） ----------
    def stats(self, root: str) -> dict:
        lim = self._limits(root)
        now = time.time()
        self._recover_window(root)
        dq = self._prune(root, now)
        st = self._load_state(root, "")
        return {
            "root_domain": root,
            "state": st.get("state", ST_NORMAL),
            "reason": st.get("reason", ""),
            "window_seconds": lim["window"],
            "max_requests": lim["max_requests"],
            "used": len(dq),
            "remaining": max(0, lim["max_requests"] - len(dq)),
            "requests_last_60s": sum(1 for t in dq if now - t < 60),
            "requests_last_600s": sum(1 for t in dq if now - t < 600),
            "inflight": self._inflight.get(root, 0),
            "queued": self._queued.get(root, 0),
            "tests_mode": config.TRAFFIC_TEST_MODE,
            "last_success_at": st.get("last_success_at"),
            "last_error_at": st.get("last_error_at"),
            "last_error_type": st.get("last_error_type", ""),
        }

    def roots_seen(self) -> list[str]:
        keys = set(self._sent.keys())
        try:
            from . import store
            keys.update(store.distinct_traffic_roots())
        except Exception:
            pass
        return sorted(k for k in keys if k)

    # ---------- 审计落库（失败不阻断请求） ----------
    def _audit(self, root: str, url: str, event_type: str, reason: str = "",
               project_id: str = "") -> None:
        self._audit_raw(url or root, event_type, reason=reason, project_id=project_id,
                        root=root)

    def _audit_raw(self, url: str, event_type: str, *, reason: str = "",
                   project_id: str = "", session_id: str = "", tool_alias: str = "",
                   fingerprint: str = "", host: str = "", root: str = "",
                   ip: str = "", status_code: int | None = None, bytes_in: int = 0,
                   error_type: str = "", os_error_code: int = 0) -> None:
        try:
            from . import store
            if not host:
                parts = urlsplit(url)
                host = (parts.netloc or "").split("@")[-1]
            if not root:
                root = self.root_domain_of(host)
            port = 0
            if "://" in url:
                try:
                    port = urlsplit(url).port or (443 if url.startswith("https") else 80)
                except ValueError:
                    port = 0
            store.add_traffic_event({
                "project_id": project_id, "session_id": session_id,
                "root_domain": root, "host": host, "resolved_ip": ip, "port": port,
                "tool_alias": tool_alias, "identity_label": "",
                "request_fingerprint": fingerprint, "event_type": event_type,
                "status_code": status_code, "error_type": error_type,
                "os_error_code": os_error_code, "bytes_in": bytes_in,
                "redaction_summary": reason[:300],
            })
        except Exception:
            logger.debug("流量事件落库失败（不影响请求）", exc_info=True)

    # ---------- 测试支持 ----------
    def reset(self) -> None:
        """清空进程内状态（仅测试用；不动数据库）。"""
        self._sent.clear()
        self._fingerprints.clear()
        self._host_locks.clear()
        self._root_locks.clear()
        self._global_lock = None
        self._inflight.clear()
        self._queued.clear()
        self._states.clear()
        self._window_loaded.clear()
        self._ip_cache.clear()
        self._policy_cache.clear()


# 进程内单例
governor = TrafficGovernor()
