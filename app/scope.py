# -*- coding: utf-8 -*-
"""授权白名单（data/scope.json）唯一实现。

背景：白名单此前在三个地方各写了一份，且语义已经分叉——
  · app/executor.py  的 _load_scope：只读文件，缺失返回空（进而 fail-closed 拒绝）
  · app/replayer.py  的 _load_scope：文件缺失时会**静默写入** example.com 再放行
  · app/pyexec.py     直接复用 executor 的 check_scope
同名函数两套行为，安全边界的实际效果取决于走哪条路径，属于隐患。
这里收敛为唯一实现：三处调用方（命令行执行器 / HTTP 重放器 / py_exec）共用。

设计取舍（沿用 executor 原有约定，不放宽任何闸门）：
  · 白名单为空（含 scope.json 不存在或解析失败）一律视为「未授权」，由调用方拒绝执行。
    宁严不松：静默放行会让这道校验形同虚设。
  · 不擅自创建默认 scope.json。此前重放器会写入 example.com 兜底，容易让人误以为
    「已经配好了授权」，故一律只读、不写。
  · 子域匹配：条目可写域名或 IP；example.com 同时匹配 a.example.com。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from . import config

# ---------- 主机形态识别 ----------
# 为什么放在这里：py_exec 的 target 与 Agent 的「从任务描述提取目标」都在判断
# 「这个字符串到底是不是主机」，两处规则一旦分叉就会出现「一边认、一边不认」的
# 静默缺口（此前 py_exec 用「不含点就跳过」的粗判，加个空格即可绕过白名单）。
# 现收敛为唯一实现，agent.py 与 pyexec.py 共用。
#
# 文件名后缀列表：这些其实不是 TLD，是模型把文件名当域名填进来的常见误判。
# 公开命名：agent.py 的「从任务描述提取目标」也用这一份，避免两处列表分叉。
FAKE_TLDS = {
    "json", "exe", "jar", "py", "txt", "log", "md", "bat", "vbs", "vbe",
    "yaml", "yml", "ini", "csv", "xlsx", "xls", "dll", "sys", "cfg", "conf",
}
_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
_URL_RE = re.compile(r"https?://[^\s，。；）)\"'<>]+")
_DOMAIN_RE = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")

# 只回环 / 明确指向本机的名字：任何授权场景下都不该成为 SRC 测试目标，
# 且它们「不含点」不会自然落入主机判定，需单独点名拦截（防「代码里打本机」）。
_DENY_HOSTS = {"localhost", "localhost.localdomain", "0.0.0.0"}


def _is_host_like(token: str) -> bool:
    """单个 token 是否像 URL / IPv4 / 域名（而非企业名、版本号等自由文本）。"""
    t = (token or "").strip().strip("'\"<>()[]")
    if not t:
        return False
    if _URL_RE.match(t):
        return True
    if _IPV4_RE.fullmatch(t):
        return True
    m = _DOMAIN_RE.fullmatch(t)
    if not m:
        return False
    # 排除「v1.2.3」这类末段是数字的串，以及把文件名当域名的情况
    return m.group(0).rsplit(".", 1)[-1].lower() not in FAKE_TLDS


def find_hosts(text: str) -> list[str]:
    """从自由文本里抽出所有「像主机」的片段，按出现顺序去重返回。

    用于「target 里可能混着说明文字/多个主机」的场景：逐个校验，
    只要有一个不在白名单就拒绝——不能让一个空格把整串带去跳过校验。
    """
    s = (text or "").strip()
    if not s:
        return []
    out: list[str] = []
    for m in _URL_RE.finditer(s):
        h = target_host(m.group(0))
        if h and h not in out:
            out.append(h)
    for m in _IPV4_RE.finditer(s):
        tok = m.group(0)
        if tok not in out:
            out.append(tok)
    for m in _DOMAIN_RE.finditer(s):
        tok = m.group(0)
        tld = tok.rsplit(".", 1)[-1].lower()
        if tld in FAKE_TLDS:
            continue
        if tok not in out:
            out.append(tok)
    # 只回环 / 指向本机的名字单独兜一层
    for tok in re.split(r"[\s,;、]+", s):
        tok = tok.strip().strip("'\"<>()[]").lower()
        if tok in _DENY_HOSTS and tok not in out:
            out.append(tok)
    # 「像主机」的片段才返回；纯自由文本（企业名/版本号）返回空
    return [h for h in out if h in _DENY_HOSTS or _is_host_like(h) or _IPV4_RE.fullmatch(h)]


def load_scope() -> list[str]:
    """读取授权白名单的**主机合并视图**：domains 数组 + targets[].host 合并去重。

    v012 P2-3 起支持结构化 targets 写法——所有既有的主机级校验
    （check_scope / argv 逐 token 复核 / 目标列表文件 / py_exec）都消费本函数，
    因此结构化条目的 host 自动获得与 domains 同等的白名单资格；
    端口/协议细粒度限制由 check_scope 额外处理。
    文件缺失或解析失败返回空列表（长度 0 = 未配置任何授权）。
    """
    entries = _read_scope_raw()
    if entries is None:
        return []
    hosts: list[str] = []
    for e in entries:
        if e["host"] not in hosts:
            hosts.append(e["host"])
    return hosts


def _read_scope_raw() -> list[dict] | None:
    """读原始 scope.json 并归一化为结构化条目；文件缺失/解析失败返回 None。"""
    p = config.SCOPE_FILE
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    out: list[dict] = []
    domains = data.get("domains", [])
    if isinstance(domains, list):
        for d in domains:
            if isinstance(d, str) and d.strip():
                out.append({"host": d.strip().lower(), "ports": None, "schemes": None})
    for t in (data.get("targets") or []):
        if not isinstance(t, dict):
            continue
        host = str(t.get("host") or "").strip().lower()
        if not host:
            continue
        ports = t.get("ports")
        schemes = t.get("schemes")
        try:
            ports_set = {int(x) for x in ports} if isinstance(ports, list) and ports else None
        except (TypeError, ValueError):
            ports_set = None
        out.append({
            "host": host,
            "ports": ports_set,
            "schemes": {str(x).strip().lower() for x in schemes}
                       if isinstance(schemes, list) and schemes else None,
        })
    return out


def load_scope_targets() -> list[dict]:
    """读取结构化授权条目（v012 P2-3）。

    scope.json 支持两种写法（可混用）：
      {"domains": ["example.com", ...]}                     —— 旧写法，主机级，端口/协议不限
      {"targets": [{"host": "example.com", "ports": [80, 443],
                    "schemes": ["https"]}, ...]}            —— 新写法，可限定端口/协议
    归一化输出：[{host, ports(set|None), schemes(set|None)}]；
    ports/schemes 未声明 = 不限（向后兼容：旧 domains 的效果）。
    """
    entries = _read_scope_raw()
    return entries if entries is not None else []


def target_host(target: str) -> str:
    """从 target 提取主机名：去协议、端口、路径、查询串与凭据。

    支持 URL / 纯域名 / IPv4 三种形态。无法解析时回退为去掉端口的原文，
    保证「解析不出来」不会变成「绕过校验」——回退值照样要过白名单。
    """
    t = (target or "").strip().lower()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    try:
        host = urlparse(t).hostname or ""
    except Exception:
        host = ""
    if host:
        # 尾点 FQDN（'www.jiaoyu.cn.'）会被 urlparse 原样保留，导致子域匹配失败；
        # 统一去掉尾点（审计 P2-3，方向仍是 fail-closed）
        return host.rstrip(".")
    # 解析失败：至少去掉端口，避免 "example.com:8080" 这类绕过精确匹配
    return t.split("/", 1)[0].split("@")[-1].split(":")[0]


def host_in_scope(host: str, scope: list[str]) -> bool:
    """精确匹配或子域匹配。白名单条目可直接写 IP（IP 走精确匹配）。"""
    if not host:
        return False
    for d in scope:
        if not d:
            continue
        if host == d or host.endswith("." + d):
            return True
    return False


def check_scope(target: str) -> str | None:
    """校验 target 是否在授权白名单内。返回 None 表示放行，否则返回拒绝原因。

    v012 P2-3：scope.json 里条目声明了 ports/schemes 时，target 里的端口与
    协议也一并校验（host 命中但端口/协议不在授权列表 → 拒绝）；
    条目未声明则不限制（完全向后兼容旧的 domains 写法）。
    无法从 target 解析出端口/协议时按「未指定」放行（工具会在连接层报错，
    授权层不做猜测——猜错方向的授权比不授权更危险）。
    """
    host = target_host(target)
    scope = load_scope()
    if not scope:
        return ("授权白名单为空（data/scope.json 未配置或解析失败），已拒绝执行。"
                "请先在 data/scope.json 的 domains 中填写已获书面授权的目标，"
                "或设置环境变量 ENFORCE_SCOPE=0 临时关闭本校验（不建议）。")
    if not host_in_scope(host, scope):
        return (f"目标「{host or target}」不在授权白名单内，已拒绝执行。"
                f"当前白名单：{', '.join(scope)}。"
                f"新增授权目标请编辑 data/scope.json。")
    # ---- 端口/协议细粒度校验（仅当 host 命中的条目声明了 ports/schemes）----
    port, scheme = _parse_port_scheme(target)
    if port is not None or scheme is not None:
        for entry in load_scope_targets():
            if not host_in_scope(host, [entry["host"]]):
                continue
            if entry["ports"] is not None and port is not None and port not in entry["ports"]:
                return (f"目标「{host}:{port}」的端口不在授权范围内"
                        f"（授权端口：{sorted(entry['ports'])}），已拒绝执行。")
            if (entry["schemes"] is not None and scheme is not None
                    and scheme not in entry["schemes"]):
                return (f"目标「{scheme}://{host}」的协议不在授权范围内"
                        f"（授权协议：{sorted(entry['schemes'])}），已拒绝执行。")
    return None


def _parse_port_scheme(target: str) -> tuple[int | None, str | None]:
    """从 target 提取 (端口, 协议)。解析不出返回 (None, None)。

    ⚠️ 只认**显式声明**：协议仅在 target 显式含 "://" 时返回（裸域名不做
    默认 http 推断——域名型工具可能走任意协议/只做 DNS，凭推断去拒绝
    会误杀大量正常请求）；端口仅在显式写出（URL 带端口或裸 host:port）时返回。
    """
    t = (target or "").strip().lower()
    if not t:
        return None, None
    scheme = None
    port = None
    if "://" in t:
        scheme = t.split("://", 1)[0] or None
    try:
        u = urlparse(t if "://" in t else "http://" + t)
        if u.port:
            port = int(u.port)
    except ValueError:
        # host:port 形态：urlparse 对裸 host:port 的 .port 会抛 ValueError
        if ":" in t and "/" not in t:
            tail = t.rsplit(":", 1)[-1]
            if tail.isdigit():
                port = int(tail)
    except Exception:
        pass
    return port, scheme


def first_unauthorized_host_in_argv(tokens: list[str]) -> tuple[int, str] | None:
    """对最终 argv 逐 token 抽主机并过白名单（审计 P0-2/P0-3 的根治层）。

    白名单此前只覆盖 target：args 可走私 --url evil.com，url 型 target 可用
    「授权域/+空格」夹带第二个目标。本函数对 spawn 前的最终 argv 逐 token
    复核，无论走私走 target、args 还是模板渲染，都会被拦下。

    返回第一个含越权主机的 (下标, 主机)；全部放行返回 None。
    argv[0]（解释器/exe 路径）与本地路径形态的 token（盘符/绝对路径）跳过。
    白名单为空时返回 (1, '')，由调用方按 fail-closed 处理。
    """
    scope_list = load_scope()
    if not scope_list:
        return 1, ""
    for i, tok in enumerate(tokens):
        if i == 0:
            continue
        t = (tok or "").strip()
        if not t:
            continue
        # 本地路径形态（盘符 + 斜杠，或以 / 开头的绝对路径）不是测试目标。
        # ⚠️ 必须 re.match 锚定 token 开头：用 re.search 会把 URL scheme 里的
        # 's:/'（http**s:/**）误判成盘符，导致所有 http(s) URL token 被跳过、
        # argv 复核形同虚设（此坑在首次实现时真实踩中）。
        if re.match(r"[A-Za-z]:[\\/]", t) or t.startswith("/"):
            continue
        for h in find_hosts(t):
            if h in _DENY_HOSTS or not host_in_scope(h, scope_list):
                return i, h
    return None


# ---------- 目标列表文件校验（v010，P0-2 收窄后的剩余真空） ----------
# argv 逐 token 复核（上方）只能看到命令行上写出的主机；nuclei/httpx/naabu 等
# 工具的 -l/--list/--urls/--input 参数指向的目标列表文件，其**文件内容**完全不
# 经过 argv —— 文件里写 evil.com 即可绕过全部校验。这里把「列表文件内容」
# 纳入同一套白名单口径。
TARGET_LIST_FLAGS = {"-l", "--list", "--list-", "--urls", "--input", "-l/", "-L"}

# 列表文件读取上限：防止把超大文件当目标清单喂进来拖垮校验（正常目标列表
# 远小于此；超过上限按「拒绝」处理而不是硬读，方向仍是 fail-closed）。
TARGET_LIST_MAX_BYTES = 1 * 1024 * 1024


def _first_unauthorized_host_in_text(text: str, scope_list: list[str]) -> str:
    """逐行抽主机过白名单，返回第一个未授权主机；全部授权返回空串。

    列表文件常见形态：裸域名、URL、host:port、注释行（# 开头）与空行。
    抽取复用 find_hosts（与 argv 复核同一套口径，避免规则分叉）。
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for h in find_hosts(line):
            if h in _DENY_HOSTS or not host_in_scope(h, scope_list):
                return h
    return ""


def first_unauthorized_target_list_in_argv(tokens: list[str]) -> tuple[str, str] | None:
    """扫描 argv 中「目标列表旗标 + 文件路径」，校验文件内容是否含未授权主机。

    返回 (旗标, 未授权主机) 或 None（无列表参数 / 文件不可读 / 内容全部授权）。
    - 旗标后无值（下一个 token 以 - 开头或不存在）→ 交由工具自行报错，放行；
    - 文件不存在 / 无法读取 → 放行（执行时工具会因文件缺失而失败，不是授权问题）；
    - 文件超过 TARGET_LIST_MAX_BYTES → 返回 (旗标, "<oversized>")，按拒绝处理。
    白名单为空时返回 ('', '')，由调用方按 fail-closed 处理。
    """
    scope_list = load_scope()
    if not scope_list:
        return "", ""
    for i, tok in enumerate(tokens):
        if i == 0 or tok not in TARGET_LIST_FLAGS:
            continue
        if i + 1 >= len(tokens):
            continue
        path = (tokens[i + 1] or "").strip()
        if not path or path.startswith("-"):
            continue
        p = Path(path)
        try:
            if not p.is_file():
                continue
            if p.stat().st_size > TARGET_LIST_MAX_BYTES:
                return tok, "<oversized>"
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        bad = _first_unauthorized_host_in_text(text, scope_list)
        if bad:
            return tok, bad
    return None
