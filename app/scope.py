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
    """读取授权白名单。文件缺失或解析失败返回空列表（长度 0 = 未配置任何授权）。"""
    p = config.SCOPE_FILE
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    domains = data.get("domains", [])
    if not isinstance(domains, list):
        return []
    return [d.strip().lower() for d in domains if isinstance(d, str) and d.strip()]


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
        return host
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
    """校验 target 是否在授权白名单内。返回 None 表示放行，否则返回拒绝原因。"""
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
    return None
