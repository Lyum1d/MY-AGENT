# -*- coding: utf-8 -*-
"""FOFA 资产测绘客户端（供内置工具 fofa_search 使用）。

- Key 从本机 config.yaml 的 fofaEmail/fofaKey 读取（该文件不入库，与 ceye/密钥同层）。
- httpx 客户端 trust_env=False（对齐 R5 红线：不受环境代理影响，FOFA 国内可直连）。
- 仅查询 fofa.info 公开资产数据库，不与被测目标交互。
"""
from __future__ import annotations

import base64
from typing import Any

import httpx

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from . import config

FOFA_API = "https://fofa.info/api/v1/search/all"


def _parse_flat_yaml(text: str) -> dict:
    """无 pyyaml 时的极简解析：只支持本项目 config.yaml 用到的扁平 key: value。

    背景：config.yaml 此前只在装了 pyyaml 时才能读，而 requirements.txt 没声明该依赖，
    导致 FOFA 永远提示「未配置」。这里补一个内置兜底，装不装 pyyaml 功能都可用。
    不追求通用 YAML 语义（嵌套/列表/多行），够用即可；有 pyyaml 时优先走 pyyaml。
    """
    out: dict[str, object] = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line or line.startswith("-"):
            continue
        key, val = line.split(":", 1)
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if not key:
            continue
        out[key] = int(val) if val.isdigit() else val
    return out


def _load_fofa_conf() -> dict[str, str]:
    """从 config.yaml 读 fofaEmail/fofaKey（个人配置不入库）。"""
    out = {"email": "", "key": "", "size": 100}
    cfg_path = config.APP_DIR / "config.yaml"
    if not cfg_path.exists():
        return out
    try:
        text = cfg_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return out

    data: object = {}
    if yaml is not None:
        try:
            data = yaml.safe_load(text) or {}
        except Exception:
            data = _parse_flat_yaml(text)
    else:
        # 未安装 pyyaml：走内置兜底解析（config.yaml 已加入 requirements，正常应有）
        data = _parse_flat_yaml(text)
    if not isinstance(data, dict):
        return out

    out["email"] = str(data.get("fofaEmail") or "").strip()
    out["key"] = str(data.get("fofaKey") or "").strip()
    try:
        out["size"] = min(500, max(1, int(data.get("fofaSize") or 100)))
    except Exception:
        out["size"] = 100
    return out



def is_configured() -> bool:
    c = _load_fofa_conf()
    return bool(c["key"])


async def search(query: str, size: int | None = None,
                 fields: str = "host,ip,port,title,server") -> dict[str, Any]:
    """执行 FOFA 查询。query 为 FOFA 语法（如 domain="example.com"）。"""
    conf = _load_fofa_conf()
    if not conf["key"]:
        return {"error": (
            "FOFA 未配置。请在 src-agent 本机 config.yaml 中填写 fofaEmail / fofaKey"
            "（该文件不入库），无需重启即可生效。"
        )}
    q = (query or "").strip()
    if not q:
        return {"error": "查询语法为空。FOFA 语法示例：domain=\"example.com\"、body=\"Coremail\"、icp=\"京ICP备xxxx号\"。"}
    n = size or conf["size"]
    params: dict[str, Any] = {
        "key": conf["key"],
        "qbase64": base64.b64encode(q.encode()).decode(),
        "size": n,
        "fields": fields,
    }
    if conf["email"]:
        params["email"] = conf["email"]

    try:
        async with httpx.AsyncClient(trust_env=False, timeout=30.0) as client:
            resp = await client.get(FOFA_API, params=params)
            data = resp.json()
    except Exception as e:
        return {"error": f"FOFA 请求失败：{e}"}

    if data.get("error"):
        msg = str(data.get("errmsg") or data.get("message") or "未知错误")
        hint = ""
        if "820041" in msg or "上限" in msg or "F点" in msg:
            hint = "（今日配额/F点已用尽，FOFA 测绘暂停，可先挖已入库资产）"
        elif "429" in msg or "频繁" in msg:
            hint = "（请求过频，稍后再试）"
        elif "401" in msg or "无效" in msg or "不正确" in msg:
            hint = "（email/key 无效，请检查 config.yaml）"
        return {"error": f"FOFA：{msg}{hint}", "query": q}

    results = data.get("results") or []
    rows = []
    for r in results:
        if isinstance(r, (list, tuple)) and len(r) >= 5:
            rows.append({"host": r[0], "ip": r[1], "port": r[2],
                         "title": r[3], "server": r[4]})
        else:
            rows.append({"raw": r})
    return {
        "query": q,
        "count": len(results),
        "total": data.get("size"),
        "consumed_fpoint": data.get("consumed_fpoint"),
        "results": rows,
    }
