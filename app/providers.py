# -*- coding: utf-8 -*-
"""LLM 供应商（Provider）注册中心。

目标：让本控制台能接入市面上几乎所有大模型服务——任何 **OpenAI 兼容端点**、
**Anthropic 原生端点**，以及本地 **Ollama / LM Studio / vLLM**，
都统一用「类型 + Base URL + API Key + 模型名」四件套描述。

配置持久化在 %USERPROFILE%\\.src_agent_llm.json（密钥不进项目仓库），
运行时热读：控制台「设置」里增删改后无需重启服务。

兼容旧版本：首次加载时会把旧的 .deepseek_api_key / .llm_anthropic.json 迁移进来。
"""
from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any

from . import config

STORE_VERSION = 1

# 内置不可删除的三个供应商（可编辑、可重置）
BUILTIN_IDS = ("ollama", "deepseek", "anthropic")

# ---------- 厂商预设目录（控制台「从模板添加」用） ----------
# type: openai = OpenAI 兼容 /chat/completions；anthropic = Anthropic /v1/messages
PRESETS: list[dict[str, Any]] = [
    {"key": "ollama", "name": "本地 Ollama", "type": "openai",
     "base_url": "http://localhost:11434/v1", "model": "qwen3.5:9b",
     "local": True, "thinking": True,
     "note": "本机私有部署，数据不出机器；需先 ollama serve"},
    {"key": "lmstudio", "name": "LM Studio / vLLM / 本地服务", "type": "openai",
     "base_url": "http://localhost:1234/v1", "model": "local-model",
     "local": True, "note": "任意 OpenAI 兼容的本地推理服务"},
    # ---- 国内主流 ----
    {"key": "deepseek", "name": "DeepSeek 深度求索", "type": "openai",
     "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat",
     "note": "deepseek-chat / deepseek-reasoner，function calling 已实测"},
    {"key": "qwen", "name": "通义千问（阿里云百炼）", "type": "openai",
     "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "model": "qwen-plus",
     "note": "qwen-plus / qwen-max / qwen-turbo"},
    {"key": "zhipu", "name": "智谱 GLM", "type": "openai",
     "base_url": "https://open.bigmodel.cn/api/paas/v4", "model": "glm-4.6",
     "note": "GLM-4 系列，端点自带 /v1 语义"},
    {"key": "moonshot", "name": "Moonshot Kimi", "type": "openai",
     "base_url": "https://api.moonshot.cn/v1", "model": "moonshot-v1-128k",
     "note": "超长上下文，适合全量源码/日志分析"},
    {"key": "volcengine", "name": "火山方舟（豆包）", "type": "openai",
     "base_url": "https://ark.cn-beijing.volces.com/api/v3", "model": "doubao-pro-32k",
     "note": "需先在方舟控制台创建推理接入点"},
    {"key": "siliconflow", "name": "硅基流动 SiliconFlow", "type": "openai",
     "base_url": "https://api.siliconflow.cn/v1", "model": "Qwen/Qwen2.5-72B-Instruct",
     "note": "一个 Key 打通多款开源模型，按量计费"},
    {"key": "hunyuan", "name": "腾讯混元", "type": "openai",
     "base_url": "https://api.hunyuan.cloud.tencent.com/v1", "model": "hunyuan-turbo",
     "note": "腾讯云 API Key"},
    {"key": "baidu", "name": "百度千帆（文心）", "type": "openai",
     "base_url": "https://qianfan.baidubce.com/v2", "model": "ernie-4.0-8k",
     "note": "千帆平台 OpenAI 兼容网关"},
    {"key": "stepfun", "name": "阶跃星辰 Step", "type": "openai",
     "base_url": "https://api.stepfun.com/v1", "model": "step-1-8k"},
    {"key": "minimax", "name": "MiniMax", "type": "openai",
     "base_url": "https://api.minimax.chat/v1", "model": "MiniMax-Text-01"},
    {"key": "dashscope-intl", "name": "阿里云国际 Model Studio", "type": "openai",
     "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "model": "qwen-plus"},
    # ---- 海外主流 ----
    {"key": "openai", "name": "OpenAI", "type": "openai",
     "base_url": "https://api.openai.com/v1", "model": "gpt-4o",
     "note": "gpt-4o / gpt-4o-mini / o3-mini"},
    {"key": "anthropic", "name": "Anthropic Claude", "type": "anthropic",
     "base_url": "https://api.anthropic.com", "model": "claude-sonnet-4-5",
     "note": "Anthropic 原生 /v1/messages 协议"},
    {"key": "gemini", "name": "Google Gemini", "type": "openai",
     "base_url": "https://generativelanguage.googleapis.com/v1beta/openai", "model": "gemini-2.0-flash",
     "note": "Google 官方 OpenAI 兼容层"},
    {"key": "grok", "name": "xAI Grok", "type": "openai",
     "base_url": "https://api.x.ai/v1", "model": "grok-3"},
    {"key": "groq", "name": "Groq", "type": "openai",
     "base_url": "https://api.groq.com/openai/v1", "model": "llama-3.3-70b-versatile",
     "note": "推理极快，适合批量低复杂决策"},
    {"key": "openrouter", "name": "OpenRouter", "type": "openai",
     "base_url": "https://openrouter.ai/api/v1", "model": "openai/gpt-4o",
     "note": "一个 Key 访问上百个模型，支持自动回退"},
    {"key": "together", "name": "Together AI", "type": "openai",
     "base_url": "https://api.together.xyz/v1", "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo"},
    {"key": "mistral", "name": "Mistral AI", "type": "openai",
     "base_url": "https://api.mistral.ai/v1", "model": "mistral-large-latest"},
    {"key": "custom", "name": "自定义端点", "type": "openai",
     "base_url": "", "model": "", "note": "任意 OpenAI 兼容 /chat/completions 端点"},
]


# ---------- 存储 ----------
def _file():
    return config.LLM_PROVIDERS_FILE


def _default_providers() -> list[dict[str, Any]]:
    """内置三个默认供应商；ollama 永远可用，云端两个待填 Key。"""
    return [
        {"id": "ollama", "name": "本地 Ollama", "type": "openai",
         "base_url": config.OLLAMA_BASE_URL, "api_key": "", "model": config.OLLAMA_MODEL,
         "thinking": True, "local": True, "builtin": True, "enabled": True},
        {"id": "deepseek", "name": "DeepSeek 深度求索", "type": "openai",
         "base_url": config.DEEPSEEK_BASE_URL, "api_key": config.DEEPSEEK_API_KEY,
         "model": config.DEEPSEEK_MODEL, "local": False, "builtin": True, "enabled": True},
        {"id": "anthropic", "name": "Anthropic 兼容端点", "type": "anthropic",
         "base_url": config.ANTHROPIC_BASE_URL, "api_key": config.ANTHROPIC_AUTH_TOKEN,
         "model": config.ANTHROPIC_MODEL or config.DEFAULT_ANTHROPIC_MODEL,
         "local": False, "builtin": True, "enabled": True},
    ]


def _read() -> dict:
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _write(data: dict) -> None:
    _file().parent.mkdir(parents=True, exist_ok=True)
    _file().write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _normalize(p: dict) -> dict:
    """补齐字段、清洗空白，保证下游拿到的结构一致。"""
    out = {
        "id": str(p.get("id") or "").strip(),
        "name": str(p.get("name") or "").strip(),
        "type": str(p.get("type") or "openai").strip().lower(),
        "base_url": str(p.get("base_url") or "").strip(),
        "api_key": str(p.get("api_key") or "").strip(),
        "model": str(p.get("model") or "").strip(),
        "thinking": bool(p.get("thinking")),
        "local": bool(p.get("local")),
        "builtin": bool(p.get("builtin")),
        "enabled": p.get("enabled", True) is not False,
        "timeout": int(p.get("timeout") or 0) or 300,
    }
    if out["type"] not in ("openai", "anthropic"):
        out["type"] = "openai"
    return out


def _migrate_legacy(cfg: dict) -> bool:
    """把旧版 .deepseek_api_key / .llm_anthropic.json 迁进新的供应商配置。"""
    changed = False
    by_id = {p["id"]: p for p in cfg.get("providers", [])}

    ds = by_id.get("deepseek")
    if ds and not ds.get("api_key"):
        try:
            key = config.DEEPSEEK_KEY_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            key = ""
        if not key:
            key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        if key:
            ds["api_key"] = key
            changed = True

    an = by_id.get("anthropic")
    if an and not (an.get("api_key") and an.get("base_url")):
        try:
            old = json.loads(config.LLM_ANTHROPIC_FILE.read_text(encoding="utf-8"))
        except Exception:
            old = {}
        if isinstance(old, dict):
            if not an.get("base_url") and old.get("base_url"):
                an["base_url"] = str(old["base_url"]).strip()
                changed = True
            if not an.get("api_key") and old.get("api_key"):
                an["api_key"] = str(old["api_key"]).strip()
                changed = True
            if not an.get("model") and old.get("model"):
                an["model"] = str(old["model"]).strip()
                changed = True
    return changed


# 进程内缓存：避免每次请求都读盘。按文件 mtime 失效，
# 这样外部进程（编辑器、测试脚本、第二实例）改过配置后，服务下一次读取能拿到最新值，
# 不会被自己的陈旧缓存覆盖。
_cache: dict | None = None
_cache_mtime: float = 0.0


def _file_mtime() -> float:
    try:
        return _file().stat().st_mtime
    except OSError:
        return 0.0


def cfg() -> dict:
    """读取完整配置（带迁移与默认值兜底）。文件被外部改动时自动重载。"""
    global _cache, _cache_mtime
    mtime = _file_mtime()
    if _cache is not None and mtime == _cache_mtime:
        return _cache

    data = _read()
    providers = [_normalize(p) for p in data.get("providers", []) if isinstance(p, dict)]
    # 内置三个必须存在（老用户删了也会补回来）
    have = {p["id"]: p for p in providers}
    for d in _default_providers():
        if d["id"] not in have:
            providers.append(_normalize(d))
            have[d["id"]] = providers[-1]
        else:
            have[d["id"]]["builtin"] = True

    cfg_data = {
        "version": STORE_VERSION,
        "providers": providers,
        "current": str(data.get("current") or "").strip(),
        "auto_route": data.get("auto_route", True),           # 漏洞类任务自动路由云端
        "auto_route_id": str(data.get("auto_route_id") or "deepseek").strip() or "deepseek",
    }
    if _migrate_legacy(cfg_data):
        _write(cfg_data)

    if not any(p["id"] == cfg_data["current"] and p["enabled"] for p in providers):
        cfg_data["current"] = "ollama"
    _cache = cfg_data
    _cache_mtime = _file_mtime()
    return _cache


def invalidate() -> None:
    """外部写盘后调用，强制下次重新读盘。"""
    global _cache
    _cache = None


def save(cfg_data: dict) -> None:
    global _cache, _cache_mtime
    cfg_data["version"] = STORE_VERSION
    _write(cfg_data)
    _cache = cfg_data
    _cache_mtime = _file_mtime()


def mask(key: str) -> str:
    key = (key or "").strip()
    if not key:
        return ""
    return key[:4] + "…" + key[-4:] if len(key) > 8 else "****"


# ---------- 查询 ----------
def list_providers() -> list[dict]:
    """返回给前端的供应商列表（密钥打码）。"""
    c = cfg()
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "type": p["type"],
            "base_url": p["base_url"],
            "model": p["model"],
            "local": p["local"],
            "builtin": p["builtin"],
            "enabled": p["enabled"],
            "thinking": p["thinking"],
            "timeout": p["timeout"],
            "configured": bool(p["base_url"] and p["model"]) and (p["local"] or bool(p["api_key"])),
            "has_key": bool(p["api_key"]),
            "key_masked": mask(p["api_key"]),
        }
        for p in c["providers"]
    ]


def get(pid: str) -> dict | None:
    for p in cfg()["providers"]:
        if p["id"] == pid:
            return p
    return None


def raw(pid: str) -> dict | None:
    """取含密钥的原始配置（仅后端内部使用，不下发前端）。"""
    return get(pid)


def current_id() -> str:
    return cfg()["current"]


def current() -> dict:
    p = get(current_id())
    if p and p["enabled"]:
        return p
    p = get("ollama")
    return p or cfg()["providers"][0]


# ---------- 增删改 ----------
def _slug(name: str) -> str:
    """生成 URL 安全的 ASCII id（中文名会退化成 p-xxxx 短随机串）。"""
    base = re.sub(r"[^a-zA-Z0-9]+", "-", (name or "").strip()).strip("-").lower()
    if not base:
        # 纯中文/符号名称：给一个稳定的短 id，避免把非 ASCII 塞进 URL 路径
        base = "p-" + uuid.uuid4().hex[:6]
    return base[:24]


def _unique_id(base: str) -> str:
    ids = {p["id"] for p in cfg()["providers"]}
    if base not in ids:
        return base
    for i in range(2, 100):
        cand = f"{base}-{i}"
        if cand not in ids:
            return cand
    return f"{base}-{uuid.uuid4().hex[:6]}"


def upsert(data: dict) -> dict:
    """新增或更新供应商。带 id 且已存在=合并更新；无 id=新建。"""
    c = cfg()
    pid = str(data.get("id") or "").strip()
    target = get(pid) if pid else None

    if target is None:
        name = str(data.get("name") or "").strip() or "未命名供应商"
        pid = _unique_id(_slug(name))
        target = _normalize({"id": pid, "name": name})
        c["providers"].append(target)

    for k in ("name", "type", "base_url", "api_key", "model"):
        if k in data and data[k] is not None:
            val = str(data[k]).strip()
            # api_key 语义：空字符串或打码值（含 …）都视为「不修改已有密钥」，
            # 避免用户在设置里编辑其它字段（如改模型名）保存时把 Key 意外清空。
            # 想清空 Key 用「恢复默认」（内置）或删除重建（自定义）。
            if k == "api_key" and (not val or "…" in val):
                continue
            target[k] = val
    for k in ("thinking", "local", "enabled"):
        if k in data and data[k] is not None:
            target[k] = bool(data[k])
    if data.get("timeout"):
        try:
            target["timeout"] = int(data["timeout"])
        except Exception:
            pass
    if target["id"] in BUILTIN_IDS:
        target["builtin"] = True
    # R4 红线：内置 Ollama（qwen3.5:9b）思考模式必须恒开，关闭会退化成纯文本、不再调工具，
    # 这里强制锁定，即使前端传 thinking=False 也被忽略。
    if target["id"] == "ollama":
        target["thinking"] = True
    target["base_url"] = target["base_url"].rstrip("/")
    save(c)
    return target


def delete(pid: str) -> bool:
    """删除供应商。内置三个不可删除（可改配置停用）。"""
    if pid in BUILTIN_IDS:
        return False
    c = cfg()
    before = len(c["providers"])
    c["providers"] = [p for p in c["providers"] if p["id"] != pid]
    if len(c["providers"]) == before:
        return False
    if c["current"] == pid:
        c["current"] = "ollama"
    save(c)
    return True


def reset_builtin(pid: str) -> bool:
    """把内置供应商恢复默认（清空 Key、恢复默认端点）。"""
    d = next((x for x in _default_providers() if x["id"] == pid), None)
    if not d:
        return False
    c = cfg()
    c["providers"] = [_normalize(d) if p["id"] == pid else p for p in c["providers"]]
    save(c)
    return True


def set_current(pid: str) -> dict:
    p = get(pid)
    if not p:
        raise ValueError(f"供应商不存在：{pid}")
    if not p["enabled"]:
        raise ValueError(f"供应商已停用：{p['name']}")
    if not p["local"] and not p["api_key"]:
        raise ValueError(f"未填写 API Key：{p['name']}")
    if not p["base_url"] or not p["model"]:
        raise ValueError(f"未填写 Base URL 或模型名：{p['name']}")
    c = cfg()
    c["current"] = pid
    save(c)
    return p


def set_auto_route(enabled: bool, pid: str = "") -> None:
    c = cfg()
    c["auto_route"] = bool(enabled)
    if pid:
        c["auto_route_id"] = pid
    save(c)


def auto_route_id() -> str:
    c = cfg()
    if not c.get("auto_route", True):
        return ""
    return c.get("auto_route_id", "deepseek")


def presets() -> list[dict]:
    return [dict(p) for p in PRESETS]
