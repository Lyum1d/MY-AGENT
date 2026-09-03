# -*- coding: utf-8 -*-
"""模型层：本地 Ollama 为主，云端 DeepSeek 为备用通道。

重要结论（实测）：
  qwen3.5:9b 在关闭思考模式时会退化成纯文本输出、不再产生 tool_calls。
  因此 OLLAMA_THINKING 必须保持 True，不要为了省时间关掉它。
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx

from . import config


class LLMBackend(ABC):
    name: str = "base"

    @abstractmethod
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """返回归一化结果：{"tool_calls": [...], "content": "..."}"""
        ...

    def available(self) -> bool:
        return True


class OllamaBackend(LLMBackend):
    """本地 Ollama，OpenAI 兼容接口。"""

    name = "ollama"

    def __init__(self) -> None:
        self.base_url = config.OLLAMA_BASE_URL
        self.model = config.OLLAMA_MODEL
        self.timeout = 300.0

    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        # 思考模式必须开启：关掉后模型不再调用工具（实测结论）
        if config.OLLAMA_THINKING:
            payload["thinking"] = True

        async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        msg = data.get("choices", [{}])[0].get("message", {})
        return {
            "tool_calls": msg.get("tool_calls") or [],
            "content": msg.get("content") or "",
            "backend": self.name,
        }

    async def health(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                r = await client.get(self.base_url.replace("/v1", "/api/tags"))
                models = [m.get("name") for m in r.json().get("models", [])]
            return {"ok": True, "models": models, "model": self.model,
                    "ready": self.model in models}
        except Exception as e:
            return {"ok": False, "error": str(e), "model": self.model, "ready": False}


class DeepSeekBackend(LLMBackend):
    """云端备用通道。未配置 API Key 时自动禁用，不影响本地运行。"""

    name = "deepseek"

    def __init__(self) -> None:
        self.api_key = config.DEEPSEEK_API_KEY
        self.base_url = config.DEEPSEEK_BASE_URL
        self.model = config.DEEPSEEK_MODEL

    def available(self) -> bool:
        return bool(self.api_key)

    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        if not self.available():
            raise RuntimeError("DeepSeek 未配置 API Key，请设置环境变量 DEEPSEEK_API_KEY")

        payload: dict[str, Any] = {"model": self.model, "messages": messages}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=180.0, trust_env=False) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            data = resp.json()

        msg = data.get("choices", [{}])[0].get("message", {})
        return {
            "tool_calls": msg.get("tool_calls") or [],
            "content": msg.get("content") or "",
            "backend": self.name,
        }

    async def health(self) -> dict:
        # 云端不做真实探测（避免白耗 API 配额），只看 Key 是否已配置
        return {
            "ok": self.available(),
            "model": self.model,
            "ready": self.available(),
            "reason": None if self.available() else "未配置 DEEPSEEK_API_KEY",
        }


_backends: dict[str, LLMBackend] = {}

# ---------- 运行时后端选择 ----------
# 默认取 config.DEFAULT_BACKEND；可通过 /api/models 在前端切换，并持久化到 data/runtime.json，
# 服务重启后仍保持用户上次的选择。
_RUNTIME_FILE = config.DATA_DIR / "runtime.json"
_current_backend: str | None = None


def _load_saved_backend() -> str | None:
    try:
        return json.loads(_RUNTIME_FILE.read_text(encoding="utf-8")).get("backend")
    except Exception:
        return None


def _save_backend(name: str) -> None:
    try:
        _RUNTIME_FILE.write_text(
            json.dumps({"backend": name}, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass


def get_backend(name: str | None = None) -> LLMBackend:
    """取后端实例。不传 name 时返回当前运行时选中的后端。"""
    global _current_backend
    if name is None:
        if _current_backend is None:
            saved = _load_saved_backend()
            _current_backend = saved if saved in ("ollama", "deepseek") else config.DEFAULT_BACKEND
            # 持久化的选择指向未配置 Key 的云端时，回退到本地，避免启动即不可用
            if _current_backend == "deepseek" and not config.DEEPSEEK_API_KEY:
                _current_backend = "ollama"
        name = _current_backend
    if name not in _backends:
        _backends[name] = OllamaBackend() if name == "ollama" else DeepSeekBackend()
    return _backends[name]


def current_backend_name() -> str:
    return get_backend().name


def set_backend(name: str) -> LLMBackend:
    """切换运行时后端并持久化。校验失败抛 ValueError / RuntimeError。"""
    global _current_backend
    if name not in ("ollama", "deepseek"):
        raise ValueError(f"未知后端：{name}（可选 ollama / deepseek）")
    if name == "deepseek" and not config.DEEPSEEK_API_KEY:
        raise RuntimeError("DeepSeek 未配置 API Key，请先设置环境变量 DEEPSEEK_API_KEY 再切换")
    _current_backend = name
    _save_backend(name)
    return get_backend(name)


def parse_tool_arguments(raw: str) -> dict:
    """容错解析模型返回的参数（小模型偶尔吐出不合法 JSON）。"""
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {"target": raw.strip(), "args": ""}
