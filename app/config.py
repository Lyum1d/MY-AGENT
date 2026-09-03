# -*- coding: utf-8 -*-
"""全局配置。所有路径与模型参数集中在此处。"""
from __future__ import annotations

import os
from pathlib import Path

# ---------- 目录 ----------
APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = APP_DIR / "data"
WEB_DIR = APP_DIR / "web"
DATA_DIR.mkdir(exist_ok=True, parents=True)

# 天狐渗透工具箱根目录。
# 团队协作时每位成员工具箱存放位置不同，优先读环境变量 TOOLBOX_ROOT；
# 未设置时回退到本机默认路径（仅作个人兜底，不要依赖它跨机生效）。
TOOLBOX_ROOT = Path(
    os.getenv(
        "TOOLBOX_ROOT",
        r"E:\BaiduNetdiskDownload\天狐渗透工具箱-社区版V3.0+4.0更新升级包\天狐渗透工具箱-社区版V3.0",
    )
)

# ---------- 工具箱内置运行时 ----------
TOOLBOX_PYTHON = TOOLBOX_ROOT / "python3" / "python.exe"
JAVA8_BIN = TOOLBOX_ROOT / "Java_path" / "Java_8_win" / "bin"
JAVA11_BIN = TOOLBOX_ROOT / "Java_path" / "Java_11_win" / "bin"

# ---------- 模型 ----------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
# 探测结论：qwen3.5:9b 关闭思考模式会退化成纯文本、不再调用工具，因此思考模式必须保持开启
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
OLLAMA_THINKING = True

# 云端备用通道（未配置 API Key 时自动禁用，不影响本地运行）
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

DEFAULT_BACKEND = "ollama"  # ollama | deepseek

# ---------- 风险分级 ----------
# L0 只读/本地分析 -> 自动执行
# L1 主动探测扫描 -> 自动执行（全程留痕）
# L2 漏洞验证利用 -> 需确认
# L3 权限/横向/接管 -> 需确认 + 二次确认
RISK_LEVELS = {
    "L0": {"name": "只读 / 本地分析", "policy": "auto", "auto": True, "double_confirm": False},
    "L1": {"name": "主动探测扫描", "policy": "auto", "auto": True, "double_confirm": False},
    "L2": {"name": "漏洞验证与利用", "policy": "confirm", "auto": False, "double_confirm": False},
    "L3": {"name": "权限 / 横向 / 接管", "policy": "confirm", "auto": False, "double_confirm": True},
}
DEFAULT_RISK_LEVEL = "L2"  # 未定级工具一律按 L2 处理，宁严不松

# 可编排的工具类型（能取回 stdout）；其余为图形界面，只能启动
SCRIPTABLE_TYPES = {"命令行", "Python", "JAVA8", "JAVA11", "批处理"}

# ---------- Agent ----------
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "12"))  # 单轮最多执行步数，防止死循环
TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "600"))  # 单工具总时长上限（秒）
TOOL_IDLE_TIMEOUT = int(os.getenv("TOOL_IDLE_TIMEOUT", "120"))  # 无输出多久判定卡死（秒）
MAX_OUTPUT_LINES = int(os.getenv("MAX_OUTPUT_LINES", "2000"))  # 单工具最多回传多少行
MAX_OUTPUT_CHARS = 8000  # 回喂给模型的最大字符数，超出截断防止撑爆上下文

# ---------- 服务 ----------
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8770"))

# ---------- 模型路由 ----------
# 漏洞验证类任务自动路由到云端模型（要求 DEEPSEEK_API_KEY 已配置，否则自动回退本地）
AUTO_ROUTE_VULN = os.getenv("AUTO_ROUTE_VULN", "1") == "1"
VULN_KEYWORDS = (
    "漏洞", "验证", "越权", "未授权", "注入", "payload", "exp", "poc",
    "弱口令", "爆破", "绕过", "rce", "sqli", "xss", "ssrf",
)

# ---------- HTTP 重放器 ----------
REPLAY_MIN_INTERVAL = float(os.getenv("REPLAY_MIN_INTERVAL", "0.6"))  # 全局请求最小间隔（秒）
REPLAY_MAX_BODY = 4000     # 回传给模型的最大响应体长度（字符）
SCOPE_FILE = DATA_DIR / "scope.json"  # 授权域名白名单
