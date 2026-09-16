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

# 通用 Anthropic 兼容通道（claude code 系 / GLM 等任意 Anthropic 兼容端点）。
# 优先从个人配置文件（%USERPROFILE%\.llm_anthropic.json，由控制台「设置」写入）读取，
# 环境变量仅作兜底 seed，命名对齐 tinyctfer：ANTHROPIC_BASE_URL / AUTH_TOKEN / MODEL。
ANTHROPIC_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "")
ANTHROPIC_AUTH_TOKEN = os.getenv("ANTHROPIC_AUTH_TOKEN", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "")
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"  # 端点若不支持可在设置里改

# ---------- 个人密钥目录（%USERPROFILE%，不进项目仓库） ----------
USER_HOME = Path(os.environ.get("USERPROFILE", str(Path.home())))
DEEPSEEK_KEY_FILE = USER_HOME / ".deepseek_api_key"      # 一行 Key（旧版，已被 providers 迁移接管）
LLM_ANTHROPIC_FILE = USER_HOME / ".llm_anthropic.json"   # {"base_url","api_key","model"}（旧版，同上）
LLM_PROVIDERS_FILE = USER_HOME / ".src_agent_llm.json"   # 通用供应商配置（现行）

# ---------- 默认供应商（云端优先）----------
# 变更（用户 2026-09-15）：此前一律回退到本地 ollama（"本地优先"），
# 现在改为「保留本地模型接口可用，但默认优先云端」。解析顺序见 providers._pick_default：
#   1. 本项指定的供应商（若已启用且配置完整）
#   2. 其它任何「已启用 + 配置完整 + 非本地」的供应商
#   3. 本地 ollama（仅在前两者都不可用时兜底）
# 留空则跳过第 1 步，完全按 2 → 3 自动挑选。
PREFERRED_PROVIDER = os.getenv("AGENT_PREFERRED_PROVIDER", "deepseek")
DEFAULT_BACKEND = PREFERRED_PROVIDER  # 兼容旧名（旧语义即"默认后端"）

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
# L2/L3 等用户确认的等待上限（秒），超时按「拒绝」处理
CONFIRM_TIMEOUT = int(os.getenv("AGENT_CONFIRM_TIMEOUT", "600"))
# 单次决策回传给模型的工具 schema 上限（工具过多会拖慢本地小模型）
MAX_TOOL_SCHEMAS = int(os.getenv("AGENT_MAX_TOOL_SCHEMAS", "40"))
# 项目情报库每类条目上限（注入上下文前会截断）
INTEL_CAP = int(os.getenv("INTEL_CAP", "150"))

# ---- 上下文压缩（机械式，不调用模型）----
# 借鉴 LuaN1ao 的「摘要压缩」思路，但刻意改用确定性裁剪：本地小模型写摘要本身会产生
# 幻觉，等于用一个不可靠环节去修另一个不可靠环节。只压 role=tool 消息的正文，绝不删消息。
HISTORY_COMPRESS_AFTER_MESSAGES = int(os.getenv("HISTORY_COMPRESS_AFTER_MESSAGES", "24"))
HISTORY_KEEP_RECENT = int(os.getenv("HISTORY_KEEP_RECENT", "12"))   # 最近 N 条保持原文
HISTORY_SUMMARY_CHARS = int(os.getenv("HISTORY_SUMMARY_CHARS", "300"))  # 压缩后每条保留多少字

# ---- 失败止损分两档（借鉴 LuaN1ao EXECUTOR_FAILURE_THRESHOLD 的语义）----
# 连续失败到 SWITCH 档 → 要求模型「换策略」，而不是直接停；到 STOP 档才停止。
FAILURE_SWITCH_THRESHOLD = int(os.getenv("AGENT_FAILURE_SWITCH", "3"))
FAILURE_STOP_THRESHOLD = int(os.getenv("AGENT_FAILURE_STOP", "6"))

# ---- 单次任务 token 预算（成本熔断）----
# 本地 Ollama 不返回 usage，因此不会触发；云端供应商超限即停止，避免无声烧钱。
RUN_TOKEN_BUDGET = int(os.getenv("AGENT_RUN_TOKEN_BUDGET", "800000"))

# ---- 任务分片并行（split_task：拆小份 → 并发跑 → 合并）----
# 子任务并发上限。**不要调太高**：并行意味着对目标同时发起更多请求，
# 平台规则禁止影响业务可用性的高并发；同时也会推高云端 token 消耗。
SUBTASK_MAX_CONCURRENCY = int(os.getenv("SUBTASK_MAX_CONCURRENCY", "3"))
# 单个子任务的步数预算（比主任务小，避免一个子任务吃光预算）
SUBTASK_MAX_STEPS = int(os.getenv("SUBTASK_MAX_STEPS", "8"))
# 单次最多拆几个子任务
SUBTASK_MAX_COUNT = int(os.getenv("SUBTASK_MAX_COUNT", "4"))
# 合并回主线索时，最多带上多少条子任务期间新增的已证事实
SUBTASK_MERGE_FACTS = int(os.getenv("SUBTASK_MERGE_FACTS", "20"))

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

# 命令行工具执行前是否强制校验授权白名单（app/executor.py）。
# 背景：白名单此前只在 HTTP 重放器（replayer）生效，命令行工具（executor）
#   仅校验 target 格式、不校验目标是否在授权范围内，存在越权扫描缺口。
# 取值：1=强制（默认，未授权目标直接拒绝执行，与重放器行为对齐）
#       0=关闭（仅日志告警）——仅供临时排查，不建议长期关闭。
# 注意：白名单为空时一律拒绝执行（含未配置 scope.json 的情况），
#   宁可让工具跑不起来，也不能静默放行未授权目标。
ENFORCE_SCOPE = os.getenv("ENFORCE_SCOPE", "1") == "1"

# ---------- Python 代码执行通道（py_exec，Agent 直出代码） ----------
PY_EXEC_TIMEOUT = int(os.getenv("PY_EXEC_TIMEOUT", "90"))    # 单段代码上限（秒），超时中断
PY_EXEC_MAX_CHARS = 6000    # 单段代码最大字符数
PY_EXEC_DIR = DATA_DIR / "scripts" / "exec"  # 代码留档目录（按目标分子目录）
