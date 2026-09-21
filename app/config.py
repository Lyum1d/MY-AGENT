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
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "30"))  # 单轮最多执行步数，防止死循环
# think 空转上限：到这一轮把「必须动手」推进上下文，再下一轮仍只推理就结束本轮。
# 目的是不让一个「只想不做」的模型把步数预算全烧在思考上（每轮都是一次 LLM 调用）。
THINK_STREAK_MAX = int(os.getenv("AGENT_THINK_STREAK_MAX", "3"))

# 预算感知：剩余步数 <= 该值时，每轮在上下文里明确提示「即将超支」并要求收敛。
BUDGET_REMIND_AT = int(os.getenv("AGENT_BUDGET_REMIND_AT", "3"))

# 执行模式（消融开关）：react=严格单步，plan=整轮批量执行。
EXECUTION_MODE = os.getenv("AGENT_EXECUTION_MODE", "react").strip().lower()
if EXECUTION_MODE not in ("react", "plan"):
    EXECUTION_MODE = "react"

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
HISTORY_EXCERPT_CHARS = int(os.getenv("HISTORY_EXCERPT_CHARS", "80"))
HISTORY_SUMMARY_CHARS = int(os.getenv("HISTORY_SUMMARY_CHARS", "300"))  # 压缩后每条保留多少字

# ---------- 续聊记忆恢复（SessionManager.adopt） ----------
# 服务重启、或切回某条线索继续聊时，把落库的对话原文还原成「给模型的 messages」。
# 不还原会怎样：会话对象被重建时 messages 一片空白，模型对之前所有轮次零记忆，
# 而前端仍能从 chat_messages 看到完整对话 —— 人和模型看到的历史不一致，
# 用户会以为「它记得」，实际它什么都不记得。
# 只还原对话层（用户原话 + 模型说明/结论）；工具输出不在 chat_messages 里，
# 由 steps 表 / 情报库 / 已证事实库另行注入，这里不重复搬运。
RESTORE_CHAT_MAX = int(os.getenv("AGENT_RESTORE_CHAT_MAX", "24"))        # 最多还原多少条
RESTORE_CHAT_CHARS = int(os.getenv("AGENT_RESTORE_CHAT_CHARS", "1200"))  # 单条截断字符

# ---------- 步骤输出落库裁剪 ----------
# 此前只存尾部（output[-2000:]），导致工具开头的关键结果（命中统计、存活清单首页）
# 永久丢失，而上下文压缩又提示模型「可用 search_history 检索」——提示与事实不符。
# 改为头 + 尾都保留，中间以省略标记连接。
# v031（第三轮 shhxqh 实战）：1500/2000 依然不够 —— 功能码全集、存活清单这类**中段**
# 结果仍落进省略区，模型只能重新向目标发请求回捞（实测 6 次，占全局预算 1/3）。
# 提到 4000/4000：单步落库上限 8KB，steps 表膨胀可控，换取「落库版本≈可用版本」。
STEP_OUTPUT_HEAD = int(os.getenv("AGENT_STEP_OUTPUT_HEAD", "4000"))
STEP_OUTPUT_TAIL = int(os.getenv("AGENT_STEP_OUTPUT_TAIL", "4000"))

# ---------- 历史检索回传（v031） ----------
# 原实现只回 220/300 字符片段，即使落库版本有 8KB 也拿不到中段清单。
# 提高片段长度，让 search_history 真正能替代「重新向目标取数」。
SEARCH_SNIPPET_CHARS = int(os.getenv("AGENT_SEARCH_SNIPPET_CHARS", "800"))

# ---------- 受控脚本接口正文上限与落盘（v031） ----------
# 原实现：text 硬截断 65536，且**无法取回完整正文** —— 脚本只能改用 Range 头再发
# 请求（实测门户页 110762 字节被截掉 40%，导致「首页无外链 JS」的错误判定，多耗
# 2 次目标请求）。现改为：上限提高到 128KB（覆盖常见门户页），仍超限时把**完整
# 正文落盘**并回 saved_text_path，脚本可用 tmpdir() 离线读取，不必再打目标。
PY_EXEC_TEXT_LIMIT = int(os.getenv("AGENT_PY_EXEC_TEXT_LIMIT", "131072"))

# ---------- 记忆注入上限 ----------
# 超过上限的条目会在注入块尾部写明「另有 N 条未展示」，不再是无声截断 ——
# 否则模型既不知道「还有更多记忆它看不见」，也没动机去检索，只会重复收集。
FACT_INJECT_MAX = int(os.getenv("AGENT_FACT_INJECT_MAX", "20"))      # 已证事实库
RECORD_INJECT_MAX = int(os.getenv("AGENT_RECORD_INJECT_MAX", "20"))  # 本线索开局记录
BRANCH_INJECT_MAX = int(os.getenv("AGENT_BRANCH_INJECT_MAX", "8"))   # 同项目其他线索摘要

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

# ---- 出网限速（实现见 app/ratelimit.py）----
TOOL_MIN_INTERVAL = float(os.getenv("TOOL_MIN_INTERVAL", "1.0"))
GLOBAL_MIN_INTERVAL = float(os.getenv("GLOBAL_MIN_INTERVAL", "0.2"))

# ---- 统一流量调度（v023.1，实现见 app/traffic.py）----
# 滑动窗口请求预算：同一 root_domain 在窗口内最多发这么多请求，超出即暂停
# （不是自动提高额度）。默认值取「保守档」——由 zueb.edu.cn 实测事故确定：
# 单脚本连发几十个敏感后缀请求即触发 IP 级封禁且封禁 >20 分钟。
TRAFFIC_WINDOW_SECONDS = int(os.getenv("AGENT_TRAFFIC_WINDOW", "600"))
TRAFFIC_MAX_REQUESTS = int(os.getenv("AGENT_TRAFFIC_MAX_REQUESTS", "30"))
TRAFFIC_BURST = int(os.getenv("AGENT_TRAFFIC_BURST", "5"))
# 并发上限：同一主机 1、同一根域名 1（v023.1 保守档，不可自动提高）
TRAFFIC_HOST_CONCURRENCY = int(os.getenv("AGENT_TRAFFIC_HOST_CONCURRENCY", "1"))
TRAFFIC_ROOT_CONCURRENCY = int(os.getenv("AGENT_TRAFFIC_ROOT_CONCURRENCY", "1"))
# 请求指纹短期复用 TTL（秒）。**默认 0 = 关闭**。
# v023.4 实现了完整复用能力（同指纹在 TTL 内复用已有观察，多分支测同一接口
# 时只有一次真实流量），但回归验证发现：开启会改变「差分/流程」的既有语义
# （连续两次相同请求第二次会命中缓存，稳定性判定失真）——即使复验已用独立
# variant_id + no_cache 规避，仍会掩盖真实的目标行为变化。因此默认关闭、
# 由用户按目标敏感度显式开启（AGENT_TRAFFIC_FP_TTL=120）。
TRAFFIC_FP_TTL = float(os.getenv("AGENT_TRAFFIC_FP_TTL", "0"))
# 测试模式：放预算/并发（跑回归套件用），生产不得开启。status 接口会公开该标志
TRAFFIC_TEST_MODE = os.getenv("AGENT_TRAFFIC_TEST_MODE", "") == "1"
TRAFFIC_TEST_MULTIPLIER = int(os.getenv("AGENT_TRAFFIC_TEST_MULTIPLIER", "50"))

# ---- py_exec 流量治理（v023.2）----
# 脚本网络访问策略：
#   safe（默认）——检测到「网络库 + 循环」的脚本直接拒绝，要求改用受控接口；
#   warn         ——只警告不拒绝（过渡期）；
#   legacy       ——完全关闭检测与受控通道（仅为排障保留，不推荐）。
PY_EXEC_NETWORK_POLICY = os.getenv("AGENT_PY_EXEC_NETWORK_POLICY", "safe").strip().lower()
# 单个脚本经受控通道的最大请求数（超出后 safe_http_request 返回预算错误，
# 目标暂停则宿主直接终止脚本进程树）
PY_EXEC_MAX_REQUESTS = int(os.getenv("AGENT_PY_EXEC_MAX_REQUESTS", "20"))
PY_EXEC_REQUEST_TIMEOUT = float(os.getenv("AGENT_PY_EXEC_REQUEST_TIMEOUT", "25"))

# ---- 扫描器速率治理（v023.2）----
# 0（默认）= 未声明内部速率能力的工具在启动前显示「流量不可观测」警告但仍可运行；
# 1 = 严格模式，未声明者直接拒绝自动运行（v023 计划 MUST 项，切到严格需用户确认，
#     因为会一次性禁用大量可用工具——过渡期用警告模式，声明补齐后再切）
SCANNER_REQUIRE_DECLARATION = os.getenv("AGENT_SCANNER_REQUIRE_DECLARATION", "0") == "1"
SCANNER_DEFAULT_RATE = int(os.getenv("AGENT_SCANNER_DEFAULT_RATE", "5"))       # 每秒请求
SCANNER_DEFAULT_THREADS = int(os.getenv("AGENT_SCANNER_DEFAULT_THREADS", "2"))  # 并发线程
# v023.4 拆分背压：目标剩余预算低于该值时拒绝 split_task 并发拆分
SUBTASK_MIN_BUDGET = int(os.getenv("AGENT_SUBTASK_MIN_BUDGET", "6"))

# v023.7：项目「已证实事实」自动注入（每轮提醒里带上，供后续线索复用）。
# 背景（shhxqh 第二轮实战）：第一轮的已证实事实（后端入口、免权限控制器…）
# 只能靠人工写进任务书复述给模型，否则模型会重新发现甚至重复验证。
INJECT_FACTS = os.getenv("AGENT_INJECT_FACTS", "1") == "1"
INJECT_FACTS_MAX = int(os.getenv("AGENT_INJECT_FACTS_MAX", "10"))       # 最多注入条数
INJECT_FACTS_CHARS = int(os.getenv("AGENT_INJECT_FACTS_CHARS", "240"))  # 单条截断

# ---- 远程访问（run.py 拒绝启动 + app/main.py 令牌中间件）----
ALLOW_REMOTE = os.getenv("ALLOW_REMOTE", "0") == "1"
ACCESS_TOKEN = os.getenv("SRC_AGENT_TOKEN", "")


# ---------- Python 代码执行通道（py_exec，Agent 直出代码） ----------
PY_EXEC_TIMEOUT = int(os.getenv("PY_EXEC_TIMEOUT", "90"))    # 单段代码上限（秒），超时中断
PY_EXEC_MAX_CHARS = 6000    # 单段代码最大字符数
PY_EXEC_DIR = DATA_DIR / "scripts" / "exec"  # 代码留档目录（按目标分子目录）

# ---- py_exec 沙箱（v010 P0-1：进程级隔离）----
# 背景：py_exec 在宿主解释器里执行模型直出的任意 Python，此前 env=os.environ
#   完整继承宿主环境——DeepSeek/FOFA/代理凭据等全部对子进程可见，且 proc.kill()
#   只杀直接子进程，脚本再起的子进程会残留。
# 沙箱分级实现（容器/受控代理属架构级方案，另行规划）：
#   ① 环境变量白名单：子进程只继承下方内置白名单 + 用户扩展文件里的变量；
#   ② 临时工作目录：执行 cwd 用一次性临时目录，结束后清理（留档仍在 PY_EXEC_DIR）；
#   ③ Windows Job Object：KILL_ON_JOB_CLOSE —— 超时/异常关闭句柄即终止整棵进程树。
# PY_EXEC_ENV_ALLOW_JSON：用户可扩展的「允许继承」变量名清单（JSON 数组，可选）。
#   为什么不做成 data/*.json 强制项：允许哪些变量是本机个性化配置（如某些脚本
#   需要 HTTP_PROXY 走 Burp），做成「缺省内置 + 用户可选扩展」最省事且不影响他人。
PY_EXEC_ENV_ALLOW_JSON = DATA_DIR / "pyexec_env_allow.json"
PY_EXEC_TMP_ROOT = DATA_DIR / "scripts" / "tmp"   # 一次性工作目录的父目录（自动创建）

# ---------- 云端外发控制（v010 P0-4） ----------
# 背景：默认路由是「云端优先」（见 _pick_default 注释），工具输出里的 Cookie、
#   Authorization、内网路径、凭据会原样进入 LLM 请求。漏洞类任务几乎必然触碰
#   这些内容，等于把目标站点的会话凭据交给云端供应商。
# 模式（环境变量 AGENT_CLOUD_EGRESS，默认 redact）：
#   local_only —— 一切请求只允许本地供应商；选中云端时直接拒绝并提示切换本地。
#   redact     —— 允许上云，但发送前对 messages 做脱敏（Cookie/Bearer/JWT/
#                 password= 形态键值对/邮箱/手机号），并记录命中摘要到日志。
#   allow      —— 不做任何处理（仅在你明确知道并接受外发风险时使用）。
# 注意：脱敏作用于**发往云端的那份副本**，session.messages 原文不受影响，
#   本地供应商（local=True）不经过脱敏（数据不出本机）。
CLOUD_EGRESS_MODE = os.getenv("AGENT_CLOUD_EGRESS", "redact").strip().lower()

# ---------- LLM 重试与故障转移（v011 P1-6） ----------
# 背景：本机 DNS 抖动 / 云端限流（429）/ 网关临时故障（502/503/504）会让
#   一整轮任务直接报废——实际只是几十秒的网络问题。对可重试错误做指数退避，
#   重试耗尽后自动切到下一个可用供应商（切换原因记录到步骤流与日志）。
# LLM_RETRY_MAX：额外重试次数（0=不重试）；退避 = LLM_RETRY_BASE_DELAY * 2^attempt。
# LLM_FAILOVER_MAX：单次任务内最多自动切换几次供应商（防雪崩式连环切换）。
# RUN_TIME_BUDGET：单次任务墙钟时间上限（秒，0=不限）。token 预算管钱、
#   步数管轮次，都不管时间——超时按中断处理，半程成果照常沉淀。
LLM_RETRY_MAX = int(os.getenv("AGENT_LLM_RETRY_MAX", "3"))
LLM_RETRY_BASE_DELAY = float(os.getenv("AGENT_LLM_RETRY_BASE_DELAY", "1.0"))
LLM_FAILOVER_MAX = int(os.getenv("AGENT_LLM_FAILOVER_MAX", "2"))
RUN_TIME_BUDGET = int(os.getenv("AGENT_RUN_TIME_BUDGET", "1800"))
