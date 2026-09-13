# -*- coding: utf-8 -*-
"""Agent 编排层：ReAct 单步决策循环。

为什么是「单步」而不是「一次规划全部步骤」：
  实测 qwen3.5:9b 在被要求一次规划多步时，只输出文字方案、不产生 tool_calls。
  因此这里每次只让模型决定「下一步用哪个工具」，执行完把结果回喂，再问下一步。
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import config, store
from . import kb, fofa
from . import pyexec
from . import replayer
from .executor import executor
from .intel import format_intel, update_intel_from_steps
from .llm import auto_route_candidate, get_backend, parse_tool_arguments
from .registry import registry

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """你是一个渗透测试编排助手，服务于 SRC（安全应急响应中心）漏洞挖掘场景。

工作原则：
1. 一步一动：每次只选择「一个」最合适的工具执行，不要一次列出全部计划。
2. 先看结果再决定：收到工具输出后，基于真实结果判断下一步，不要臆测。
3. 只使用下面工具清单中真实存在的工具，绝对不要编造工具名。
4. 目标是企业名称时，先用「可用清单里的」资产收集工具扩展资产（如 app_info 按名称收集 APP/资产；
   ensan 已禁用、不要调用），拿到域名后再做子域名(oneforall)、指纹(ehole)、漏洞检测。
   目标类型与起步工具：企业名→app_info；域名/IP/URL→先 httpx 存活探测，再 ehole 指纹。
5. 工具失败/超时 = 「调整并重试」信号：放大超时、换参数或拆小步骤再试，不要放弃任务，
   也不要原样重复刚失败过的同一条命令。
6. 每一步都要简要说明你的判断依据。
7. 每次回复必须二选一：要么调用一个工具，要么给出最终结论。
   绝不允许只描述"下一步打算做什么"而不实际调用工具。
8. 事实纪律：只能基于真实工具输出下结论。禁止编造漏洞、凭据、flag、版本号或"疑似成功"。
   区分「已证实的事实」与「待验证的猜测」，报告中结论只先给证据确凿的，再扩展可疑点。

对话树工作流（多条线索并行推进）：
9. 发现值得单独深挖的可疑点（注入点/弱口令/未授权接口/可疑目录等）时，调用 propose_branch
   向用户建议开辟新线索，由用户确认；新线索会带上相关记录独立推进，避免当前对话信息过载。
10. 需要其他线索里已查到的信息时，调用 search_history 按关键词检索（子域名、路径、端口、
    工具结果等），检索到的内容是已证实的工具输出，可直接引用；检索不到就继续用工具查证。

知识库与测绘（kb / fofa）：
11. 进站先调用 kb_read 读「打穿短表」（手法索引，当开场几枪），再按目标特征用 kb_search 找
    对应打法篇目并用 kb_read 读全文后动手——禁止凭空编测试手法，禁止每站通读全部篇目。
    特征对照速查：有用户体系→idor-test+authbypass-test；有搜索/筛选→injection-test；有上传→
    file-upload-test；有内容请求/预览→ssrf-test；有评论/富文本→xss-test；有支付/优惠券→
    logic-test+race-condition-test；接口字段多→info-leak-test；OAuth/JWT→oauth-jwt-test；
    GraphQL→graphql-test；网关/微服务→api-gateway-test；前后端分离→http-smuggling-test；
    WAF 拦截→waf-bypass（有差分面的参数被拦才读）；路径/下载→path-traversal-lfi-test；
    XML 解析→xxe-test；Java 反序列化/中间件→deserialization-test+jndi-injection-test；
    JS 加密参数→js-reverse-guide；公开 Redis/rsync/FPM/AJP/h2-console→info-leak-test。
12. 安全红线（知识库打法之上，不可违反）：越权验证优先读/列表差分（GET）；写越权按
    「先添加→删自己刚加的」顺序，禁止改/删他人已有对象，禁止扣钱/清库存/批量/真资损；
    用户提供登录态后严禁登出/注销/吊销会话；CORS 永不挖（勿读 cors-test.md）；禁止开场对
    每个 path 喂引号当注入检测，注入打在有差分面的参数上；nuclei/afrog 只当已知 CVE 辅助，
    禁止全量模板当本站矩阵。
13. FOFA 测绘（fofa_search）按「一种子闭环」：一个种子（业务名/根域/全资子公司）查完 →
    去重去废存活确认 → 剩余活面挖完 → 才查下一个种子；禁止多种子一次搜完再挖、禁止拿
    测绘充数代替实际挖掘。查到的每个活面都要真实探测。
14. 写正式漏洞报告前先 kb_read 读 vuln-report-format（报告取舍闸门：认钥闸/匿名闸/不写清单，
    低危信息类默认不单独成篇；最终落库仍按本项目补天格式）。

Web 站点渗透 SOP（不可跳步，先手工后工具）：
① 打开页面看结构 → ② 查源码/JS/注释/接口，收集泄露信息（凭据、API、内网路径）→
③ 逐个测正常功能（登录/搜索/上传）并留意每步请求 → ④ 确认无隐藏逻辑后才跑自动化
工具（目录/漏洞扫描）→ ⑤ 工具无果时从「功能与逻辑」视角推断漏洞：IDOR/越权/认证绕过/
SSTI/文件上传/命令注入/SSRF/XXE/竞态/路径穿越等。发现任何凭据或漏洞先记录存证，再继续。

可用工具（别名 = 工具名 | 分类 | 风险等级 | 说明）：
{tool_list}

风险等级含义：L0 只读、L1 主动扫描、L2 漏洞利用、L3 权限与横向移动。
L2/L3 工具需要用户授权确认才会执行，你可以正常选择它们。
"""


# 目标参数中出现这些特征，说明模型把说明文字当成了目标
_BAD_TARGET_PATTERNS = ("请提供", "请用户", "请确认", "请输入", "未知", "待定", "？", "?", "示例")

# 域名提取时要排除的"假 TLD"（其实是文件扩展名）
_FAKE_TLDS = {
    "json", "exe", "jar", "py", "txt", "log", "md", "bat", "vbs", "vbe",
    "yaml", "yml", "ini", "csv", "xlsx", "xls", "dll", "sys", "cfg", "conf",
}


def extract_target(text: str) -> str:
    """从用户任务描述中提取目标（URL / IP / 域名）。

    本地小模型在工具执行失败后常"忘记"目标并反问用户，
    因此这里主动提取一次，在每轮决策时重申。
    """
    if not text:
        return ""

    m = re.search(r"https?://[^\s，。；）)\"'<>]+", text)
    if m:
        return m.group(0).rstrip("，。；）)")

    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", text)
    if m:
        return m.group(0)

    for m in re.finditer(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", text):
        cand = m.group(0)
        tld = cand.rsplit(".", 1)[-1].lower()
        if tld in _FAKE_TLDS:
            continue
        return cand
    return ""


def _is_host_like(target: str) -> bool:
    """判断目标是否像 URL / IP / 域名（而非企业名等自由文本）。

    复用 extract_target 的域名/假 TLD 规则，保证与「从消息提取目标」口径一致：
    「test.json」这类文件扩展名会被判为 False，不会被误当域名。
    """
    t = (target or "").strip()
    if not t:
        return False
    return extract_target(t) == t


def validate_target(target: str) -> str | None:
    """校验目标参数。返回 None 表示合法，否则返回原因。

    本地小模型常见问题：把「请用户提供目标域名或IP」这类说明文字当作 target 传进命令行。
    """
    if not target:
        return "目标为空"
    if len(target) > 120:
        return f"目标过长（{len(target)} 字符）"
    if target.count(" ") >= 2:
        return "目标包含多个空格，疑似自然语言句子"
    if any(p in target for p in _BAD_TARGET_PATTERNS):
        return f"目标包含说明性文字「{target[:30]}」"
    return None


# ---------- markdown 代码块兜底解析 ----------
# 背景：qwen3.5:9b 有时把工具调用写成 ```bash 代码块而不产生真正的 tool_calls，
# 或产生 name="tool_call" 的畸形调用（被拦截报「不存在的工具」）。
# 这里从输出文本里做文本级恢复，能救回一轮决策，避免空转催促。

_CODE_FENCE_RE = re.compile(r"```[a-zA-Z]*[ \t]*\r?\n(.*?)```", re.S)
_TARGET_FLAGS = {"-u", "--url", "-t", "--target"}


def _parse_tool_from_markdown(content: str) -> dict | None:
    """从模型输出的 markdown 代码块里恢复工具调用。

    支持 ```bash / ```json 两种形式；第一个 token 必须能解析为真实工具，
    否则返回 None（防止把普通说明性代码块误当成调用）。
    返回 {"name": alias, "arguments": {"target": ..., "args": ...}}。
    target/args 交给 build_command 管线清洗（剥重复旗标、剥非法 flag、剥引号）。
    """
    if not content or "```" not in content:
        return None
    for m in _CODE_FENCE_RE.finditer(content):
        block = m.group(1).strip()
        if not block:
            continue

        # --- json 形式：{"name": ..., "arguments": ...} 或 {"function": {...}} ---
        if block.lstrip().startswith("{"):
            try:
                data = json.loads(block)
                fn = data.get("function") or data
                name = fn.get("name") or fn.get("tool")
                if name:
                    tool, _ = registry.resolve(str(name))
                    if tool is not None:
                        args = fn.get("arguments") or fn.get("args") or {}
                        if isinstance(args, str):
                            args = parse_tool_arguments(args)
                        return {"name": tool.alias, "arguments": args if isinstance(args, dict) else {}}
            except Exception:
                pass
            continue

        # --- bash / shell 形式：第一个 token 视为工具名 ---
        tokens = [t for t in block.split() if not t.startswith("#")]
        # 去掉 shell 提示符（"$ oneforall ..." / "$ domain.com ..."）
        while tokens and tokens[0] in ("$", "#"):
            tokens = tokens[1:]
        if not tokens:
            continue
        name = tokens[0].lstrip("$").strip()
        if not name or name.startswith("-"):
            continue
        tool, _ = registry.resolve(name)
        if tool is None:
            continue

        rest = tokens[1:]
        target = ""
        for i, t in enumerate(rest):
            if t in _TARGET_FLAGS and i + 1 < len(rest):
                target = rest[i + 1].strip("'\"")
                break
            mt = re.match(r"^(?:-u|--url|--target)=(.+)$", t)
            if mt:
                target = mt.group(1).strip("'\"")
                break
        if not target:
            target = extract_target(block)
        return {
            "name": tool.alias,
            "arguments": {"target": target or "", "args": " ".join(rest)},
        }
    return None


@dataclass
class Step:
    id: str
    tool_alias: str
    tool_name: str
    target: str
    args: str
    risk: dict
    status: str = "pending"  # pending | running | done | denied | error
    output: str = ""
    started_at: float | None = None
    finished_at: float | None = None


@dataclass
class Session:
    id: str
    project: str = ""
    messages: list[dict] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    events: asyncio.Queue = field(default_factory=asyncio.Queue)
    control: asyncio.Queue = field(default_factory=asyncio.Queue)
    state: str = "idle"  # idle | running | awaiting_confirm | done | error
    target: str = ""     # 从任务描述中提取的目标，每轮重申防止模型遗忘
    nudges: int = 0      # 已催促次数，防止无限追问
    created_at: float = field(default_factory=time.time)
    # ---- 对话树（线索分支）----
    parent_id: str = ""              # 父会话 id，根线索为 ''
    title: str = ""                  # 线索名
    records: list[str] = field(default_factory=list)  # 开分支时打包带来的记录
    summary: str = ""                # 最近一轮结论摘要（写回父对话/供其他线索引用）

    async def emit(self, event: dict) -> None:
        await self.events.put(event)


class SessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}

    def create(self, project: str = "", parent_id: str = "", title: str = "",
               records: list[str] | None = None) -> Session:
        sid = uuid.uuid4().hex[:12]
        s = Session(id=sid, project=project, parent_id=parent_id,
                    title=title, records=list(records or []))
        self.sessions[sid] = s
        return s

    def adopt(self, sid: str) -> Session | None:
        """从持久化层恢复已有会话（对话树切换线索/服务重启后续聊）。

        内存里已有则直接返回；store 里也没有返回 None。
        历史步骤一并装回：续聊时「已尝试过的工具」提醒、开分支的记录挑选都依赖它。
        """
        s = self.sessions.get(sid)
        if s:
            return s
        rec = store.get_session(sid)
        if not rec:
            return None
        row = rec["session"]
        try:
            records = json.loads(row.get("context") or "[]")
        except Exception:
            records = []
        s = Session(
            id=sid,
            project=row.get("project_id") or "",
            parent_id=row.get("parent_id") or "",
            title=row.get("title") or "",
            records=records if isinstance(records, list) else [],
        )
        s.target = row.get("target") or ""
        s.state = "idle"
        s.summary = row.get("summary") or ""
        for st in rec["steps"]:
            s.steps.append(Step(
                id=st.get("id") or uuid.uuid4().hex[:12],
                tool_alias=st.get("tool_alias") or "",
                tool_name=st.get("tool_name") or "",
                target=st.get("target") or "",
                args=st.get("args") or "",
                risk={"level": st.get("risk_level") or ""},
                status=st.get("status") or "done",
                output=st.get("output") or "",
                started_at=st.get("created_at"),
                finished_at=st.get("created_at"),
            ))
        self.sessions[sid] = s
        return s

    def get(self, sid: str) -> Session | None:
        return self.sessions.get(sid)


sessions = SessionManager()


class Agent:
    def __init__(self, backend_name: str | None = None) -> None:
        # 不在初始化时钉死后端：留 None，run() 时取运行时当前后端，
        # 这样前端切换模型后无需重启服务即对新任务生效。
        self.backend_name = backend_name

    # ---------- 主循环 ----------
    async def run(self, session: Session, user_message: str) -> None:
        session.state = "running"
        session.messages.append({"role": "user", "content": user_message})
        # 对话历史落库：切线索回放时可见用户原始消息
        try:
            store.save_chat_message(session.id, "user", user_message)
        except Exception:
            logger.exception("用户消息落库失败")
        session.target = extract_target(user_message)
        # 项目里显式填写的「目标」优先：用户建项目时填的常是纯企业名/域名，
        # 而任务描述往往只说「做信息收集」之类，模型从消息里识别不出目标。
        proj = store.get_project(session.project) if session.project else None
        proj_target = (proj.get("target") or "").strip() if proj else ""
        if proj_target and not session.target:
            # 项目 target 由用户在界面手填，可能混入「待定」「请提供」这类说明文字。
            # 原先直接赋值，问题要拖到工具执行前才以「目标参数无效」的形式暴露，
            # 打断模型决策。这里先过一遍格式校验，让它在任务开始时就失败得明明白白。
            # 注意：这是「提前失败」，不替代下方工具执行前的 validate_target 兜底，
            # 两处调用的是同一个函数、同一套参数，不存在任何放宽。
            bad_proj_target = validate_target(proj_target)
            if bad_proj_target:
                logger.warning("项目目标未采用（%s）：%r", bad_proj_target, proj_target)
            else:
                session.target = proj_target
        # 立即落库，避免中途关闭页面导致整轮记录丢失（树字段一并带上，
        # 分支线索在首次运行后就出现在小地图上）
        store.save_session(session.id, session.project, user_message, session.target,
                           "running", parent_id=session.parent_id, title=session.title)
        await session.emit({"type": "session_start", "session_id": session.id})
        backend = get_backend(self.backend_name)
        # 漏洞验证类任务自动路由云端：本地小模型在多步推理上明显吃力，
        # 云端模型（已验证 function calling）决策质量高一个量级。未配 Key 时自动回退。
        # 路由目标可在「设置 → 模型供应商」里改（默认 deepseek），也可关闭自动路由。
        if self.backend_name is None and config.AUTO_ROUTE_VULN:
            cloud = auto_route_candidate(backend.name)
            if cloud and any(k in user_message.lower() for k in config.VULN_KEYWORDS):
                backend = cloud
                await session.emit({
                    "type": "reasoning",
                    "data": f"检测到漏洞验证类任务，本次决策自动路由到「{cloud.label}」"
                            "（可在设置 → 模型供应商里关闭自动路由）",
                })
        await session.emit({
            "type": "model",
            "data": {
                "backend": backend.name,
                "model": getattr(backend, "model", ""),
                "label": getattr(backend, "label", backend.name),
                "local": bool(getattr(backend, "local", backend.name == "ollama")),
            },
        })
        if session.target:
            await session.emit({"type": "target", "data": session.target})
        system = SYSTEM_PROMPT.format(tool_list=registry.alias_reference())
        # 注入项目上下文（名称/目标/备注），让模型在首轮就明确目标，无需再向用户索要
        if proj:
            ctx_lines: list[str] = []
            if proj.get("name"):
                ctx_lines.append(f"项目名称：{proj['name']}")
            if proj.get("target"):
                ctx_lines.append(f"项目目标：{proj['target']}")
            if proj.get("note"):
                ctx_lines.append(f"项目备注：{proj['note']}")
            if ctx_lines:
                system += (
                    "\n\n【当前项目上下文】\n" + "\n".join(ctx_lines) + "\n"
                    "以上「项目目标」即本次任务的默认目标，直接使用，不要再向用户索要目标；"
                    "若用户任务里另有更具体的域名/IP/URL，则以任务里的为准。"
                    "目标是企业名时用可用工具（如 app_info）扩展资产，不要调用已禁用的 enscan。"
                )
        # 注入项目情报库：历史会话沉淀的子域/API/技术栈，避免重复收集
        if session.project:
            system += format_intel(store.get_intel(session.project))
            # 注入已证事实库（note_fact / 人工登记），已证实内容无需重复验证
            try:
                _facts = store.list_facts(session.project)
                if _facts:
                    _fl = "\n".join(f"- {f['content']}" for f in _facts[:20])
                    system += (
                        "\n\n【已证事实库（工具输出已证实，可直接引用、不得推翻或重复验证；"
                        "报告中基于这些事实组织结论）】\n" + _fl
                    )
            except Exception:
                logger.exception("已证事实注入失败")
        # 注入对话树上下文：①本线索开局打包记录 ②同项目其他线索的进展摘要。
        # 目的：单对话过长会遗忘细节，把方向拆到独立线索里深挖，跨线索信息按需取用。
        if session.records:
            rec_lines = "\n".join(f"- {r}" for r in session.records[:20])
            system += (
                "\n\n【本线索开局背景（从上级对话打包带来的已查记录，可直接引用，"
                "不要重复验证，也不要质疑其真实性）】\n" + rec_lines
            )
        if session.project:
            try:
                _others = [t for t in store.list_tree(session.project)
                           if t["id"] != session.id and (t.get("summary") or t.get("task"))]
                if _others:
                    _ol = []
                    for t in _others[:8]:
                        name = t.get("title") or (t.get("task") or "")[:24] or "未命名线索"
                        brief = t.get("summary") or (t.get("task") or "")[:80]
                        _ol.append(f"- 线索《{name}》（{t.get('status', 'active')}）：{brief}")
                    system += (
                        "\n\n【同项目其他线索的进展（并行推进的其他对话，详情可用 "
                        "search_history 工具按关键词检索，不要臆测其内容）】\n" + "\n".join(_ol)
                    )
            except Exception:
                logger.exception("线索树上下文注入失败")
        consecutive_failures = 0

        for step_no in range(1, config.MAX_STEPS + 1):
            # 每轮重建提醒：小模型在工具失败后容易「忘记」目标并反问用户，
            # 而且会反复调用同一个刚失败的工具，必须显式告诉它试过了什么。
            reminder = self._build_reminder(session)
            messages = [{"role": "system", "content": system + reminder}] + session.messages

            await session.emit({"type": "thinking", "step": step_no,
                                "data": f"第 {step_no} 步：正在决策…"})
            try:
                result = await backend.chat(messages, tools=registry.build_schemas())
            except Exception as e:
                await session.emit({"type": "error", "data": f"模型调用失败：{e}"})
                session.state = "error"
                await session.emit({"type": "done", "state": "error"})
                return

            # ---- 模型给出思考/说明 ----
            if result.get("content"):
                await session.emit({"type": "reasoning", "data": result["content"]})
                # 对话历史落库：模型说明（reasoning）
                try:
                    store.save_chat_message(session.id, "assistant", result["content"], kind="reasoning")
                except Exception:
                    logger.exception("模型说明落库失败")

            tool_calls = result.get("tool_calls") or []

            # ---- 没有工具调用：先尝试从 markdown 代码块兜底恢复 ----
            if not tool_calls:
                recovered = _parse_tool_from_markdown(result.get("content") or "")
                if recovered:
                    await session.emit({
                        "type": "reasoning",
                        "data": f"模型未产生 tool_calls，但输出文本中包含可识别的工具调用，"
                                f"已自动恢复：{recovered['name']}",
                    })
                    tool_calls = [{
                        "id": f"call_{step_no}_fallback",
                        "function": {
                            "name": recovered["name"],
                            "arguments": json.dumps(recovered["arguments"], ensure_ascii=False),
                        },
                    }]

            # ---- 仍没有工具调用 = 任务结束 ----
            if not tool_calls:
                # 本地小模型两种常见退化：① 反问用户要目标 ② 只描述计划不调用工具。
                # 两者都催促一次，仍不动手就认定它已给出结论。
                if session.nudges < 2:
                    session.nudges += 1
                    session.messages.append({
                        "role": "user",
                        "content": "请立即调用一个工具继续执行；如果任务确实已完成，"
                                   f"就直接给出最终结论。不要只描述计划。本次任务：{user_message}",
                    })
                    await session.emit({
                        "type": "reasoning",
                        "data": f"（模型未调用工具，第 {session.nudges} 次催促其执行或收尾）",
                    })
                    continue

                answer = result.get("content") or "（模型未给出结论）"
                session.messages.append({"role": "assistant", "content": answer})
                await self._write_back(session, answer)
                await session.emit({"type": "answer", "data": answer})
                session.state = "done"
                await session.emit({"type": "done", "state": "done"})
                return

            # ---- 有工具调用：逐步执行 ----
            assistant_msg: dict[str, Any] = {"role": "assistant", "content": result.get("content") or ""}
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.get("id", f"call_{step_no}_{i}"),
                    "type": "function",
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": tc["function"]["arguments"],
                    },
                }
                for i, tc in enumerate(tool_calls)
            ]
            session.messages.append(assistant_msg)

            for tc in assistant_msg["tool_calls"]:
                fn = tc["function"]
                alias = fn["name"]
                params = parse_tool_arguments(fn.get("arguments", "{}"))
                target = str(params.get("target", "")).strip()
                args = str(params.get("args", "") or "").strip()

                # ---- 校验工具名（模型会拼错甚至编造） ----
                tool, fuzzy = registry.resolve(alias)
                if tool is None:
                    # 兜底恢复路径 1：name="tool_call" 之类畸形调用，
                    # 真实调用可能嵌在 arguments 的 JSON 里
                    inner = parse_tool_arguments(fn.get("arguments", "{}"))
                    if isinstance(inner, dict):
                        inner_fn = inner.get("function") or inner
                        inner_name = inner_fn.get("name") or inner_fn.get("tool")
                        if inner_name:
                            resolved, _ = registry.resolve(str(inner_name))
                            if resolved is not None:
                                await session.emit({
                                    "type": "reasoning",
                                    "data": f"tool_calls 畸形（name={alias!r}），"
                                            f"已从 arguments 中恢复真实调用：{resolved.alias}",
                                })
                                tool, fuzzy = resolved, False
                                params = inner_fn.get("arguments") or inner_fn.get("args") or {}
                                if isinstance(params, str):
                                    params = parse_tool_arguments(params)
                                target = str(params.get("target", "")).strip()
                                args = str(params.get("args", "") or "").strip()
                    # 兜底恢复路径 2：真实调用写在输出文本的 markdown 代码块里
                if tool is None:
                    recovered = _parse_tool_from_markdown(result.get("content") or "")
                    if recovered:
                        await session.emit({
                            "type": "reasoning",
                            "data": f"工具名 `{alias}` 不存在，但输出文本中包含可识别的调用，"
                                    f"已自动恢复：{recovered['name']}",
                        })
                        tool, fuzzy = registry.resolve(recovered["name"])[0], False
                        params = recovered["arguments"]
                        target = str(params.get("target", "")).strip()
                        args = str(params.get("args", "") or "").strip()
                if tool is None:
                    msg = (
                        f"工具 `{alias}` 不存在。请从可用工具清单中选择真实存在的工具，"
                        f"不要编造工具名。可用工具：{', '.join(t.alias for t in registry.usable_scriptable())}"
                    )
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": msg})
                    # 记录 repr：模型返回的名字常带不可见字符，只打印原文会看不出问题
                    logger.warning("拦截不存在的工具：alias=%r 原始=%r", alias, fn.get("name"))
                    await session.emit({"type": "error", "data": f"已拦截不存在的工具：{alias}"})
                    continue
                if fuzzy:
                    await session.emit({
                        "type": "reasoning",
                        "data": f"工具名 `{alias}` 不存在，已自动纠正为 `{tool.alias}`（{tool.name}）",
                    })

                # ---- 内置 note_fact：记录已证事实（不进执行计划/不走风险闸门）----
                if tool.alias == "note_fact":
                    await self._note_fact(session, tc, target, args)
                    continue

                # ---- 内置 search_history / propose_branch（对话树能力，L0，不走风险闸门）----
                if tool.alias == "search_history":
                    await self._search_history(session, tc, args or target)
                    continue
                if tool.alias == "propose_branch":
                    await self._propose_branch(session, tc, args)
                    continue

                # ---- 内置 kb_search / kb_read / fofa_search（知识库与测绘，L0/L1）----
                if tool.alias in ("kb_search", "kb_read", "fofa_search"):
                    await self._kb_fofa_tool(session, tool.alias, tc, args)
                    continue

                # ---- 校验目标（模型会把中文句子当目标传入） ----
                bad_target = validate_target(target)
                if bad_target:
                    msg = f"目标参数无效：{bad_target}。target 必须是域名、IP、URL 或企业名称，不能是说明性文字。请从用户任务中提取真实目标后重试。"
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": msg})
                    await session.emit({"type": "error", "data": f"已拦截无效目标：{target[:40]}"})
                    continue

                # 风险等级必须用「纠正后」的规范别名查，否则模型拼错工具名
                # （如 ddddd_scan）时 risk_of 会查不到，等级变成 ? 被默认拒绝。
                risk = registry.risk_of(tool.alias) or {}
                step = Step(
                    id=tc["id"],
                    tool_alias=tool.alias,
                    tool_name=tool.name,
                    target=target,
                    args=args,
                    risk=risk,
                )
                session.steps.append(step)

                # ---- 风险闸门 ----
                if not risk.get("auto", False):
                    approved = await self._await_confirm(session, step)
                    if not approved:
                        step.status = "denied"
                        session.messages.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": f"用户拒绝执行 {tool.name}（风险等级 {risk.get('level')}）。请改用其他更低风险的方式，或说明为什么必须执行。",
                        })
                        await session.emit({"type": "step_denied", "step": self._step_dict(step)})
                        try:
                            store.save_step(session.id, self._step_dict(step))
                        except Exception:
                            pass
                        continue

                # ---- 执行 ----
                await self._execute(session, step, tc["id"])
                # 执行成功即重置连续失败计数；失败则累加
                if step.status == "done":
                    consecutive_failures = 0
                elif step.status == "error":
                    consecutive_failures += 1

            # 连续多次失败说明思路不对，及时止损避免空转
            if consecutive_failures >= 3:
                stop_msg = f"连续 {consecutive_failures} 次执行失败，已停止。请检查目标可达性、工具参数或授权范围。"
                await self._write_back(session, stop_msg)
                await session.emit({
                    "type": "answer",
                    "data": stop_msg,
                })
                self._persist_intel(session)
                session.state = "done"
                await session.emit({"type": "done", "state": "done"})
                return

        max_steps_msg = f"已达到最大步数 {config.MAX_STEPS}，停止执行。"
        await self._write_back(session, max_steps_msg)
        await session.emit({"type": "answer", "data": max_steps_msg})
        self._persist_intel(session)
        session.state = "done"
        await session.emit({"type": "done", "state": "done"})

    # ---------- 情报沉淀 ----------
    def _persist_intel(self, session: Session) -> None:
        """会话结束时，把本轮工具输出沉淀进项目情报库，供下轮注入。"""
        if not session.project:
            return
        try:
            update_intel_from_steps(session.project, [st.output for st in session.steps])
        except Exception:
            logger.exception("项目情报沉淀失败")

    # ---------- 已证事实记录 ----------
    async def _note_fact(self, session: Session, tc: dict, target: str, args: str) -> None:
        """note_fact 内置工具执行：写入项目事实库并回馈模型。"""
        content = (args or "").strip() or (target or "").strip()
        if not session.project:
            note = "当前会话未关联项目，无法保存事实。请先创建/选择项目后再执行。"
        elif not content:
            note = "事实内容为空：args 应填要记录的事实正文（一句一事）。"
        else:
            try:
                rec = store.add_fact(session.project, content[:500], source="agent")
                note = f"已记录已证事实 #{rec.get('id','')}：{content[:120]}"
            except Exception as e:
                note = f"记录事实失败：{e}"
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
        await session.emit({"type": "reasoning", "data": f"（{note}）"})

    # ---------- 对话树：跨线索检索 ----------
    async def _search_history(self, session: Session, tc: dict, keyword: str) -> None:
        """search_history 内置工具：在项目内所有会话的历史工具输出里检索关键词。"""
        kw = (keyword or "").strip()[:80]
        if not session.project:
            note = "当前会话未关联项目，无法检索历史线索。"
        elif not kw:
            note = "搜索关键词为空：args 应填要检索的关键词（域名、路径、工具名、端口等）。"
        else:
            try:
                hits = store.search_history(session.project, kw)
            except Exception as e:
                hits = []
                note = f"检索失败：{e}"
            if not hits:
                note = f"未检索到包含「{kw}」的历史记录。可换更具体的关键词（如具体路径、子域名、端口）。"
            else:
                lines = []
                for h in hits:
                    src = h.get("title") or (h.get("task") or "")[:24] or "未命名线索"
                    lines.append(
                        f"【线索《{src}》· {h.get('tool_name') or h.get('tool_alias')} → {h.get('target') or '-'}】\n"
                        f"{h.get('snippet', '')}"
                    )
                note = f"检索到 {len(hits)} 条包含「{kw}」的历史记录（已证实的工具输出，可直接引用）：\n\n" + "\n\n".join(lines)
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
        await session.emit({"type": "reasoning", "data": f"（检索历史线索：{kw} → {len(hits) if session.project and kw else 0} 条）"})

    # ---------- 对话树：建议开辟新线索 ----------
    async def _propose_branch(self, session: Session, tc: dict, args: str) -> None:
        """propose_branch 内置工具：向用户展示「开新线索」卡片，用户确认后才真正创建。

        卡片候选记录 = 本会话最近的工具步骤摘要（前端可勾选打包带走）。
        """
        text = (args or "").strip()
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        title = (lines[0] if lines else "新线索")[:60]
        reason = "\n".join(lines[1:]) if len(lines) > 1 else ""
        candidates = [self._step_dict(st) for st in session.steps[-6:]]
        await session.emit({
            "type": "branch_proposal",
            "data": {
                "title": title,
                "reason": reason,
                "candidates": candidates,
            },
        })
        note = (f"已把「开新线索」卡片展示给用户，建议标题《{title}》。"
                f"用户确认后新对话会自动携带相关记录独立推进；"
                f"请继续当前任务，或在当前方向确实告一段落时给出结论结束。")
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
        await session.emit({"type": "reasoning", "data": f"（已发出开新线索建议：《{title}》，等待用户确认）"})

    # ---------- 知识库 / FOFA 测绘 ----------
    async def _kb_fofa_tool(self, session: Session, alias: str, tc: dict, args: str) -> None:
        """kb_search / kb_read / fofa_search 内置工具执行。"""
        arg = (args or "").strip()
        try:
            if alias == "kb_search":
                if arg.lower() == "list" or not arg:
                    topics = kb.list_topics()
                    body = "\n".join(f"- [{t['category']}] {t['file']}  {t['title']}" for t in topics)
                    note = f"知识库共 {len(topics)} 篇（kb=漏洞类型打法，rules=工作流/报告规则）：\n{body}"
                else:
                    hits = kb.search(arg)
                    if not hits:
                        note = f"知识库中未检索到「{arg}」。可用 args='list' 查看全部篇目名。"
                    else:
                        body = "\n".join(
                            f"- [{h['category']}] {h['file']}（命中 {h['score']}）\n  {h['snippet'][:200]}"
                            for h in hits
                        )
                        note = f"「{arg}」命中 {len(hits)} 篇，用 kb_read 读全文：\n{body}"
            elif alias == "kb_read":
                r = kb.read(arg)
                note = f"【{r.get('file', arg)}】\n{r.get('content') or r.get('error', '')}"
            else:  # fofa_search
                r = await fofa.search(arg)
                if r.get("error"):
                    note = f"FOFA 查询失败：{r['error']}"
                else:
                    body = "\n".join(
                        f"- {x.get('host', '')} | {x.get('ip', '')}:{x.get('port', '')}"
                        f" | {(x.get('title') or '')[:40]} | {(x.get('server') or '')[:30]}"
                        for x in r.get("results", [])
                    )
                    note = (f"FOFA 查询「{r['query']}」返回 {r['count']} 条（消耗 F点：{r.get('consumed_fpoint', '?')}）：\n{body}"
                            "\n按「一种子闭环」：把这些活面挖完再查下一个种子。")
        except Exception as e:
            note = f"{alias} 执行异常：{e}"
            logger.exception("%s 执行异常", alias)
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note[: config.MAX_OUTPUT_CHARS + 2000]})
        await session.emit({"type": "reasoning", "data": f"（{alias} → {'OK' if '失败' not in note and '异常' not in note else '见结果'}）"})

    # ---------- 对话树：结论回流 ----------
    async def _write_back(self, session: Session, answer: str) -> None:
        """会话给出最终结论后：①摘要落库（供其他线索的上下文注入与小地图展示）
        ②父会话在线时实时推送 branch_update 通知。"""
        text = (answer or "").strip()
        if not text:
            return
        # 对话历史落库：最终结论（answer）
        try:
            store.save_chat_message(session.id, "assistant", text, kind="answer")
        except Exception:
            logger.exception("结论消息落库失败")
        session.summary = text[:1000]
        try:
            store.save_summary(session.id, session.summary)
        except Exception:
            logger.exception("结论摘要落库失败")
        if session.parent_id:
            parent = sessions.get(session.parent_id)
            if parent:
                await parent.emit({
                    "type": "branch_update",
                    "data": {
                        "child": session.id,
                        "title": session.title or "子线索",
                        "summary": text[:300],
                    },
                })

    # ---------- 防呆提醒 ----------
    @staticmethod
    def _build_reminder(session: Session) -> str:
        """每轮注入目标 + 已尝试工具，抑制「遗忘目标」与「重复调同一失败工具」。"""
        parts: list[str] = []
        if session.target:
            if _is_host_like(session.target):
                note = (f"所有工具的 target 参数都必须填 `{session.target}`，"
                        f"除非用户明确要求更换目标。")
            else:
                # 企业名（如「腾讯」）不能直接当扫描工具的目标
                note = (f"`{session.target}` 看起来是企业名称而非域名/IP。"
                        f"请先用可用工具（如 app_info 按名称收集 APP/资产）扩展出域名，"
                        f"拿到域名后再把域名作为 target 使用其余工具；"
                        f"不要把企业名直接塞进扫描/探测类工具的 target，也不要调用已禁用的 enscan。")
            parts.append(
                f"\n\n【本次任务目标：{session.target}】\n{note}"
                f"不要向用户索要目标，也不要把说明文字填进 target。"
            )
        if session.steps:
            tried: dict[str, list[str]] = {}
            for st in session.steps:
                tried.setdefault(st.tool_alias, []).append(st.status)
            items = []
            for alias, statuses in tried.items():
                mark = "失败" if all(s != "done" for s in statuses) else "已执行"
                items.append(f"{alias}({mark}x{len(statuses)})")
            parts.append(
                "\n【本轮已尝试过的工具】" + "、".join(items)
                + "\n不要用同样的参数重复调用其中标记为「失败」的工具；"
                  "换用其他工具或换参数。重复调用失败工具是最严重的错误。"
            )
        return "".join(parts)

    # ---------- 确认流程 ----------
    async def _await_confirm(self, session: Session, step: Step) -> bool:
        session.state = "awaiting_confirm"
        await session.emit({
            "type": "need_confirm",
            "step": self._step_dict(step),
            "risk": step.risk,
        })
        try:
            resp = await asyncio.wait_for(session.control.get(), timeout=600)
        except asyncio.TimeoutError:
            await session.emit({"type": "error", "data": "确认超时，已取消该步骤"})
            return False
        session.state = "running"
        return bool(resp.get("approved"))

    # ---------- 执行并收集输出 ----------
    async def _execute(self, session: Session, step: Step, tool_call_id: str) -> None:
        tool = registry.get_by_alias(step.tool_alias)
        if tool is None:
            return

        step.status = "running"
        step.started_at = time.time()
        await session.emit({"type": "step_start", "step": self._step_dict(step)})

        chunks: list[str] = []
        exit_code = None
        # 内置工具走 app/replayer.py 托管运行器（不 spawn 工具箱子进程）
        if tool.alias == "httpreplay":
            gen = replayer.run_replay(step.target, step.args)
        elif tool.alias == "nuclei_cli":
            gen = replayer.run_nuclei(tool, step.target, step.args)
        elif tool.alias == "py_exec":
            gen = pyexec.run_py_exec(step.args, step.target)
        else:
            gen = executor.run(tool, step.target, step.args)
        async for ev in gen:
            etype = ev.get("type")
            if etype == "output":
                chunks.append(ev["data"])
                await session.emit({"type": "output", "step_id": step.id, "data": ev["data"]})
            elif etype == "command":
                await session.emit({"type": "command", "step_id": step.id, "data": ev["data"]})
            elif etype == "error":
                chunks.append(f"[错误] {ev['data']}")
                await session.emit({"type": "output", "step_id": step.id, "data": f"[错误] {ev['data']}"})
            elif etype == "exit":
                exit_code = ev.get("code")
                await session.emit({"type": "exit", "step_id": step.id, "code": exit_code})

        step.output = "\n".join(chunks)
        step.finished_at = time.time()
        # 部分工具退出码不可信（如 EHole：没命中「重点资产」就返回 1，
        # 但其实已经把指纹打出来了）。有实质输出就按成功算，否则会把成功误判为失败。
        meaningful = bool(step.output.strip())
        ok = exit_code == 0 or (tool.ignore_exit_code and meaningful)
        step.status = "done" if ok else "error"
        await session.emit({"type": "step_done", "step": self._step_dict(step)})
        # 每步即时落库
        try:
            store.save_step(session.id, self._step_dict(step))
        except Exception:
            pass

        # 回喂给模型（截断，防止撑爆上下文）
        content = step.output or "（工具无输出）"
        if not ok:
            content = (
                f"【{step.tool_name} 执行失败】退出码 {exit_code}。输出如下：\n{content}\n"
                f"禁止用同样参数再次调用 {step.tool_name}。"
                f"请换参数，或改用功能相近的其他工具；"
                f"若已无其他可行手段，就直接给出结论结束任务。"
            )
        if len(content) > config.MAX_OUTPUT_CHARS:
            content = content[: config.MAX_OUTPUT_CHARS] + f"\n…（输出过长已截断，共 {len(step.output)} 字符）"
        session.messages.append({"role": "tool", "tool_call_id": tool_call_id, "content": content})

    def _step_dict(self, step: Step) -> dict:
        return {
            "id": step.id,
            "tool_alias": step.tool_alias,
            "tool_name": step.tool_name,
            "target": step.target,
            "args": step.args,
            "risk": step.risk,
            "status": step.status,
            "output": step.output[-2000:],
            "elapsed": round(step.finished_at - step.started_at, 1) if step.finished_at and step.started_at else None,
        }


agent = Agent()
