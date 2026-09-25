# -*- coding: utf-8 -*-
"""v048 优化回归测试：文档契约 + getattr 窄例外 + 任务级约束闸门。

三项都由 2026-09-25 某企业站 实战暴露，每项都有现场证据：

  A. **模型看到的 caveat 没跟着功能更新**（本轮最贵的一项）
     `app/registry.py` 里 py_exec 的 caveat 标着 `必读（v023.7）`，只说「用 `tmpdir` 落盘」，
     **完全没提** v045 的 `save_text`/`load_text`、v045.2 的 `load_bytes`/`file_md5`。
     v045.2 当时只改了**沙箱模块的 docstring** —— 而那份要主动 `print(...__doc__)` 才看得到。
     后果：Agent 明确推理出「128KB 截断 → 改为落盘后本地全量解析」，然后只能写 `open()` 去读
     → 被判非只读拒 → **只好放弃落盘**，于是大 JS 永远读不完整。
     **v031 专门做的落盘机制，实战里一次没用上。**
     同一条 caveat 还有第二处矛盾：④ 说「依赖可用 httpx」，而分档器一律判 `import httpx` 非只读；
     `description` 里同样写着「（httpx/requests 可用）」。
     修法：把 caveat 改成**机器可校验的契约**，并用测试把
     「caveat 声明」↔「分档器白名单」↔「沙箱实际导出」**三处绑死**。

  B. **`getattr` 判定过严，且与已有的窄例外自相矛盾**
     分档器早已给 `__import__("re")`（参数是字面量、模块在白名单内）开了窄例外，
     却对**同样安全**的 `getattr(obj, "text", "")` 一律拒绝。实测因它一步 py_exec
     被判 L3、白等 90 秒才被拒。

  C. **任务级禁令进不了闸门**
     任务书写明「不做字典爆破」，Agent 仍调 OneForALL（**95247 词**字典 + massdns）。
     它是 **L0 → 风险闸门自动放行**，整条链上没有任何环节能拦住 ——
     风险闸门只知道「工具多危险」，不知道「本次任务不允许什么」。
     **双输**：违反公益 SRC 最小必要，且 OneForALL 输出还被截断，
     14 个子域最终只拿到 HTML 里实引用的 3 个。

统计行格式必须是 `结果：N 通过 / M 失败`（run_all_tests.py 的正则要求）。
"""
from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import (config, pyexec_bridge, pyexec_grade,      # noqa: E402
                 registry, taskguard)

REPO = Path(__file__).resolve().parent
PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" —— {detail}" if detail else ""))


def read(rel: str) -> str:
    try:
        return (REPO / rel).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def py_exec_tool():
    return registry.ToolRegistry().load().get_by_alias("py_exec")


# ---------------------------------------------------------------- A
_MARK_API = "【受控接口】"
_MARK_DENY = "【禁止使用】"


def _section(text: str, marker: str) -> str:
    """取某个 【…】 段的内容（到下一个 【 或串尾）。"""
    i = text.find(marker)
    if i < 0:
        return ""
    i += len(marker)
    j = text.find("【", i)
    return text[i:j if j >= 0 else len(text)]


def _tokens(segment: str) -> set[str]:
    """段内的名字集合（用「、」分隔，允许 `urllib.request` 这种带点的）。"""
    out = set()
    for part in re.split(r"[、\s]+", segment):
        p = part.strip().strip("`").strip("。，；")
        if re.fullmatch(r"[A-Za-z_][\w.]*", p):
            out.add(p)
    return out


def test_a_doc_contract():
    """[A] 文档契约：caveat ↔ 分档器白名单 ↔ 沙箱实际导出，三处必须一致。"""
    print("\n[A] py_exec 文档契约（散文会漂移，契约不会）")
    t = py_exec_tool()
    caveat = t.caveat or ""
    check("py_exec 工具存在且带 caveat", bool(caveat))

    api_sec, deny_sec = _section(caveat, _MARK_API), _section(caveat, _MARK_DENY)
    check("caveat 含机器可校验的「受控接口」段", bool(api_sec))
    check("caveat 含机器可校验的「禁止使用」段", bool(deny_sec))

    api = _tokens(api_sec)
    deny = _tokens(deny_sec)
    check("受控接口段能解析出名字", len(api) >= 5, str(sorted(api)))

    # ---- 正向：段里声明的 == 分档器白名单（两侧都查，任一漂移就红）----
    missing = sorted(pyexec_grade.ALLOWED_SRCAGENT_NAMES - api)
    extra = sorted(api - pyexec_grade.ALLOWED_SRCAGENT_NAMES)
    check("分档器白名单里的每个 API 都写进了 caveat（v045.2 就是漏了这一步）",
          not missing, f"漏写：{missing}")
    check("caveat 没多写分档器不认的 API", not extra, f"多写：{extra}")

    # ---- 反向：caveat 说「禁止」的，闸门必须真的禁（否则是空头警告）----
    not_denied = sorted(x for x in deny
                        if x not in pyexec_grade.DENIED_ROOTS
                        and x not in pyexec_grade.DENIED_BUILTINS)
    check("caveat 列为禁止的每一项，分档器都真的会拒（不许有空头警告）",
          not not_denied, f"其实没禁：{not_denied}")
    check("两段没有交集（同一名字不能既允许又禁止）",
          not (api & deny), str(sorted(api & deny)))

    # ---- 模型实际踩过的坑必须被明确写进「禁止」段 ----
    for tok in ("httpx", "requests", "urllib.request", "os", "subprocess",
                "socket", "importlib", "open", "eval", "exec"):
        check(f"禁止段列了 `{tok}`（模型实测误用的写法）", tok in deny)

    # ---- v048 的具体修复：落盘后怎么读，必须写在模型看得见的地方 ----
    for tok in ("saved_text_path", "load_text", "load_bytes", "file_md5", "tmpdir"):
        check(f"caveat 写明 `{tok}`（落盘解析路线才走得通）", tok in caveat)
    check("caveat 明确警告不要用裸 open() 读落盘文件",
          "不要用裸 `open()`" in caveat or "不要用裸 `open()` 去读" in caveat)

    # ---- 描述（模型最先读的一段）不得再宣传被禁的库 ----
    desc = t.description or ""
    check("description 不再写「httpx/requests 可用」",
          "httpx" not in desc and "requests" not in desc, desc[:80])

    # ---- 第三方：沙箱实际导出必须与白名单完全一致 ----
    src = pyexec_bridge.SCRIPT_MODULE_SOURCE
    exported = set(re.findall(r"^(?:def|class)\s+([A-Za-z_]\w*)", src, re.M)) | set(
        re.findall(r"^([A-Z][A-Z_0-9]{2,})\s*=", src, re.M))
    exported = {n for n in exported if not n.startswith("_") and n != "main"}
    ghost = sorted(pyexec_grade.ALLOWED_SRCAGENT_NAMES - exported)
    check("白名单里的每个 API 沙箱都真的导出了（曾经有 range_download/save_artifact "
          "两个幽灵 API 在白名单里）", not ghost, f"幽灵：{ghost}")
    undeclared = sorted(exported - pyexec_grade.ALLOWED_SRCAGENT_NAMES)
    check("沙箱导出的每个公开名都进了白名单（漏了等于模型不能用）",
          not undeclared, f"未登记：{undeclared}")


# ---------------------------------------------------------------- B
def test_b_getattr():
    """[B] getattr 字面量窄例外：与 __import__ 的例外同原理。"""
    print("\n[B] `getattr` 窄例外（同一个原理不能只落在一半入口上）")
    g = pyexec_grade.grade
    T = pyexec_grade.TIER_OPAQUE

    allowed_cases = [
        ('from srcagent import safe_http_request\nr = safe_http_request("https://a.test/")\n'
         'print(getattr(r, "text", "")[:100])', "防御性取字段（本轮实测被误拒的形态）"),
        ('import json\nprint(getattr(json, "dumps")({"a": 1}))', "字面量取白名单模块方法"),
        ('print(getattr("abc", "upper")())', "字面量取字符串方法"),
    ]
    for code, label in allowed_cases:
        check(f"放行：{label}", g(code).tier != T, f"实得 {g(code).tier}")

    denied_cases = [
        ('print(getattr(__builtins__, "ev"+"al")("1"))', "拼接属性名"),
        ('n = "system"\nprint(getattr(__import__("os"), n))', "变量属性名"),
        ('print(getattr(1, "__class__"))', "双下划线属性名"),
        ('print(getattr(1, "_private"))', "下划线开头"),
        ('import os\nprint(getattr(os, "system"))', "属性名是危险动词"),
        ('import sys\nprint(getattr(sys, "modules"))', "取 modules（模块表）"),
        ('print(getattr(object(), "popen"))', "popen"),
        ('print(getattr(x, "environ"))', "environ"),
        ('print(getattr(x, "read", encoding="utf-8"))', "带关键字参数"),
        ('print(getattr(x, "a", "b", "c"))', "参数过多"),
        ('print(getattr(x))', "参数过少"),
    ]
    for code, label in denied_cases:
        check(f"拒绝：{label}", g(code).tier == T, f"实得 {g(code).tier}")

    # ---- 反向：危险属性名表里的每个名字都不能被字面量放行 ----
    leaky = []
    for name in sorted(pyexec_grade.DENIED_ATTR_NAMES):
        code = f'print(getattr(obj, "{name}"))'
        if g(code).tier != T:
            leaky.append(name)
    check(f"{len(pyexec_grade.DENIED_ATTR_NAMES)} 个危险属性名逐一试用均被拒",
          not leaky, f"漏网：{leaky[:8]}")

    # ---- 两处例外同原理：都是「参数是字面量 → 不构成动态能力」----
    check("字面量白名单模块的 __import__ 仍放行（既有例外没被破坏）",
          g('print(__import__("json").dumps({"a": 1}))').tier != T)
    check("非白名单模块的 __import__ 仍拒绝",
          g('print(__import__("subprocess").run(["id"]))').tier == T)
    check("源码写明两条例外同原理", "字面量例外" in read("app/pyexec_grade.py"))


# ---------------------------------------------------------------- C
def test_c_task_constraints():
    """[C] 任务级约束闸门：解析 → 能力标签 → 拒绝 → 留痕 → 落库。"""
    print("\n[C] 任务级约束闸门（L0 自动放行的工具也要拦得住）")
    tg = taskguard

    # ---- 解析 ----
    hit_cases = [
        "公益 SRC 纪律：最小必要验证。不做目录爆破式扫描、不跑大字典、不并发。",
        "只读：禁止 POST/DELETE、禁止上传、禁止暴力破解、禁止批量枚举。",
        "**不做字典爆破**",
        "禁止扫描",
    ]
    for text in hit_cases:
        check(f"解析出禁令：{text[:24]}", bool(tg.parse(text)))
    miss_cases = [
        # 划范围的提醒句（最容易被误判的一类）
        "代码内 HTTP 请求只允许发往当前授权目标及其资产，禁止扫描/访问未授权主机或内网。",
        "不要扫描授权范围外的任何主机",
        "禁止越权访问，不得访问内网",
        "请做第一轮只读侦察，输出已证实/已证否/可疑三档。",
    ]
    for text in miss_cases:
        check(f"不误判（划范围的提醒句）：{text[:20]}", not tg.parse(text))

    # ---- merge：后续消息不该抹掉先前声明的禁令 ----
    a = tg.parse("不做字典爆破")
    b = tg.parse("禁止扫描")
    check("merge 保留双方约束", set(tg.merge(a, b)) == {"bruteforce", "scan"})
    check("merge 不会把旧约束抹掉", "bruteforce" in tg.merge(a, {}))

    # ---- 能力标签 ----
    reg = registry.ToolRegistry().load()
    caps_of = {t.alias: list(t.caps) for t in reg.tools if getattr(t, "caps", None)}
    check("有工具声明了 caps", len(caps_of) >= 5, str(sorted(caps_of))[:120])
    unknown = sorted({c for cs in caps_of.values() for c in cs}
                     - set(tg.CAP_LABEL))
    check("overrides 里的 caps 取值都在 taskguard.CAP_LABEL 登记过"
          "（新增标签必须登记，否则闸门不知怎么拦）", not unknown, f"未登记：{unknown}")

    c = tg.parse("不做字典爆破")
    check("oneforall 被拦（它就是本轮实际被误用的那个）",
          bool(tg.violation(c, caps_of.get("oneforall"))))
    check("ehole 不被拦（单发被动指纹，不是爆破）",
          not tg.violation(c, caps_of.get("ehole")))
    check("scan 类工具在只声明 bruteforce 时不被拦",
          not tg.violation(c, caps_of.get("fscan")))
    c2 = tg.parse("禁止扫描")
    check("声明「禁止扫描」时 fscan 被拦", bool(tg.violation(c2, caps_of.get("fscan"))))
    check("无约束时不拦任何工具", not tg.violation({}, caps_of.get("oneforall")))

    # ---- 拒绝消息必须给可执行替代（否则模型只会换个工具重试）----
    msg = tg.refusal_message("OneForALL", "bruteforce", "不做字典爆破")
    check("拒绝消息给出替代路径", "改用" in msg and "crt.sh" in msg or "sitemap" in msg)
    check("拒绝消息明确要求不要换同类工具重试", "不要" in msg and "重试" in msg)

    # ---- 接线：必须在风险闸门之前，否则 L0 已经从旁边走掉了 ----
    src = read("app/agent.py")
    i_cons = src.find("taskguard.violation(session.constraints")
    i_gate = src.find("# ---- 风险闸门 ----")
    check("agent 调用了约束闸门", i_cons > 0)
    check("约束闸门在风险闸门**之前**（放在之后 L0/L1 就已经放行了）",
          0 < i_cons < i_gate, f"constraint@{i_cons} gate@{i_gate}")
    check("约束闸门对 L0/L1 也生效（不看 risk.auto）",
          "getattr(tool, \"caps\", None)" in src[i_cons - 200:i_cons + 200]
          or "getattr(tool, \"caps\", None)" in src)
    check("拦截后发 step_denied 留痕", "step_denied" in src[i_cons:i_cons + 900])
    check("拦截后给模型发 reasoning 说明原因",
          "reasoning" in src[i_cons:i_cons + 1400])

    # ---- 每轮重申：写在任务书开头挡不住，长上下文里会被淹没 ----
    check("每轮提醒注入当前生效约束", "本次任务已声明的禁令" in src)
    check("说清「会被直接拒绝」而不是「需要确认」", "会被直接拒绝执行" in src)

    # ---- 落库与恢复：闸门依据丢失 = 静默失效 ----
    scols = [r[1] for r in __import__("sqlite3").connect(
        REPO / "data" / "projects.db").execute("pragma table_info(sessions)")]
    check("sessions 表有 constraints 列（旧库已迁移）", "constraints" in scols)
    ss = read("app/store.py")
    check("save_session 支持 constraints 且仅显式传入时更新",
          "constraints: dict | None = None" in ss and "if constraints is not None" in ss)
    check("adopt 会把 constraints 装回（否则续聊后闸门失效）",
          "s[\"constraints\"]" in src or "s.constraints = json.loads(row.get(\"constraints\")"
          in src)
    check("run() 开头解析并 merge 约束", "taskguard.merge(" in src)

    # ---- 开关 ----
    check("config 暴露 TASK_CONSTRAINTS_ENABLED", hasattr(config, "TASK_CONSTRAINTS_ENABLED"))
    check("开关默认开启", config.TASK_CONSTRAINTS_ENABLED is True)
    check("README 或 overrides 说明了 caps 字段",
          "v048 新增 caps" in read("data/tool_overrides.json"))


def test_d_no_real_targets():
    """[D] 本版新增/改动文件不得含真实靶标（继承 v046/v047 的词干口径）。"""
    print("\n[D] 本版改动文件防泄露")
    scope_file = REPO / "data" / "scope.json"
    if not scope_file.exists():
        check("scope.json 不存在 → 跳过（非本机环境）", True)
        return
    try:
        domains = json.loads(scope_file.read_text(encoding="utf-8")).get("domains") or []
    except Exception as e:                                       # noqa: BLE001
        check("scope.json 可解析", False, str(e))
        return
    allow = {"discuz"}
    stems = []
    for d in domains:
        if not isinstance(d, str) or "." not in d:
            continue
        s = d.split(".")[0].lower()
        if len(s) >= 4 and s not in allow and s not in stems:
            stems.append(s)
    if not stems:
        check("无可查词干 → 跳过", True)
        return
    files = ["app/taskguard.py", "app/pyexec_grade.py", "app/registry.py",
             "app/agent.py", "app/store.py", "app/config.py",
             "data/tool_overrides.json", "test_048_fixes.py"]
    hits = []
    for rel in files:
        text = read(rel).lower()
        for s in stems:
            if s in text:
                hits.append(f"{rel}⊃{s}")
    check(f"本版 8 个文件不含靶标词干（查了 {len(stems)} 个）", not hits, str(hits))


def test_e_gate_end_to_end():
    """[E] 端到端：任务声明禁令时，L0 的 OneForALL 真的被拦下。

    [C] 组只断言了「闸门写在风险闸门之前」（源码位置）。位置对不等于**活着** ——
    插错变量、被提前 continue 掉、条件恒假，都能让位置断言通过而闸门从没生效。
    所以这里用假后端跑一遍**真实的 agent.run()**：让它第一轮就调 oneforall，
    看这一步是不是真的被拒。

    ⚠️ 安全前提：目标用**不在授权白名单**的 `example.test`。即使闸门是死的，
    执行器的 scope 校验也会拦住 —— 不会对任何真实目标发出流量。
    同时断言拒绝理由里**没有**「不在授权白名单」字样：出现它就说明是 scope 拦的、
    也就是约束闸门失效了（这正是不变量测试该抓的）。
    """
    print("\n[E] 端到端：约束闸门真的拦得住 L0 工具")
    import asyncio
    import json as _json

    from app import agent as agent_mod
    from app import store
    from app.agent import agent, sessions
    from app.registry import registry as _reg

    if not _reg.tools:                                    # 幂等：load() 是追加式的
        _reg.load()
    if not _reg.get_by_alias("oneforall"):
        check("oneforall 存在于工具清单（无则跳过）", False, "缺 oneforall")
        return
    caps = list(getattr(_reg.get_by_alias("oneforall"), "caps", []) or [])
    check("oneforall 带 bruteforce 能力标签", "bruteforce" in caps, str(caps))

    TASK = ("对 https://example.test/ 做第一轮只读侦察。"
            "公益 SRC 纪律：最小必要验证，**不做字典爆破**、不跑大字典。"
            "子域只从页面 HTML/JS 里找线索。")

    class _ToolBackend:
        name, label, model, local = "ollama", "本地 Ollama", "fake-v048", True

        def __init__(self, tool_name: str):
            self.calls = 0
            self.tool_name = tool_name

        def available(self):
            return True

        async def chat(self, messages, tools=None):
            self.calls += 1
            self.last_messages = messages          # 提醒不进 session.messages，只能从这里看
            if self.calls == 1:
                return {"tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": self.tool_name,
                                 "arguments": _json.dumps(
                                     {"target": "example.test"}, ensure_ascii=False)}}],
                    "content": "先枚举子域"}
            return {"tool_calls": [], "content": "DONE"}

    proj = store.create_project("[测试] v048 约束闸门", "example.test", "跑完即删")
    fake = _ToolBackend("oneforall")
    saved = agent_mod.get_backend
    agent_mod.get_backend = lambda name=None: fake
    try:
        s = sessions.create(project=proj["id"])
        events: list[dict] = []

        async def consume():
            while True:
                ev = await s.events.get()
                events.append(ev)
                if ev.get("type") == "done":
                    return

        async def drive():
            t = asyncio.create_task(consume())
            await agent.run(s, TASK)
            await t

        asyncio.run(drive())
    finally:
        agent_mod.get_backend = saved

    check("任务文本里解析出了 bruteforce 禁令",
          "bruteforce" in (s.constraints or {}), str(s.constraints))

    steps = [st for st in s.steps if st.tool_alias == "oneforall"]
    check("oneforall 确实被尝试过（用例有效，不是空跑）", bool(steps),
          f"steps={[(x.tool_alias, x.status) for x in s.steps]}")
    if steps:
        st = steps[0]
        check("该步状态是 denied", st.status == "denied", st.status)
        check("拒绝理由来自任务级约束", "已声明禁用" in (st.output or ""),
              (st.output or "")[:120])
        check("拒绝理由**不是** scope 拦的（否则说明约束闸门是死的）",
              "不在授权白名单" not in (st.output or ""))
        check("同一步没有被当成成功执行",
              all(x.status != "done" for x in steps),
              str([x.status for x in steps]))
    check("发了 reasoning 说明拦截原因",
          any(e.get("type") == "reasoning" and "任务级约束" in str(e.get("data", ""))
              for e in events),
          str([e.get("type") for e in events])[:120])

    # ---- 落库：闸门依据必须持久化，否则 adopt 续聊后失效 ----
    row = store.get_session_row(s.id) or {}
    check("constraints 已落库", "bruteforce" in (row.get("constraints") or ""),
          str(row.get("constraints"))[:80])

    # ---- 提醒注入：模型每轮都该看到禁令（写在任务书开头挡不住长上下文） ----
    # 提醒是拼进 system 的**局部**变量（messages = [system+reminder] + history），
    # 不落 session.messages —— 所以要查「后端实际收到的那一份」。
    got = "\n".join(str(m.get("content", "")) for m in
                     (getattr(fake, "last_messages", None) or [])
                     if m.get("role") == "system")
    check("每轮提醒里带了禁令（模型真的看得到）",
          "本次任务已声明的禁令" in got and "不做字典爆破" in got,
          got[-160:] if got else "后端未收到 system 消息")

    store.delete_project(proj["id"])
    check("测试项目已清理", store.get_project(proj["id"]) is None)


def main() -> int:
    print("=" * 68)
    print("v048 优化回归：文档契约 / getattr 窄例外 / 任务级约束闸门")
    print("=" * 68)
    test_a_doc_contract()
    test_b_getattr()
    test_c_task_constraints()
    test_d_no_real_targets()
    test_e_gate_end_to_end()
    print("\n" + "=" * 68)
    print(f"结果：{PASS} 通过 / {FAIL} 失败")
    print("=" * 68)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
