# -*- coding: utf-8 -*-
"""v047 优化回归测试：py_exec 能力分档 + 交互式工具剔除 + 超时口径。

本文件覆盖 2026-09-22 discuz.vip 实战暴露的三类问题（每类都有现场证据）：

  A. **py_exec 一刀切 L3**（P0-1，价值最大的一项）
     `py_exec` 是万能工具，于是不论代码做什么都被判 L3（double_confirm，两轮人工确认）。
     侦察期几乎每个动作都要靠 Python —— 实测「抓首页 + 正则抽链接」也判 L3。
     操作者只有两条路：被几十次弹窗拖死（于是弃用），或闭眼连点（闸门变橡皮图章）。
     修法：静态能力分档，按**能力**而不是**通道**给等级。
        · 只读 + 无网络      → L0（自动）——语义就是 L0「只读 / 本地分析」
        · 只读 + 受控接口出网 → L2        ——能力与 httpreplay 等价，而它就是 L2
        · 其余 / 判不出      → L3        ——fail-closed，保持原状

  B. **交互式工具交给模型**（白烧一步 + 120 秒）
     某加密小工具是交互式菜单程序，非交互调用只打印菜单然后等 stdin，撞满
     `TOOL_IDLE_TIMEOUT` 才被终止；而它在 risk_grades.json 里是 **L0（自动执行）**，
     所以没有任何人工环节能提前拦住它。修法：标注 + 剔出模型可见清单 + 执行前拒绝。

  C. **超时口径散落且互相矛盾**
     py_exec 90s / 工具 idle 120s / 工具总时长 600s，三者关系从未被写明，
     表现为「py_exec 是推荐的探测通道，预算却比通用工具还紧」的设计倒挂。
     修法：统一说明 + `/api/health` 暴露 + startup 自检不变量。

  D. **目标串粘装饰字符**（本轮新发现，DB 里 5 个会话中招）
     `extract_target` 的 URL 正则不排除反引号/星号/全角括号，把
     `` `https://a.com/` `` 抓成 `https://a.com/` + 反引号；且这些脏串**能通过**
     `validate_target` 与 `_is_host_like`，一路流到执行层 → 请求打到 `/\\`` → 404
     → 模型得出「该路径不存在」的错误结论。**脏数据比报错更危险。**

统计行格式必须是 `结果：N 通过 / M 失败`（run_all_tests.py 的正则要求）。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import config, pyexec_grade, registry                  # noqa: E402
from app.agent import extract_target                            # noqa: E402

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


# ============================================================
def test_a_grading():
    """[A] 静态能力分档：三档判定 + 已知逃逸路径必须 fail-closed。"""
    print("\n[A] py_exec 静态能力分档（按能力而非通道定级）")
    g = pyexec_grade.grade

    # ---- 本地只读 → readonly_local ----
    for code, why in [
        ("import re\nprint(re.findall('a', 'aaa'))", "纯正则计算"),
        ("import json, base64\nprint(base64.b64encode(b'x'))", "纯编解码"),
        ("from srcagent import load_text\nprint(load_text('a.txt'))", "读会话目录文本"),
        ("from srcagent import load_bytes, file_md5\nprint(file_md5(load_bytes('a.bin')))",
         "受控字节读取（v045.2 新增，平台落盘是二进制）"),
        ("import srcagent\nprint([n for n in dir(srcagent) if not n.startswith('_')])",
         "内省受控 API 是正确行为，必须放行"),
    ]:
        r = g(code)
        check(f"本地只读判为 {pyexec_grade.TIER_LOCAL}：{why}",
              r.tier == pyexec_grade.TIER_LOCAL,
              f"实得 {r.tier}（{r.detail}）")

    # ---- 受控出网 → readonly_net ----
    for code, why in [
        ("from srcagent import safe_http_request\n"
         "print(safe_http_request('https://a.test/'))", "from-import 形态"),
        ("import srcagent\nprint(srcagent.safe_http_request('https://a.test/'))",
         "属性调用形态"),
        # v048：这里原本用 save_artifact —— 实测沙箱**从未导出**它（幽灵 API），
        # 已从白名单移除，故改用真正存在的 save_text 表达同一意图（受控落盘 → net 档）。
        ("from srcagent import save_text\nprint(save_text('a.txt','x'))",
         "受控落盘（有本地副作用）也按 net 档"),
    ]:
        r = g(code)
        check(f"受控出网判为 {pyexec_grade.TIER_NET}：{why}",
              r.tier == pyexec_grade.TIER_NET,
              f"实得 {r.tier}")

    # ---- 出网代码绝不能落到「本地只读」档（否则等于自动放行出网）----
    r = g("from srcagent import safe_http_request\nsafe_http_request('https://a.test/')")
    check("出网代码不会误判为本地只读（不会获得 auto）", r.tier != pyexec_grade.TIER_LOCAL)

    # ---- 已知逃逸路径：全部必须 opaque（fail-closed）----
    escapes = [
        ("import os\nos.system('id')", "直接 import os"),
        ("open('/etc/passwd').read()", "裸 open"),
        ("import subprocess\nsubprocess.run(['id'])", "子进程"),
        ("eval('1+1')", "eval"),
        ("getattr(__builtins__, 'ev'+'al')('1')", "getattr 拼名绕过"),
        ("import requests\nrequests.get('https://a.test')", "裸 HTTP 库"),
        ("import urllib.request\nurllib.request.urlopen('http://a.test')", "urllib.request"),
        ("import srcagent\nsrcagent._os.system('id')", "顺私有属性爬到沙箱内的 os"),
        ("import srcagent\nsrcagent._os.popen('id')", "同上（popen）"),
        ("print(().__class__.__bases__)", "经典沙箱逃逸链"),
        ("print(''.__class__.__mro__)", "同上（__mro__）"),
        ("print(__import__('o'+'s').system('id'))", "动态拼模块名"),
        ("print(__import__('re', globals()))", "带关键字参数的 __import__"),
        ("import importlib\nimportlib.import_module('os')", "动态导入"),
        ("print(THIS IS NOT PYTHON", "语法错误（判不出 → 不许降级）"),
        ("", "空代码"),
    ]
    bad = []
    for code, why in escapes:
        r = g(code)
        if r.tier != pyexec_grade.TIER_OPAQUE:
            bad.append(f"{why}→{r.tier}")
    check(f"{len(escapes)} 条已知逃逸路径全部 fail-closed", not bad, str(bad[:5]))

    # ---- 窄例外：字面量白名单模块的 __import__ 不是逃逸（实测误拒过一次）----
    r = g("print(__import__('json').dumps({'a': 1}))")
    check("字面量白名单模块的 __import__ 被放行（实测踩过的误拒）",
          r.tier == pyexec_grade.TIER_LOCAL, f"实得 {r.tier}")
    r = g("print(__import__('subprocess').run(['id']))")
    check("非白名单模块的 __import__ 仍拒绝", r.tier == pyexec_grade.TIER_OPAQUE)

    # ---- 文件权限：判定器不得碰网络/文件（纯 AST）----
    # v048：这条原先用「DENIED_ROOTS 之前不许出现 socket/subprocess 字样」当代理指标，
    # 而新增的 DENIED_ATTR_NAMES 里正好有 "socket"/"system" 这些**属性名** —— 假红。
    # 代理指标不可靠，直接查真正的导入表。
    src = read("app/pyexec_grade.py")
    imports = set()
    for ln in src.splitlines():
        m = re.match(r"\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))", ln)
        if m:
            for part in (m.group(1) or m.group(2) or "").split(","):
                imports.add(part.strip().split(".")[0].split(" as ")[0].strip())
    check("判定器只做静态分析（导入表里没有网络/进程/文件模块）",
          "ast" in imports
          and not (imports & {"socket", "subprocess", "os", "shutil", "pathlib",
                              "httpx", "requests", "urllib"}),
          f"实得导入 {sorted(imports)}")


def test_b_apply_to():
    """[B] apply_to：只降级不升级 + double_confirm 同步 + 开关 + 留痕。"""
    print("\n[B] 分档结果套用到风险等级（不可让步的三条纪律）")
    reg = registry.ToolRegistry().load()
    base = reg.risk_of("py_exec")
    check("py_exec 工具默认等级仍是 L3（分档不改静态定级）",
          base and base.get("level") == "L3", str(base))
    check("py_exec 默认 double_confirm=True", base.get("double_confirm") is True)

    # ---- 本地只读：L3 → L0 ----
    nr, note = pyexec_grade.apply_to("import re\nprint(re.findall('a','aaa'))", base)
    check("本地只读脚本 L3 → L0", nr.get("level") == "L0", str(nr.get("level")))
    check("降级后 auto=True（不再弹确认）", nr.get("auto") is True)
    check("降级后 double_confirm 同步为 False（否则前后端会不一致）",
          nr.get("double_confirm") is False)
    check("降级必须留痕（note 非空，操作者要知道为何没问）", bool(note))
    check("留痕写明原定级", "L3" in note)

    # ---- 受控出网：L3 → L2 ----
    nr2, note2 = pyexec_grade.apply_to(
        "from srcagent import safe_http_request\nsafe_http_request('https://a.test/')", base)
    check("受控出网脚本 L3 → L2", nr2.get("level") == "L2", str(nr2.get("level")))
    check("L2 仍需确认（auto=False）", nr2.get("auto") is False)
    check("L2 不做二次确认（double_confirm=False）", nr2.get("double_confirm") is False)

    # ---- opaque：完全不降级 ----
    nr3, note3 = pyexec_grade.apply_to("import os\nos.system('id')", base)
    check("不可判定代码保持 L3（fail-closed）", nr3.get("level") == "L3")
    check("未降级时不产生留痕（避免刷屏）", note3 == "")
    check("未降级时原 dict 未被改写", nr3 is base or nr3.get("reason") == base.get("reason"))

    # ---- 纪律 1：只降级不升级 ----
    low = {"level": "L0", "name": "只读 / 本地分析", "auto": True,
           "double_confirm": False, "reason": "x", "tool": "y"}
    nr4, note4 = pyexec_grade.apply_to(
        "from srcagent import safe_http_request\nsafe_http_request('https://a.test/')", low)
    check("基线 L0 + 出网代码 → 保持 L0（不会被分档抬到 L2）",
          nr4.get("level") == "L0", str(nr4.get("level")))
    check("只降级不升级：该情形不留痕", note4 == "")

    # ---- 纪律 2：开关 ----
    saved = config.PY_EXEC_GRADE_ENABLED
    try:
        config.PY_EXEC_GRADE_ENABLED = False
        nr5, note5 = pyexec_grade.apply_to("import re\nprint(1)", base)
        check("开关关闭时完全不降级（操作者要绝对保守时的出口）",
              nr5.get("level") == "L3" and note5 == "")
    finally:
        config.PY_EXEC_GRADE_ENABLED = saved

    # ---- 纪律 3：档位映射必须指向合法等级 ----
    for lv in (config.PY_EXEC_GRADE_LEVEL_LOCAL, config.PY_EXEC_GRADE_LEVEL_NET):
        check(f"档位映射 {lv} 是合法风险等级", lv in config.RISK_LEVELS)
    check("本地只读档默认对齐 L0（「只读 / 本地分析」）",
          config.PY_EXEC_GRADE_LEVEL_LOCAL == "L0")
    check("受控出网档默认对齐 L2（与 httpreplay 同能力同等级）",
          config.PY_EXEC_GRADE_LEVEL_NET == "L2")


def test_c_wiring():
    """[C] 接线位置：分档必须在 Step 构造之前；交互式拦截必须在闸门之前。"""
    print("\n[C] 接线位置（位置错了就出现「库里 L3 / 实际按 L2 放行」的分叉）")
    src = read("app/agent.py")

    i_grade = src.find("pyexec_grade.apply_to")
    i_step = src.find("step = Step(", i_grade if i_grade > 0 else 0)
    check("调用了分档器", i_grade > 0)
    check("分档在 Step 构造之前（Step.risk 会落库，改晚了库与行为不一致）",
          0 < i_grade < i_step, f"grade@{i_grade} step@{i_step}")

    i_intr = src.find('getattr(tool, "interactive", False)')
    i_gate = src.find("# ---- 风险闸门 ----")
    check("交互式工具在执行前被拦截", i_intr > 0)
    check("交互式拦截在风险闸门之前（否则会先弹确认再卡 120 秒）",
          0 < i_intr < i_gate, f"interactive@{i_intr} gate@{i_gate}")

    # 分档降级必须发事件（留痕），否则操作者只看到「这次没问我」而不知原因
    check("降级时发 reasoning 事件留痕", "grade_note" in src and '"reasoning"' in src)

    # 导入
    check("agent.py 已导入 pyexec_grade", "from . import pyexec_grade" in src)


def test_d_interactive():
    """[D] 交互式工具：不进模型清单，但精确点名给出明确拒绝。"""
    print("\n[D] 交互式工具不交给模型（白烧一步 + 120 秒的根治）")
    reg = registry.ToolRegistry().load()
    its = reg.interactive_tools()
    check("存在被标记的交互式工具", len(its) >= 1, f"实得 {len(its)}")

    aliases = {t.alias for t in its}
    check("实测中招的加密小工具已被标记", "md5_tool" in aliases, str(sorted(aliases)))

    for t in its:
        check(f"{t.alias} 有 interactive_reason（说明为何标记）", bool(t.interactive_reason))
        check(f"{t.alias} 不在模型可见清单（usable_scriptable）",
              all(x.alias != t.alias for x in reg.usable_scriptable()))
        check(f"{t.alias} 不在 build_schemas（模型看不到 schema）",
              all(s["function"]["name"] != t.alias for s in reg.build_schemas()))

    # 精确点名仍要能取到 —— 这样模型点名时能给「别用它、改用 X」而不是「工具不存在」
    t = reg.get_by_alias("md5_tool")
    check("精确点名仍能取到该工具（用于给出明确拒绝而非「不存在」）",
          t is not None and getattr(t, "interactive", False) is True)
    check("交互式工具被剔出清单后总数减少（stats.interactive 可见）",
          reg.stats().get("interactive", 0) >= 1, str(reg.stats()))

    ov = json.loads(read("data/tool_overrides.json"))
    check("overrides 里落盘了 interactive 标注（配置即文档）",
          bool((ov.get("md5_tool") or {}).get("interactive")))
    check("overrides 的 caveat 指向替代做法（py_exec + hashlib）",
          "hashlib" in ((ov.get("md5_tool") or {}).get("caveat") or ""))

    # 启动日志把「剔了几个」记下来：否则现象是「模型变笨了」
    main_src = read("app/main.py")
    check("startup 记录被剔除的交互式工具数量", "interactive_tools()" in main_src)


def test_e_timeouts():
    """[E] 超时口径：暴露 + 不变量自检。"""
    print("\n[E] 超时口径（把「配错也看不出来」变成一条告警）")
    prof = config.timeout_profile()
    ch = prof.get("channels") or {}
    check("口径表含 external_tool 通道", "external_tool" in ch)
    check("口径表含 py_exec 通道", "py_exec" in ch)
    check("外部工具有总时长与 idle 两个上限",
          ch["external_tool"].get("total_cap") and ch["external_tool"].get("idle_cap"))
    check("py_exec 明确标注**没有** idle 检测（差异写明，而非假装统一）",
          ch["py_exec"].get("idle_cap") is None)
    check("口径表给出每个值的来源（不必翻源码）",
          "" in ch["external_tool"].get("total_cap_src", "")
          or "TOOL_TIMEOUT" in ch["external_tool"].get("total_cap_src", ""))
    check("不变量 idle < total 成立", prof.get("idle_below_total") is True,
          f"idle={config.TOOL_IDLE_TIMEOUT} total={config.TOOL_TIMEOUT}")
    check("口径表暴露分档开关与档位映射",
          prof.get("py_exec_grade_enabled") is True
          and prof["py_exec_grade_levels"]["opaque"] == "L3")

    # 不变量自检必须**真能**发现配错（否则它是安慰剂）
    saved_idle, saved_total = config.TOOL_IDLE_TIMEOUT, config.TOOL_TIMEOUT
    try:
        config.TOOL_IDLE_TIMEOUT = 999
        config.TOOL_TIMEOUT = 10
        ws = config.timeout_warnings()
        check("idle >= total 时自检报出口径异常（否则 idle 是死代码）",
              any("口径异常" in w and "TOOL_IDLE_TIMEOUT" in w for w in ws), str(ws))
    finally:
        config.TOOL_IDLE_TIMEOUT, config.TOOL_TIMEOUT = saved_idle, saved_total

    saved_lv = config.PY_EXEC_GRADE_LEVEL_LOCAL
    try:
        config.PY_EXEC_GRADE_LEVEL_LOCAL = "L9"
        ws = config.timeout_warnings()
        check("档位映射配成非法等级时自检报警",
              any("PY_EXEC_GRADE_LEVEL_LOCAL" in w for w in ws), str(ws))
    finally:
        config.PY_EXEC_GRADE_LEVEL_LOCAL = saved_lv
    check("正常配置下无告警", config.timeout_warnings() == [])

    # py_exec 预算不再低于通用工具的 idle 上限（v047 修的设计倒挂）
    check("py_exec 总时长 ≥ 外部工具 idle 上限（修掉「推荐通道预算更紧」的倒挂）",
          config.PY_EXEC_TIMEOUT >= config.TOOL_IDLE_TIMEOUT,
          f"py_exec={config.PY_EXEC_TIMEOUT} idle={config.TOOL_IDLE_TIMEOUT}")
    check("放宽的只是墙钟，不放宽流量：单请求上限未变",
          config.PY_EXEC_REQUEST_TIMEOUT == 25.0)

    # health 暴露
    check("/api/health 暴露 timeouts 段", '"timeouts": config.timeout_profile()' in read("app/main.py"))
    check("startup 会跑口径自检", "config.timeout_warnings()" in read("app/main.py"))


def test_f_extract_target():
    """[F] 目标串不得粘装饰字符（脏数据比报错更危险）。"""
    print("\n[F] 目标提取：剥装饰字符，但不截断合法 URL")
    cases = [
        ("对 `https://www.discuz.vip/` 进行测试", "https://www.discuz.vip/"),
        ("**https://www.discuz.vip/**", "https://www.discuz.vip/"),
        ("与 `https://a.test/hxqhcms/`（apex 记录）", "https://a.test/hxqhcms/"),
        ("【https://a.test/】", "https://a.test/"),
        ("<https://a.test/x>", "https://a.test/x"),
        ("见 [详情](https://a.test/detail/)", "https://a.test/detail/"),
        ("看 https://a.test/ 。", "https://a.test/"),
        ("目标：`a.test`", "a.test"),
        ("1.10.0.103", "1.10.0.103"),
        # 合法 URL 字符不能被当成装饰剥掉（第一版就错在这里）
        ("用 https://a.test/p(1) 测", "https://a.test/p(1)"),
        ("https://a.test/p?a=1&b=2#frag", "https://a.test/p?a=1&b=2#frag"),
        ("host: https://a.test:8443/path", "https://a.test:8443/path"),
    ]
    bad = []
    for src, want in cases:
        got = extract_target(src)
        if got != want:
            bad.append(f"{src!r}→{got!r}(期望{want!r})")
    check(f"{len(cases)} 条目标提取用例全部正确", not bad, "; ".join(bad[:4]))

    # 只有装饰字符、不成形时不得返回半截串
    check("不成形的目标返回空串（不返回 'https://'）", extract_target("https://`（得到") == "")

    # 回归：历史上中招的 5 个会话形态，现在都不应再复现
    for raw in ["`https://a.test/`", "**https://a.test/**", "`https://a.test/p`（apex"]:
        got = extract_target(raw)
        check(f"历史脏形态已消除：{raw!r}",
              got == "" or not got.endswith(("`", "*", "（")), f"实得 {got!r}")

    # 源码侧：装饰字符集必须写清楚「为什么 ASCII 括号不在内」
    asrc = read("app/agent.py")
    check("源码写明 ASCII 括号不可当终止符（否则会截断 /p(1) 这类合法路径）",
          "不放进终止符集" in asrc or "ASCII 的 `(` `)` 不放进终止符" in asrc)


def test_g_no_real_targets():
    """[G] 本版新增/改动文件不得含真实靶标（继承 v046 的词干口径）。"""
    print("\n[G] 本版改动文件防泄露（与 test_045 的 [H] 同口径，此处只查本版文件）")
    scope_file = REPO / "data" / "scope.json"
    if not scope_file.exists():
        check("scope.json 不存在 → 跳过（非本机环境）", True)
        return
    try:
        domains = json.loads(scope_file.read_text(encoding="utf-8")).get("domains") or []
    except Exception as e:                                       # noqa: BLE001
        check("scope.json 可解析", False, str(e))
        return
    allow = {"discuz"}          # 公开产品名，与 test_045 的 _STEM_ALLOW 一致
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
    files = ["app/pyexec_grade.py", "app/config.py", "app/registry.py",
             "app/agent.py", "app/main.py", "data/tool_overrides.json",
             "test_047_fixes.py"]
    hits = []
    for rel in files:
        text = read(rel).lower()
        for s in stems:
            if s in text:
                hits.append(f"{rel}⊃{s}")
    check(f"本版 7 个文件不含靶标词干（查了 {len(stems)} 个）", not hits, str(hits))
    check("测试文件里的示例域名用 RFC 2606 保留 TLD `.test`",
          ".test" in read("test_047_fixes.py"))


def test_h_health_latency():
    """[H] 健康检查不得被可选依赖拖慢（否则会静默跳过 E2E + 前端卡 8 秒）。

    现场证据（2026-09-23 实测）：Burp 没开时 `/api/health` 要 **8.07s**
    （MCP 的 SSE 探测等满 `_sse_probe_timeout=8.0`）。而回归 harness 用它识别
    「8770 上是不是本项目的服务」，超时只给了 **2.0s** → 判定失败 →
    打印「端口被别的程序占用」→ **静默跳过两个端到端套件**，
    汇总行却写「合计 N 项通过 / 0 项失败」。

    **跳过被读成绿灯**，与 v046 那个 `[H]` 假 PASS 是同一类问题：
    不是防线被绕过，而是防线根本没跑，却报告「检查通过」。

    修法三层（缺一层都不够）：
      1. 端口没人监听 → `probe()` 立刻返回（最常见的「Burp 没开」路径，8s → ~0ms）；
      2. `/api/health` 的 MCP 段加 TTL 缓存（前端一次开页会连调两次）；
      3. harness 的探测超时从 2s 提到 30s 兜底。
    """
    print("\n[H] 健康检查延迟：不得由可选依赖决定")
    mc = read("app/mcp_client.py")
    check("MCP 探测有 TCP 预检（端口不通则立刻返回，不等满 SSE 超时）",
          "_tcp_reachable" in mc and "端口未监听" in mc)
    check("TCP 预检在 loopback 守卫之后（远程拒绝理由更该优先报）",
          mc.find("_guard_loopback()") < mc.find("_tcp_reachable()", mc.find("async def probe")))
    check("mcp_client 已导入 socket", re.search(r"^import socket$", mc, re.M) is not None)

    mn = read("app/main.py")
    check("health 的 MCP 段带 TTL 缓存", "_mcp_health_cache" in mn
          and "MCP_HEALTH_TTL" in mn)
    check("缓存回传 cached_seconds（不把缓存伪装成实时）",
          "cached_seconds" in mn)
    check("config 暴露 MCP_HEALTH_TTL", hasattr(config, "MCP_HEALTH_TTL"))
    check("MCP_HEALTH_TTL 是有限正数（缓存不能等于永久）",
          0 < config.MCP_HEALTH_TTL <= 300, f"实得 {config.MCP_HEALTH_TTL}")

    rt = read("run_all_tests.py")
    check("harness 探测超时不再过小（2s 会必失败）",
          "PROBE_TIMEOUT = 30.0" in rt)
    check("probe_service 用 PROBE_TIMEOUT 作默认",
          "timeout: float = PROBE_TIMEOUT" in rt)
    check("回环探测绕开环境代理", "ProxyHandler({})" in rt)
    check("跳过 E2E 时说明原因（否则跳过会被汇总行读成绿灯）",
          "将跳过端到端测试" in rt and "拖慢" in rt)
    check("注释里没有留下错误的「代理导致探测失败」结论",
          "这不是" in rt and "真因见" in rt)


def main() -> int:
    print("=" * 68)
    print("v047 优化回归：py_exec 能力分档 / 交互式工具 / 超时口径 / 目标提取")
    print("=" * 68)
    test_a_grading()
    test_b_apply_to()
    test_c_wiring()
    test_d_interactive()
    test_e_timeouts()
    test_f_extract_target()
    test_g_no_real_targets()
    test_h_health_latency()
    print("\n" + "=" * 68)
    print(f"结果：{PASS} 通过 / {FAIL} 失败")
    print("=" * 68)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
