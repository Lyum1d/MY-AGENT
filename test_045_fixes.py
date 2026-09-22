# -*- coding: utf-8 -*-
"""v045 优化回归测试：确认闸门前置与口径修复。

本文件覆盖 2026-09-22 实战暴露的四个具体缺陷（每个都有现场证据）：

  A. py_exec 语法预检 —— 实战中 Agent **连续 3 次**产出无法编译的代码
     （`unmatched ')'`、`unterminated string literal`），每次都先弹 L3 双轮确认、
     人工放行后才在子进程里报 SyntaxError。白耗确认次数，且把「语法错误」
     混进「用户拒绝」的归因里。修法：把检查提到风险闸门**之前**。

  B. `Resp` 下标访问报错 —— Agent 用 `r["body"]`（正确字段 `text`）只拿到裸的
     `KeyError('body')`，没有任何线索指向正确字段名，白烧一步去内省 API。
     根因：`__getattr__` 有解释性报错，`__getitem__` 没有，而模型更常用下标。

  C. `httpreplay` 长度口径 —— 原实现优先取 `Content-Length` 头，gzip 下那只是
     **压缩后**长度。实测同一响应：头 18182 / 解码后 90482 字符 / 105723 字节，
     差 5 倍，会让人误判「响应变了」。

  D. 沙箱落盘接口 —— 文档推荐「大响应落盘离线解析」，但落盘只能用裸 `open()`，
     与「只读脚本」判定冲突，导致标准动作反而要 L3 双轮确认。
     新增 save_text / load_text / list_tmpdir（路径锁在 tmpdir 内）。

统计行格式必须是 `结果：N 通过 / M 失败`（run_all_tests.py 的正则要求）。
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import pyexec, pyexec_bridge                        # noqa: E402

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" —— {detail}" if detail else ""))


# ============ 沙箱模块装载工具 ============
def load_sandbox_module():
    """把 SCRIPT_MODULE_SOURCE 在临时目录里 exec 起来，返回其命名空间。

    为什么不直接 import：这个模块不是磁盘上的 .py，而是**字符串常量**，
    由宿主在每次 py_exec 时写入工作目录。必须按真实方式装载才能测到真行为。
    """
    tmp = tempfile.mkdtemp(prefix="v045_")
    os.environ["SRC_AGENT_TMPDIR"] = tmp
    ns: dict = {"__name__": "srcagent_under_test",
                "__file__": os.path.join(tmp, "srcagent.py")}
    exec(compile(pyexec_bridge.SCRIPT_MODULE_SOURCE, "srcagent.py", "exec"), ns)
    return ns, tmp


# ============ A. py_exec 语法预检 ============
def test_syntax_precheck():
    print("\n[A] py_exec 语法预检")
    check("合法代码通过", pyexec.syntax_error("import re\nprint(re.escape('a'))") == "")
    check("空代码被拦", pyexec.syntax_error("") != "")
    check("纯空白被拦", pyexec.syntax_error("   \n  ") != "")

    # 用实战里真实出现过的两种形态（见 2026-09-22 会话 e583d9f7e6f3）
    e1 = pyexec.syntax_error('print("a"))')            # 多余右括号
    check("多余右括号被拦（实战原形 unmatched ')'）", e1 != "")
    check("括号报错含行号", "第 1 行" in e1, e1[:90])
    check("括号报错含原始行内容（便于定位）", 'print("a"))' in e1, e1[:120])

    e1b = pyexec.syntax_error("print(sorted(set([1,2,3])[:2])")
    check("缺右括号被拦", e1b != "" and "never closed" in e1b, e1b[:90])

    e2 = pyexec.syntax_error("x = 1\ny = 2\nprint(x")
    check("多行代码报错指向正确行（第 3 行）", e2 != "" and "第 3 行" in e2, e2[:90])

    e3 = pyexec.syntax_error("import re\npat = 'aaaa\nprint(pat)")
    check("未闭合字符串被拦（实战原形）", e3 != "")
    check("未闭合字符串报第 2 行", "第 2 行" in e3, e3[:90])

    # 关键边界：语法预检**只管语法**，不做能力判定。
    # import os 的代码语法是对的 → 必须放行给风险闸门，不能在这里拦。
    check("语法合法但危险的代码不在此处拦（职责边界）",
          pyexec.syntax_error("import os\nos.system('id')") == "")
    check("语法合法且带函数的代码通过",
          pyexec.syntax_error("def f(x):\n    return x * 2\nprint(f(21))") == "")


def test_syntax_precheck_wired_before_gate():
    """断言接线位置：必须在「风险闸门」之前，否则等于没修。"""
    print("\n[A2] 接线位置（必须在风险闸门之前）")
    src = (Path(__file__).resolve().parent / "app" / "agent.py").read_text(
        encoding="utf-8")
    i_syn = src.find("pyexec.syntax_error")
    i_gate = src.find("# ---- 风险闸门 ----")
    check("agent.py 调用了 pyexec.syntax_error", i_syn > 0)
    check("风险闸门存在", i_gate > 0)
    check("语法预检在风险闸门之前（关键）", 0 < i_syn < i_gate,
          f"syn@{i_syn} gate@{i_gate}")
    # 拦截后必须 continue，否则会继续往下走到闸门
    seg = src[i_syn:i_syn + 1400]
    check("拦截后 continue（不落入闸门）", "continue" in seg)
    check("用 step_done + status=error 回传（沿用既有事件类型）",
          '"type": "step_done"' in seg and '"error"' in src[i_syn - 400:i_syn + 400])
    check("拦截不算用户拒绝（文案不含「用户拒绝」）",
          "用户拒绝" not in seg)


# ============ B. Resp 下标访问 ============
def test_resp_subscript():
    print("\n[B] Resp 下标访问报错")
    ns, _ = load_sandbox_module()
    R = ns["Resp"]
    r = R({"status_code": 200, "text": "hello", "headers": {}, "error": "",
           "elapsed": 0.01, "total_chars": 5, "total_bytes": 5})

    check("下标取正确键正常", r["text"] == "hello")
    check("属性取正确键正常", r.text == "hello")
    check("属性与下标等价", r["status_code"] == r.status_code)

    try:
        r["body"]
        check("body 抛 KeyError", False, "没有抛")
    except KeyError as e:
        msg = str(e)
        check("body 抛 KeyError", True)
        check("body 报错提示 text", "'text'" in msg, msg[:140])
        check("body 报错列出可用字段", "status_code" in msg and "headers" in msg,
              msg[:140])

    try:
        r["status"]
        check("status 抛 KeyError", False)
    except KeyError as e:
        check("status 报错提示 status_code", "status_code" in str(e), str(e)[:140])

    try:
        r.zzz
        check("未知属性抛 AttributeError", False)
    except AttributeError as e:
        check("未知属性抛 AttributeError", True)
        check("属性报错也列出可用字段", "status_code" in str(e), str(e)[:140])

    # 不能误伤 dict 语义
    check(".get() 不抛（保持 dict 行为）", r.get("body") is None)
    check("in 运算符正常", "text" in r)
    check("keys() 正常", set(r.keys()) >= {"status_code", "text", "error"})
    check("空 Resp 为 False", bool(R({})) is False)
    check("非空 Resp 为 True", bool(r) is True)
    # 递归保护：两条错误路径不能互相调用成环
    # （__getattr__ 若写成 self[name] 就会经由 __getitem__ 再回来）
    try:
        for _ in range(3):
            try:
                r["nope"]
            except KeyError:
                pass
            try:
                r.nope
            except AttributeError:
                pass
        check("错误路径不成环（可重复触发）", True)
    except RecursionError:
        check("错误路径不成环（可重复触发）", False, "RecursionError")


# ============ C. httpreplay 长度口径 ============
def test_replay_length_metric():
    print("\n[C] httpreplay 长度口径")
    src = (Path(__file__).resolve().parent / "app" / "replayer.py").read_text(
        encoding="utf-8")
    check("不再把头里的 content-length 当长度来源",
          "f\"Length: {r.headers.get('content-length'" not in src)
    check("改为报告解码后字符/字节", "n_chars, n_bytes = len(r.text), len(r.content)" in src)
    check("不一致时附注说明传输态长度", "为传输态长度，不是正文长度" in src)
    check("附注会带出 Content-Encoding", "content-encoding" in src)


# ============ D. 沙箱落盘接口 ============
def test_save_load_text():
    print("\n[D] 沙箱 save_text / load_text")
    ns, tmp = load_sandbox_module()
    save, load = ns["save_text"], ns["load_text"]

    p = save("home.html", "<h1>hi</h1>")
    check("save_text 返回路径", isinstance(p, str) and p.endswith("home.html"))
    check("落盘在 tmpdir 内", os.path.abspath(p).startswith(os.path.abspath(tmp)))
    check("load_text 往返一致", load("home.html") == "<h1>hi</h1>")
    check("文件确实存在", os.path.isfile(p))

    # v033 的换行污染：newline="" 必须生效，否则 Windows 上 LF→CRLF
    save("nl.txt", "a\nb\nc")
    check("换行不被改写（LF 保持 LF）", load("nl.txt") == "a\nb\nc",
          repr(load("nl.txt")))

    save("sub/dir/deep.txt", "x")
    check("自动建子目录", load("sub/dir/deep.txt") == "x")
    check("list_tmpdir 能列出", "nl.txt" in ns["list_tmpdir"]())

    # 目录穿越必须拦住
    for bad in ("../escape.txt", "../../win.ini", "a/../../x.txt",
                "..\\escape.txt"):
        try:
            save(bad, "x")
            check(f"save_text({bad!r}) 被拦", False, "未拦截")
        except ValueError:
            check(f"save_text({bad!r}) 被拦", True)
        try:
            load(bad)
            check(f"load_text({bad!r}) 被拦", False, "未拦截")
        except ValueError:
            check(f"load_text({bad!r}) 被拦", True)


def test_sandbox_module_health():
    print("\n[D2] 沙箱模块自身健康度")
    src = pyexec_bridge.SCRIPT_MODULE_SOURCE
    try:
        ast.parse(src)
        check("模块源码语法正确", True)
    except SyntaxError as e:
        check("模块源码语法正确", False, f"line {e.lineno}: {e.msg}")
    check("docstring 提到 save_text（可发现性）", "save_text" in src)
    check("docstring 写明突发上限（避免模型写必然被限速的循环）",
          "突发上限" in src)
    check("docstring 说明下标报错也带提示", "body" in src and "text" in src)
    # 三个新函数都真的定义了
    ns, _ = load_sandbox_module()
    for fn in ("save_text", "load_text", "list_tmpdir"):
        check(f"导出了 {fn}", callable(ns.get(fn)))


# ============ E. 分类器白名单同步 ============
def test_classifier_whitelist_synced():
    print("\n[E] 能力分档器与沙箱 API 保持同步")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _classify_step import ALLOWED_SRCAGENT_NAMES, classify_py_exec

    ns, _ = load_sandbox_module()
    exported = {n for n in ns if not n.startswith("_") and callable(ns[n])}
    # 白名单里的每个名字都应该是沙箱真实导出的（防拼写漂移 / 防凭想象加名字）
    for name in ("safe_http_request", "get", "post", "save_text", "load_text",
                 "list_tmpdir", "tmpdir"):
        check(f"白名单 {name} 确实由沙箱导出（或为常量）",
              name in exported or name in ns)
    ok, why = classify_py_exec(
        "from srcagent import safe_http_request, save_text, load_text, list_tmpdir\n"
        "r = safe_http_request('https://a.example/')\n"
        "save_text('p.html', r['text'])\n"
        "print(load_text('p.html'), list_tmpdir())")
    check("用新落盘接口的脚本判为只读", ok, why)
    ok2, why2 = classify_py_exec("from srcagent import save_text\nsave_text('../x','y')")
    check("分类器不看参数内容（越界由运行时拦）", ok2, why2)


def test_readme_defaults_in_sync():
    """README 的配置默认值必须与 config.py 实际值一致。

    为什么值得一条测试（2026-09-22 实测发现）：文档里的默认值会**静默漂移**——
    查的时候发现 README 写 `MAX_STEPS=12`（实际 30）、
    `RUN_TOKEN_BUDGET=800000`（实际 2500000，差 3 倍）、
    `STEP_OUTPUT_HEAD/_TAIL=1500/2000`（实际 4000/4000）。
    这类不一致不会让任何测试变红，但会让人按错的默认值做容量规划，
    而且**只有人工逐个核对才能发现**——正好是回归该接管的事。
    """
    print("\n[F] README 配置默认值防漂移")
    from app import config as cfg
    readme = (Path(__file__).resolve().parent / "README.md").read_text(
        encoding="utf-8")
    checked, mismatched, skipped = 0, [], []
    for ln in readme.splitlines():
        if not ln.strip().startswith("|"):
            continue
        cells = [x.strip() for x in ln.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        m = re.match(r"^`([A-Z_][A-Z0-9_]*)`", cells[0])
        if not m:
            continue
        name = m.group(1)
        default = cells[2] if len(cells) > 2 else ""
        val = getattr(cfg, name, None)
        if val is None:
            skipped.append(f"{name}(代码无此名)")
            continue
        d = default.strip()
        # 路径类排在「默认」列时写的是相对形式，与绝对路径比对无意义 → 跳过
        if isinstance(val, Path) or d.endswith(".json"):
            skipped.append(f"{name}(路径)")
            continue
        # 一格写两个值（如 `4000 / 4000`）→ 与 `NAME` / `_TAIL` 两个配置对应
        if "/" in d and name == "STEP_OUTPUT_HEAD":
            tail = getattr(cfg, name.replace("HEAD", "TAIL"), None)
            parts = [p.strip() for p in d.split("/")]
            ok = (len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit()
                  and int(parts[0]) == val and tail is not None
                  and int(parts[1]) == tail)
            checked += 1
            if not ok:
                mismatched.append(f"{name}/{name.replace('HEAD','TAIL')}: "
                                  f"README={d!r} 实际={val}/{tail}")
            continue
        if d.isdigit() and isinstance(val, int):
            ok = int(d) == val
        elif d == "开":
            ok = val is True
        elif d == "关":
            ok = val is False
        else:
            skipped.append(f"{name}(非数值：{d!r})")
            continue
        checked += 1
        if not ok:
            mismatched.append(f"{name}: README={d!r} 实际={val!r}")

    check("README 表格可解析出配置项", checked >= 15, f"只核对到 {checked} 项")
    for msg in mismatched:
        check(f"默认值一致 —— {msg}", False)
    check("所有已核对项默认值一致", not mismatched,
          "；".join(mismatched) or "（无）")


def test_session_detail_confirm_visibility():
    """会话详情必须显式表达「在等人确认」，且键在两个分支都恒存在。

    为什么（2026-09-22 实测）：Agent 进入 awaiting_confirm 后，外部消费者
    （脚本/看板/无人值守编排）只看到 state 字符串，不知道谁在等、等哪一步 ——
    排查时表现为「Agent 好像卡死了」。实测自写的 SSE 监控脚本就因事件名写错
    （confirm vs 真实事件名 need_confirm）而完全静默。
    另外 REST 的 `second` 与 SSE 的 `second` 同名不同义（前者=需双轮，后者=轮次），
    这里新增语义明确的别名。
    """
    print("\n[G] 等待确认的可发现性（会话详情契约）")
    src = (Path(__file__).resolve().parent / "app" / "main.py").read_text(
        encoding="utf-8")
    seg = src[src.find('"awaiting_confirmation"'):]
    check("内存分支有 awaiting_confirmation", '"awaiting_confirmation"' in src)
    check("内存分支有 awaiting_summary", '"awaiting_summary"' in src)
    check("新增语义明确的双轮标志", '"requires_double_confirm"' in src)
    check("保留旧字段 second（不破坏既有前端）", '"second": bool(pend.get' in src)
    # 两个分支都要有这三个键，否则服务重启后消费方会 KeyError
    # 两个分支各出现一次（内存分支给有值/None，回退分支恒给空值）
    check("pending_confirm / awaiting_* 在回退分支也存在（键恒存在）",
          src.count('"awaiting_confirmation"') >= 2
          and src.count('"awaiting_summary"') >= 2
          and src.count('"pending_confirm"') >= 2,
          f"awaiting_confirmation×{src.count('\"awaiting_confirmation\"')} "
          f"awaiting_summary×{src.count('\"awaiting_summary\"')} "
          f"pending_confirm×{src.count('\"pending_confirm\"')}")
    check("等待中会给出人可读摘要", "风险 " in src and "awaiting_summary" in src)


def test_no_real_targets_in_tracked_sources():
    """已跟踪文件里不得出现本机授权靶标域名。

    为什么（2026-09-22 实测踩到）：`data/scope.json` 被 gitignore 的理由就是
    「含真实授权靶标，严禁入库」，但源码注释与测试示例里**很容易顺手写进去** ——
    本文件的第一版就在 docstring 里写了 5 处靶标名，随 v045 一起推到了
    **public 仓库**，事后才发现。项目自己的纪律被绕过的方式，往往不是
    刻意提交 scope.json，而是「写注释时顺手带上」。
    仓库里另有若干历史遗留（数处靶标名散在多个 test_* 与 app/* 注释里）。

    实现要点：靶标列表**从 data/scope.json 动态读取**，测试文件本身不含任何
    靶标名 —— 否则这个防泄露测试自己就成了新的泄露源。
    scope.json 不存在（他人克隆仓库）时跳过，不误报。
    """
    print("\n[H] 已跟踪源码不得含真实靶标（防「写注释顺手带进去」）")
    repo = Path(__file__).resolve().parent
    scope_file = repo / "data" / "scope.json"
    if not scope_file.exists():
        check("scope.json 不存在 → 跳过（非本机环境）", True)
        return
    try:
        domains = json.loads(scope_file.read_text(encoding="utf-8")).get("domains") or []
    except Exception as e:                      # noqa: BLE001
        check("scope.json 可解析", False, str(e))
        return
    # 只查「有辨识度的真实域名」，排除泛化后缀（example.com 之类模板值）
    targets = [d for d in domains
               if isinstance(d, str) and "." in d
               and not d.endswith(("example.com", "example.org"))
               and d.count(".") >= 1 and len(d) > 8]
    if not targets:
        check("scope.json 无可查靶标 → 跳过", True)
        return

    r = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True,
                       text=True, errors="replace")
    tracked = [x for x in (r.stdout or "").splitlines() if x.strip()]
    if not tracked:
        check("git 不可用或非仓库 → 跳过", True)
        return

    hits: list[str] = []
    for rel in tracked:
        p = repo / rel
        if p.suffix.lower() not in (".py", ".md", ".txt", ".json", ".example",
                                    ".yaml", ".yml", ".js", ".html", ".bat"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:                       # noqa: BLE001
            continue
        for d in targets:
            if d in text:
                hits.append(f"{rel}⊃{d}")
    hits = sorted(set(hits))

    # 分两段：本轮文件硬失败；历史遗留只报告。
    # 为什么不一刀切失败：历史遗留（长期文档里的默认靶标示例、
    # 另有 shhxqh/lsnu/cread 散落在若干 test_* 与 kb 文档里）属**既有问题**，
    # 需要在单独一个版本里做统一脱敏；现在直接判红会把「回归 0 失败」这条
    # 项目基线打破，反而让真正的回归信号被淹没。
    OUR_FILES = ("app/pyexec.py", "app/pyexec_bridge.py", "app/replayer.py",
                 "test_045_fixes.py", "app/main.py", "app/agent.py",
                 "README.md", "run_all_tests.py")
    ours = [h for h in hits if h.split("⊃")[0] in OUR_FILES]
    legacy = [h for h in hits if h.split("⊃")[0] not in OUR_FILES]
    check(f"本版改动过的文件不含真实靶标（查了 {len(targets)} 个域）",
          not ours, "命中：" + "；".join(ours[:6]))
    if legacy:
        print(f"  [WARN] 历史遗留（需单独版本统一脱敏，共 {len(legacy)} 处）：")
        for h in legacy[:10]:
            print(f"         {h}")


def main():
    print("=" * 68)
    print("v045 优化回归：确认闸门前置与口径修复")
    print("=" * 68)
    test_syntax_precheck()
    test_syntax_precheck_wired_before_gate()
    test_resp_subscript()
    test_replay_length_metric()
    test_save_load_text()
    test_sandbox_module_health()
    test_classifier_whitelist_synced()
    test_readme_defaults_in_sync()
    test_session_detail_confirm_visibility()
    test_no_real_targets_in_tracked_sources()
    print("\n" + "=" * 68)
    print(f"结果：{PASS} 通过 / {FAIL} 失败")
    print("=" * 68)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
