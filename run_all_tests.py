# -*- coding: utf-8 -*-
"""一键跑全部回归测试。

    python run_all_tests.py            # 全部（端到端会自动临时起服务）
    python run_all_tests.py --quick    # 跳过需要起服务的端到端

为什么要有这个脚本：测试分散在 5 个 Python 脚本 + 2 个 Node 脚本里，
其中端到端必须先起后端，靠人记很容易漏跑——漏跑的那次偏偏就会放出回归。

行为说明：
  · 8770 上已经有本项目服务在跑 → 直接复用，不重启（避免打断你正在用的控制台）；
  · 8770 空着 → 临时起一个，跑完自动关掉；
  · 8770 被别的程序占着 → 跳过端到端并明确说明。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# Windows GBK 控制台乱码快修（v010）：测试脚本全 UTF-8 输出。
# 背景：默认 stdout 编码跟控制台代码页（GBK/cp936）走，带中文/框线的测试
#   输出会变成乱码，甚至让人把「乱码」误判成「异常」。三层保险：
#   ① 本进程 stdout/stderr 强制 UTF-8；
#   ② 环境变量 PYTHONIOENCODING=utf-8 —— 子套件进程继承（见下方 subprocess 调用）；
#   ③ 子进程命令行统一带 -X utf8。
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
# v023.1：统一流量调度器默认按「保守档」（10 分钟 30 请求）限流——回归套件里
# 多个 fixture 套件会打到 127.0.0.1 的本地模拟服务，正常量级就会触顶。
# 测试模式显式放大预算与并发（status 接口会公开该标志，生产不得开启）；
# 单跑某个套件时也需带上该环境变量：
#   PowerShell:  $env:AGENT_TRAFFIC_TEST_MODE="1"; python test_diff.py
os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
PORT = 8770
BASE = f"http://127.0.0.1:{PORT}"

# 后端套件需要 fastapi/uvicorn/httpx。解释器选错时它们会整片崩掉，
# 所以不写死 sys.executable，而是挑一个真正装了依赖的（见 pick_python）。
NODE = "node"

# 运行后端套件所需的最小依赖
REQUIRED_MODULES = ("fastapi", "uvicorn", "httpx")

# 未配置 DeepSeek Key 时必然失败的一项（依赖环境，不是回归）
KNOWN_ENV_FAIL = "命中关键词时会路由到 deepseek 供应商"

PY_TESTS = [
    # 授权红线排第一：越权是本项目最不能接受的失败，宁可它先红
    ("授权白名单（安全红线）", "test_scope.py", False),
    ("py_exec 沙箱（v010 P0-1）", "test_sandbox.py", False),
    ("云端外发脱敏（v010 P0-4）", "test_redact.py", False),
    ("数据归属校验（v010 P1-3）", "test_ownership.py", False),
    ("工具分级与配置一致性（第二道闸门）", "test_registry.py", False),
    ("代码执行通道 py_exec（L3）", "test_pyexec.py", False),
    ("HTTP 重放器（授权与只读）", "test_replayer.py", False),
    ("证据状态模型与报告增强（v012）", "test_evidence.py", False),
    ("请求导入（Burp/HAR，v017.1）", "test_import.py", False),
    ("测试身份库与 DPAPI（v017.2）", "test_identity_store.py", False),
    ("只读身份差分（v017.3）", "test_diff.py", False),
    ("证据链与复核闸门（v017.4）", "test_evidence_bundle.py", False),
    ("流程绕过检测（v017.5）", "test_flow.py", False),
    ("整改报告修复回归（v022）", "test_022_fixes.py", False),
    ("统一流量调度（v023.1）", "test_traffic.py", False),
    ("py_exec 与扫描器治理（v023.2）", "test_pyexec_traffic.py", False),
    ("网络层 WAF 状态机（v023.3）", "test_waf.py", False),
    ("情报库与报告生成", "test_intel_report.py", False),
    ("启动器与版本一致性", "test_launcher.py", False),
    ("线索图后端", "test_graph.py", False),
    ("对话树", "test_tree.py", False),
    ("记忆机制（续聊恢复/异常沉淀/溯源）", "test_memory.py", False),
    ("可靠性（取消/重放/幂等/故障转移 v011）", "test_reliability.py", False),
    ("Token 用量统计", "test_usage.py", False),
    ("知识库与 FOFA", "test_kb_fofa.py", False),
    ("供应商模块（Python 层）", "test_multi_llm.py", False),
    ("Agent 冒烟 + 线索链联动", "test_agent_smoke.py", False),
    ("线索图端到端", "test_graph_e2e.py", True),      # 需要后端
    ("供应商与项目接口", "test_llm_providers.py", True),
]
NODE_TESTS = [
    ("高危确认闸门（前端）", "test_confirm_js.js"),
    ("前端主流程", "test_appjs.js"),
    ("线索图前端", "test_graph_js.js"),
]

# 会真实执行工具 / 需要云端 Key 的脚本：不适合自动跑，列出来避免被误以为"已覆盖"
MANUAL_TESTS = [
    ("test_jiaoyu.py", "授权实靶回归：驱动服务对 www.jiaoyu.cn 跑真实工具（补天公益 SRC），"
                       "需先启动服务。项目规范指定改动后跑它"),
    ("test_agent.py", "终端里跑一轮真实工具调用，会碰目标"),
    ("test_api.py", "下发任务并消费 SSE，会真实执行工具"),
    ("test_e2e_deepseek.py", "云端 LLM 驱动真实工具链路，需 API Key 且会碰目标"),
]
# 已经跑不起来的脚本。列出来（并直接跳过，不再计入通过/失败），别让它悄悄烂着。
# 2026-09-16 起不为空：v004→006 拉上游（Lyum1d/MY-AGENT）时，
# update.py 把 app/*.py 与 web/{app.js,index.html,style.css} 整体覆盖，
# 本地自研的「线索树导航 / 线索图 UI」「面板加载失败提示」被覆盖掉
# （上游前端里没有这些）。经确认不恢复前端，故 test_appjs.js 整体下线；
# 后端线索图已按 git HEAD 恢复，所以 test_graph.py 照常跑。
STALE_TESTS: list[tuple[str, str]] = [
    ("test_appjs.js",
     "依赖本地自研前端（线索树导航 / 线索图 UI / 面板加载失败提示）。"
     "拉上游更新时 index.html 与 app.js 被整体覆盖，这些函数在上游版里不存在，"
     "功能已下线。保留脚本以便日后恢复前端时重新启用。"),
]
# 已下线脚本的文件名集合（执行时直接跳过，理由见上）
RETIRED_SCRIPTS = {s for s, _ in STALE_TESTS}

RE_COUNT_CN = re.compile(r"通过\s*(\d+)\s*项，失败\s*(\d+)\s*项")
RE_COUNT_SMOKE = re.compile(r"结果：(\d+)\s*通过\s*/\s*(\d+)\s*失败")
RE_SKIP_SMOKE = re.compile(r"结果：\d+\s*通过\s*/\s*\d+\s*失败\s*/\s*(\d+)\s*跳过")
RE_FAILITEM = re.compile(r"失败项：(.+)")


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) == 0


def probe_service(timeout: float = 2.0) -> dict | None:
    try:
        with urllib.request.urlopen(f"{BASE}/api/health", timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8"))
        if isinstance(d, dict) and "registry" in d and "toolbox" in d:
            return d
    except Exception:
        return None
    return None


def wait_port(proc=None, deadline: float = 30.0) -> bool:
    """等端口就绪。给了 proc 就在进程已退出时立刻返回 False——
    否则 run.py 秒退（比如缺依赖）也要白等满 30 秒。"""
    start = time.time()
    while time.time() - start < deadline:
        if port_open(PORT):
            return True
        if proc is not None and proc.poll() is not None:
            return False
        time.sleep(0.2)
    return False


def _has_deps(py: str) -> bool:
    if not py:
        return False
    try:
        p = subprocess.run(
            [py, "-c", f"import {', '.join(REQUIRED_MODULES)}"],
            capture_output=True, timeout=60)
        return p.returncode == 0
    except Exception:
        return False


def pick_python() -> tuple[str, str]:
    """挑一个装了后端依赖的解释器，返回 (路径, 说明)。

    为什么需要：sys.executable 未必是装依赖那个（托管解释器通常很干净）。
    用错的解释器会让 6 个后端套件集体 ModuleNotFoundError，
    而如果只报「未解析到结果统计」，看起来就像"测试本身有问题"。
    """
    cands: list[str] = []

    def add(p: str | None) -> None:
        if p and p not in cands:
            cands.append(p)

    add(sys.executable)
    for n in ("python", "python3", "py"):
        add(shutil.which(n))
    home = os.path.expanduser("~")
    for pat in (
        os.path.join(home, "AppData", "Local", "Programs", "Python", "Python3*", "python.exe"),
        r"C:\Python3*\python.exe",
    ):
        for p in sorted(glob.glob(pat), reverse=True):
            add(p)

    for c in cands:
        if _has_deps(c):
            note = "" if c == sys.executable else f"（自动切换：当前解释器缺 {'/'.join(REQUIRED_MODULES)}）"
            return c, note
    return sys.executable, f"[警告] 所有候选解释器都缺 {'/'.join(REQUIRED_MODULES)}，后端套件会崩"


def error_hint(out: str, limit: int = 3) -> str:
    """从子进程输出里抽出真正有用的报错行。

    关键：套件崩在 import 阶段时，stdout 里是一堆 PASS，真正的死因在 traceback 里。
    只贴最后几行会全是 PASS，所以优先捞 Error/Traceback/Exception 行。
    """
    lines = [l.strip() for l in (out or "").splitlines() if l.strip()]
    if not lines:
        return "无任何输出"
    hits = [l for l in lines
            if re.search(r"Traceback|Error|Exception|ModuleNotFound|错误", l)]
    tail = hits[-limit:] if hits else lines[-limit:]
    return " ｜ ".join(t[-110:] for t in tail)


def parse_counts(out: str) -> tuple[int, int] | None:
    m = RE_COUNT_CN.search(out) or RE_COUNT_SMOKE.search(out)
    return (int(m.group(1)), int(m.group(2))) if m else None


def run_cmd(args: list[str], timeout: int = 600) -> tuple[int, str]:
    env = os.environ.copy()
    # 探测 localhost 时别让代理插一脚
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(k, None)
    # 子套件强制 UTF-8（v010）：PYTHONIOENCODING 已在模块顶部 setdefault；
    # python 命令行统一加 -X utf8（双保险）
    if args and args[0].lower().endswith(("python.exe", "python")):
        args = list(args) + ["-X", "utf8"]
    try:
        p = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"命令不存在：{args[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"超时（>{timeout}s）"


def main() -> int:
    ap = argparse.ArgumentParser(description="一键跑全部回归测试")
    ap.add_argument("--quick", action="store_true", help="跳过需要起服务的端到端测试")
    # 注意：重定向到文件时 print 默认块缓冲，汇总会卡在缓冲区里看不见
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    results: list[tuple[str, str, str]] = []      # (名称, 结论, 说明)
    server_proc: subprocess.Popen | None = None
    reuse = False

    PY, py_note = pick_python()

    print("=" * 62)
    print("  SRC 渗透 Agent · 全量回归")
    print("=" * 62)
    print(f"  解释器：{PY}")
    if py_note:
        print(f"  {py_note}")

    need_server = not args.quick
    if need_server:
        live = probe_service() if port_open(PORT) else None
        if live:
            reuse = True
            print(f"  复用已在运行的服务（版本 {live.get('version', '?')} / "
                  f"构建 {live.get('build', '?')}）")
        elif port_open(PORT):
            print(f"  [警告] 端口 {PORT} 被别的程序占用，将跳过端到端测试。")
            need_server = False
        else:
            print("  启动临时服务…")
            env = os.environ.copy()
            for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                env.pop(k, None)
            server_proc = subprocess.Popen(
                [PY, "run.py", "--no-browser"], cwd=str(ROOT), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if not wait_port(server_proc):
                # 别把 stderr 丢进 DEVNULL：服务起不来时必须能看见为什么
                err = b""
                try:
                    server_proc.terminate()
                    _, err = server_proc.communicate(timeout=5)
                except Exception:
                    pass
                hint = error_hint((err or b"").decode("utf-8", "replace"))
                print(f"  [错误] 临时服务启动失败，将跳过端到端测试。")
                print(f"         原因：{hint}")
                server_proc = None
                need_server = False
    print()

    try:
        for name, script, needs_server in PY_TESTS:
            if script in RETIRED_SCRIPTS:
                why = dict(STALE_TESTS)[script]
                results.append((name, "跳过", f"已下线（{why}）"))
                print(f"  [跳过] {name} → 已下线：{why}")
                continue
            if needs_server and not need_server:
                results.append((name, "跳过", f"未启动后端（{script}）"))
                print(f"  [跳过] {name}")
                continue
            code, out = run_cmd([PY, script])
            counts = parse_counts(out)
            if counts is None:
                # 退出码非 0 = 脚本根本没跑完（多半是 import 阶段就崩了）。
                # 只说"没解析到结果"会把 ModuleNotFoundError 这类死因藏起来。
                if code != 0:
                    hint = error_hint(out)
                    results.append((name, "异常", f"退出码 {code}：{hint}"))
                    print(f"  [异常] {name}（退出码 {code}）→ {hint}")
                else:
                    results.append((name, "异常", "跑完但没有结果统计行（脚本输出格式变了？）"))
                    print(f"  [异常] {name}（无结果统计行）")
                continue
            passed, failed = counts
            fail_items = RE_FAILITEM.search(out)
            detail = f"{passed} 通过 / {failed} 失败"
            sm = RE_SKIP_SMOKE.search(out)
            if sm and int(sm.group(1)):
                detail += f"（{sm.group(1)} 项跳过：环境未就绪）"
            if failed:
                detail += f"（{fail_items.group(1).strip()}）" if fail_items else ""
            # 唯一放行：未配 DeepSeek Key 导致的路由用例
            only_known = (failed == 1 and fail_items
                          and KNOWN_ENV_FAIL in fail_items.group(1))
            results.append((name, "通过" if only_known else ("失败" if failed else "通过"),
                            detail + ("（已知环境依赖，非回归）" if only_known else "")))
            print(f"  [{'通过' if only_known or not failed else '失败'}] {name} → {detail}")

        for name, script in NODE_TESTS:
            if script in RETIRED_SCRIPTS:
                why = dict(STALE_TESTS)[script]
                results.append((name, "跳过", f"已下线（{why}）"))
                print(f"  [跳过] {name} → 已下线：{why}")
                continue
            code, out = run_cmd([NODE, script])
            counts = parse_counts(out)
            if counts is None:
                extra = "（node 是否在 PATH？）" if code == 127 else ""
                hint = error_hint(out) if code not in (0, 127) else ""
                detail = f"没有解析到结果统计{extra}" + (f"：{hint}" if hint else "")
                results.append((name, "异常", detail))
                print(f"  [异常] {name}（退出码 {code}）{('→ ' + hint) if hint else extra}")
                continue
            passed, failed = counts
            results.append((name, "通过" if not failed else "失败",
                            f"{passed} 通过 / {failed} 失败"))
            print(f"  [{'通过' if not failed else '失败'}] {name} → "
                  f"{passed} 通过 / {failed} 失败")
    finally:
        if server_proc is not None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                server_proc.kill()
            print("\n  临时服务已关闭" + ("（原本就在运行的服务未受影响）" if reuse else ""))

    total_pass = total_fail = 0
    for _, _, detail in results:
        nums = re.search(r"(\d+) 通过 / (\d+) 失败", detail)
        if nums:
            total_pass += int(nums.group(1))
            total_fail += int(nums.group(2))

    print()
    print("-" * 62)
    for name, verdict, detail in results:
        mark = {"通过": "✓", "失败": "✗", "跳过": "-", "异常": "!"}.get(verdict, "?")
        print(f"  {mark} {name:22s} {detail}")
    print("-" * 62)
    bad = [r for r in results if r[1] in ("失败", "异常")]
    print(f"  合计 {total_pass} 项通过 / {total_fail} 项失败"
          + (f"；{len([r for r in results if r[1] == '跳过'])} 项跳过" if any(
              r[1] == "跳过" for r in results) else ""))
    if bad:
        print("  未通过：" + "、".join(r[0] for r in bad))

    # 覆盖范围要说清楚：哪些是手工的、哪些已经失效，别让人以为"跑绿了就全覆盖了"
    print()
    print("  未纳入自动跑：")
    for name, why in MANUAL_TESTS:
        print(f"    手工  {name:22s} {why}")
    for name, why in STALE_TESTS:
        print(f"    失效  {name:22s} {why}")
    if not STALE_TESTS:
        print("    （当前没有失效脚本）")
    print("=" * 62)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
