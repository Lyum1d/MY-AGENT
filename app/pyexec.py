# -*- coding: utf-8 -*-
"""Python 代码执行通道（py_exec）：Agent 意图直出代码 → 宿主解释器执行 → 流式回传。

设计对齐「Intent Engineering」：让模型对单点任务直接写一小段 Python（HTTP 交互优先
requests/httpx），而不是把它圈在「选工具→解析输出」的串行循环里。

安全边界（配合 agent 风险闸门使用）：
- 该通道在 registry 中被定级为 L3：执行前需用户确认 + 勾选书面授权（二次确认）。
- 代码在本机后端解释器运行，能力等同本机命令行，请仅在授权目标范围内使用。
- v010 进程级沙箱（P0-1 分级方案）：
  ① 环境变量白名单——凭据/代理/供应商 Key 不再被子进程继承；
  ② 一次性临时工作目录——cwd 与 TEMP/TMP 指向临时目录，结束即清理；
  ③ Windows Job Object——超时/异常时整棵进程树终止，不留孤儿进程。
  代码内部实际访问的主机仍无法静态解析，最终边界仍是 L3 的用户确认 + 书面授权。
- 每段代码写入 data/scripts/exec/<目标>/ 留档，便于审计复盘。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import AsyncIterator

from . import config, pyexec_bridge
from .scope import check_scope, find_hosts

logger = logging.getLogger("src_agent")

# ---------- 沙箱：环境变量白名单（v010 P0-1 ①） ----------
# 背景：此前 env=os.environ 完整继承宿主环境，DEEPSEEK_API_KEY / FOFA key /
#   代理凭据 / .src_agent_llm 相关变量全部对执行代码可见——一段被诱导生成的
#   脚本（比如读 env 回传）就能把宿主凭据整锅端走。
# 原则：**白名单放行**而不是黑名单排除（黑名单永远漏），只给「Python 能正常
#   起来 + 正常收输出」所必需的变量。脚本确需某个变量时，用户把它加进
#   data/pyexec_env_allow.json（JSON 字符串数组），经允许后显式注入。
_BUILTIN_ENV_ALLOW = {
    # Windows 系统必需（缺了 python.exe 起不来 / DLL 找不到）
    "SystemRoot", "SYSTEMDRIVE", "windir", "PATHEXT", "COMSPEC",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
    # 代码页/终端行为
    "PYTHONIOENCODING", "PYTHONUTF8", "PYTHONLEGACYWINDOWSSTDIO",
}
# PATH 给精简的系统目录（够 DLL 加载与常用系统调用），不继承宿主 PATH——
# 宿主 PATH 里可能混着用户目录、代理工具目录等不该被看到的注入面。
_SANDBOX_PATH = os.pathsep.join([
    r"C:\Windows\System32", r"C:\Windows", r"C:\Windows\System32\Wbem",
    r"C:\Windows\System32\WindowsPowerShell\v1.0",
])


def _load_env_allow_extra() -> set[str]:
    """读用户扩展白名单（data/pyexec_env_allow.json，JSON 字符串数组）。"""
    p = config.PY_EXEC_ENV_ALLOW_JSON
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("pyexec_env_allow.json 解析失败，忽略用户扩展白名单")
        return set()
    if not isinstance(data, list):
        return set()
    return {str(x).strip() for x in data if isinstance(x, str) and str(x).strip()}


def build_sandbox_env(workdir: str | Path) -> dict:
    """构造 py_exec 子进程环境：白名单内置项 + 用户扩展项 + 指向临时目录的 TEMP/TMP。

    返回的新 dict 与 os.environ 无共享（改它不影响宿主）。
    环境里不再出现任何 API Key / 代理 / 供应商凭据。
    """
    allow = _BUILTIN_ENV_ALLOW | _load_env_allow_extra()
    env: dict = {}
    for k, v in os.environ.items():
        if k in allow:
            env[k] = v
    env.setdefault("SystemRoot", r"C:\Windows")
    env.setdefault("SYSTEMDRIVE", "C:")
    env["PATH"] = _SANDBOX_PATH
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    # TEMP/TMP 指向本次的一次性工作目录：脚本写临时文件也不会污染真实临时区
    wd = str(workdir)
    env["TEMP"] = wd
    env["TMP"] = wd
    return env


# ---------- 沙箱：Windows Job Object 进程树终止（v010 P0-1 ③） ----------
# 背景：proc.kill() 只杀直接子进程；脚本再起 subprocess（常见：调系统命令、
#   起并发 worker）会残留孤儿进程继续跑。Job Object 的
#   JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 让「关闭句柄」= 终止整棵进程树，
#   这是 Windows 上唯一不依赖被终止方配合的杀树方式。
class _WinJobTree:
    """ctypes 实现（不引入 pywin32 依赖）。非 Windows / 初始化失败时 job=None。"""

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JobObjectExtendedLimitInformation = 9

    def __init__(self) -> None:
        self.job = None
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                raise OSError("CreateJobObjectW failed")

            class _IO_COUNTERS(ctypes.Structure):
                _fields_ = [(f, ctypes.c_ulonglong) for f in
                            ("ReadOperationCount", "WriteOperationCount",
                             "OtherOperationCount", "ReadTransferCount",
                             "WriteTransferCount", "OtherTransferCount")]

            class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.POINTER(wintypes.ULONG)),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = \
                self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                    job, self._JobObjectExtendedLimitInformation,
                    ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError("SetInformationJobObject failed")
            self.job = job
            self._kernel32 = kernel32
        except Exception:
            logger.warning("Job Object 初始化失败，杀树退回 taskkill/proc.kill 兜底",
                           exc_info=True)
            self.job = None

    def assign(self, pid: int) -> bool:
        """把已启动的进程挂到 Job 上（启动后尽快调用，越早覆盖越完整）。"""
        if not self.job:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            # AssignProcessToJobObject 要求 PROCESS_SET_QUOTA(0x0100) |
            # PROCESS_TERMINATE(0x0001)。⚠️ 不要想当然写 0x0400——那是
            # PROCESS_QUERY_INFORMATION，权限不够时 Assign 静默失败
            # （实测踩中：杀树用例三连挂，根因就是它）。
            _PROCESS_SET_QUOTA = 0x0100
            _PROCESS_TERMINATE = 0x0001
            h = self._kernel32.OpenProcess(
                wintypes.DWORD(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE),
                wintypes.BOOL(False), wintypes.DWORD(pid))
            if not h:
                return False
            ok = bool(self._kernel32.AssignProcessToJobObject(self.job, h))
            self._kernel32.CloseHandle(h)
            return ok
        except Exception:
            return False

    def close(self) -> None:
        """关闭 Job 句柄：KILL_ON_JOB_CLOSE 使整棵进程树终止。"""
        if self.job:
            try:
                self._kernel32.CloseHandle(self.job)
            except Exception:
                pass
            self.job = None


def _kill_tree_fallback(pid: int) -> None:
    """Job Object 不可用时的兜底杀树：taskkill /T /F（Windows 自带）。"""
    try:
        import subprocess as _sp
        _sp.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                capture_output=True, timeout=10,
                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def _sanitize(name: str) -> str:
    """把 target 变成安全的单层目录名。

    注意：`.` 必须保留（域名本身有点），但**纯点名**必须中和——
    `..` / `.` / `...` 拼进路径就是目录穿越，能把留档写到 PY_EXEC_DIR 之外。
    此前实现只做字符替换，`_sanitize("..")` 原样返回 `..`，是实打实的穿越入口。
    """
    name = re.sub(r"[^\w\-.]", "_", name)
    if not name.strip("."):      # 全是点（含空串）→ 无有效字符，落回占位名
        name = "_" + name
    return name[:60]


def _scope_check_target(target: str) -> str | None:
    """对 host 形态的 target 做授权白名单校验；企业名等自由文本跳过。

    py_exec 是 L3 通道，能力等同本机命令行，理应与命令行工具一样受白名单约束。
    但它的 target 仅用于留档归类，模型时常填企业名（如「腾讯」）以待后续资产扩展，
    这类值白名单里本就不存在，强制校验会误伤正常流程，故只校验「确实像主机」的片段。

    实现要点（此前版本的缺口）：
      · 旧实现用「含空格 / 含非 ASCII / 不含 . 就整串跳过」做粗判，
        于是 `evil.com foo`、`evil.com 腾讯` 这类「主机 + 一点说明」直接绕过白名单；
        现改为 **逐个抽出像主机的片段分别校验，任一未授权即拒绝**。
      · 抽出规则收敛到 app/scope.py 的 find_hosts，与 Agent 的「从任务描述提取目标」
        共用同一套口径，避免两处规则分叉出现静默缺口。
      · `localhost` 这类不含点、却明确指向本机的名字被显式纳入校验（不再跳过）。

    局限：代码内部实际请求的主机无法静态解析，本校验只覆盖声明的 target；
    真正的边界仍是 L3 的用户确认 + 书面授权，二者缺一不可。
    """
    hosts = find_hosts(target or "")
    if not hosts:               # 纯自由文本（企业名 / 版本号 / 状态词）→ 不误伤
        return None
    for h in hosts:
        denied = check_scope(h)
        if denied:
            return denied
    return None


async def run_py_exec(code: str, target: str = "", cancel_event=None,
                      project_id: str = "", session_id: str = "") -> AsyncIterator[dict]:
    """执行一段 Python 代码，产出与 executor 一致的事件流。

    yield: {"type": "output"|"error"|"exit", "data":..., "code":...}
    """
    code = (code or "").strip()
    if not code:
        yield {"type": "error", "data": "代码为空"}
        yield {"type": "exit", "code": 1}
        return
    if len(code) > config.PY_EXEC_MAX_CHARS:
        yield {"type": "error", "data": f"代码过长（{len(code)} 字符），上限 {config.PY_EXEC_MAX_CHARS}，请拆小"}
        yield {"type": "exit", "code": 1}
        return

    # ---- 授权范围校验：L3 通道同样不得打未授权目标 ----
    # 与 executor 共用 config.ENFORCE_SCOPE 开关与 data/scope.json 白名单。
    if config.ENFORCE_SCOPE:
        denied = _scope_check_target(target)
        if denied:
            yield {"type": "error", "data": denied}
            yield {"type": "exit", "code": 126}
            return

    # ---- v023.2 脚本网络访问治理（实测事故通道：脚本内部循环直连目标）----
    # safe 模式拒绝「网络库 + 循环 + URL」的事故模式，并引导改用受控接口；
    # warn 模式只提示；legacy 关闭治理（排障用）。
    policy = config.PY_EXEC_NETWORK_POLICY
    det = pyexec_bridge.detect_direct_network(code)
    if policy != "legacy" and det["risky"]:
        msg = ("检测到脚本直接使用网络库且含循环体——这类脚本在子进程里循环发包，"
               "外层流量调度器管不住，正是导致目标 IP 被封的事故模式。\n"
               "请改用受控接口：\n"
               "    from srcagent import safe_http_request\n"
               "    r = safe_http_request(\"https://授权目标/路径\")\n"
               "该接口的每次请求都会经过统一调度器（scope/预算/并发/暂停态均生效）。\n"
               "**循环写法**：把 `for u in urls: get(u)` 直接展开为顺序调用"
               "（safe_http_request 本身不限次数，只受单脚本预算约束），"
               "例如：\n"
               "    from srcagent import safe_http_request as H\n"
               "    r1 = H(urls[0]); r2 = H(urls[1]); r3 = H(urls[2])\n"
               "（展开后仍是受控请求；确实需要大量请求时请拆成多次 py_exec 调用。）")
        if policy == "safe":
            yield {"type": "error", "data": "已拒绝执行：" + msg}
            yield {"type": "exit", "code": 126}
            return
        yield {"type": "output", "data": "#（警告）" + msg}
    elif policy != "legacy" and det["single_shot"]:
        # v023.6：单次直连同样绕过调度器（不可审计、不受预算/暂停态约束）。
        # 不拒绝（风险低于循环模式），但必须提示并留痕——此前是静默放行。
        yield {"type": "output", "data": (
            "（提示）脚本直接使用了网络库（单次请求）——该请求**不经过**流量调度器："
            "不会计入预算、不受目标暂停态约束、也不会出现在流量审计里。"
            "建议改用受控接口 `from srcagent import safe_http_request`；"
            "若确需直连（例如访问本地文件或非 HTTP 协议），请忽略本提示。")}

    # 留档目录：data/scripts/exec/<目标>/exec_<毫秒时间戳>.py
    base = config.PY_EXEC_DIR / _sanitize(target or "default")
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        base = config.PY_EXEC_DIR
        base.mkdir(parents=True, exist_ok=True)
    script = base / f"exec_{int(time.time() * 1000)}.py"
    try:
        script.write_text(code, encoding="utf-8")
    except Exception as e:
        yield {"type": "error", "data": f"代码写入失败：{e}"}
        yield {"type": "exit", "code": 1}
        return

    yield {"type": "output", "data": f"# 执行 {len(code)} 字符的 Python（留档：{script.name}）"}

    # ---- 沙箱 ② 临时工作目录：执行 cwd 与 TEMP/TMP 都指向一次性目录 ----
    # 留档仍在 PY_EXEC_DIR（脚本文件本身不删，供审计复盘）；工作目录里产生的
    # 中间产物执行完即清理。目录创建失败时退回留档目录（可用性优先，沙箱
    # 的主要防线 env 白名单与 Job 杀树不受影响）。
    config.PY_EXEC_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="pyexec_", dir=str(config.PY_EXEC_TMP_ROOT)))
    cwd = workdir
    # v023.2：铺受控网络通道（脚本 `from srcagent import safe_http_request` 即用）
    bridge = None
    run_path = script          # 默认直接跑留档文件
    if policy != "legacy":
        try:
            pyexec_bridge.prepare_workdir(workdir)
            # Python 的 sys.path[0] 是**脚本所在目录**而不是 cwd——留档目录里
            # 没有 srcagent.py，`import srcagent` 会失败。因此把执行副本放进
            # workdir（留档仍在 data/scripts/exec/ 不动），让模块可被导入。
            run_path = workdir / "_script.py"
            run_path.write_text(code, encoding="utf-8")
            bridge = pyexec_bridge.ScriptBridge(workdir, tool_alias="py_exec",
                                                project_id=project_id,
                                                session_id=session_id)
        except Exception:
            logger.warning("受控网络通道初始化失败（脚本仍可执行，但无受控通道）", exc_info=True)
    try:
        env = build_sandbox_env(workdir)
    except Exception as e:
        # env 构造失败 = 白名单机制不可用：按 fail-closed 拒绝执行
        yield {"type": "error", "data": f"沙箱环境构造失败，已拒绝执行：{e}"}
        yield {"type": "exit", "code": 1}
        shutil.rmtree(workdir, ignore_errors=True)
        return

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-u", str(run_path),
        cwd=str(cwd), env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    # ---- 沙箱 ③ Job Object 杀树：启动后立即挂入，结束时整树终止 ----
    job = _WinJobTree()
    tree_killed_by_job = job.assign(proc.pid)
    if not tree_killed_by_job and os.name == "nt":
        yield {"type": "output", "data": "#（提示）Job Object 不可用，超时将用 taskkill 杀树兜底"}
    deadline = time.monotonic() + config.PY_EXEC_TIMEOUT
    timed_out = False
    cancelled = False
    bridge_task = asyncio.create_task(bridge.run()) if bridge else None
    bridge_killed_reason = ""
    _buf = b""   # 审计 P2-2：定长 read 的行缓冲（替代 readline，避免 64KB 单行炸通道）
    try:
        # 逐行流式回传；超时则中断并保留已回传部分
        while True:
            # v012 后半：取消硬终止——Job Object 关句柄即终止整树
            if cancel_event is not None and cancel_event.is_set():
                job.close()
                try:
                    proc.kill()
                except Exception:
                    pass
                if not tree_killed_by_job:
                    _kill_tree_fallback(proc.pid)
                timed_out = False
                cancelled = True
                yield {"type": "cancelled", "data": "已收到取消请求，代码执行已终止（整棵进程树）"}
                break
            # v023.2：受控通道事件与熔断——脚本请求被调度器拒绝（目标暂停/
            # 预算耗尽/scope 外）或触发封禁迹象时，终止脚本与其子进程树，
            # 不再让脚本继续尝试（计划 6.4：不能靠脚本自己"自觉"停下）。
            if bridge is not None:
                drain = []
                while not bridge.notes.empty():
                    try:
                        drain.append(bridge.notes.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                for note in drain:
                    yield {"type": "output", "data": note}
                if bridge.blocked_reason:
                    bridge_killed_reason = bridge.blocked_reason
                    job.close()
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    if not tree_killed_by_job:
                        _kill_tree_fallback(proc.pid)
                    yield {"type": "error", "data": (
                        f"受控通道已终止脚本：{bridge_killed_reason}。"
                        "已发出的请求计入流量审计，后续请求一律未发出。")}
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                # Job Object 在手：关句柄即终止整树；否则 proc.kill + taskkill 兜底
                job.close()
                try:
                    proc.kill()
                except Exception:
                    pass
                if not tree_killed_by_job:
                    _kill_tree_fallback(proc.pid)
                yield {"type": "error",
                       "data": f"执行超时（>{config.PY_EXEC_TIMEOUT}s），已中断整棵进程树。请把代码拆小或增加单步耗时上限后再试。"}
                break
            try:
                # 审计 P2-2：readline() 遇到超过 asyncio 流默认 64KB limit 的单行会抛
                # ValueError，被下面的 except Exception 吞成「执行通道异常」，掩盖真实
                # 输出。改用定长 read() + 手动切行，超长行由下方 2000 字符截断兜底。
                raw = await asyncio.wait_for(proc.stdout.read(4096), timeout=min(remaining, 5.0))
            except asyncio.TimeoutError:
                continue
            if not raw:
                break
            _buf += raw
            *lines, _buf = _buf.split(b"\n")
            for line in lines:
                text = line.decode("utf-8", "replace").rstrip("\r")
                if not text:
                    continue
                if len(text) > 2000:
                    text = text[:2000] + "…（行过长已截断）"
                yield {"type": "output", "data": text}
    except Exception as e:
        yield {"type": "error", "data": f"执行通道异常：{e}"}
    finally:
        # v023.2：先停受控通道（避免脚本退出后桥接任务空转），再收进程。
        if bridge is not None:
            bridge.stop()
        if bridge_task is not None:
            try:
                await asyncio.wait_for(bridge_task, timeout=2)
            except Exception:
                bridge_task.cancel()
        # 无论哪条路径退出：先关 Job（整树终止，含孙进程），再兜 proc.kill，
        # 最后 taskkill 兜底——三层防御保证「取消/超时后不残留子进程」。
        job.close()
        if proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=10)
        except Exception:
            rc = -1
            if os.name == "nt":
                _kill_tree_fallback(proc.pid)
        shutil.rmtree(workdir, ignore_errors=True)
    if cancelled:
        yield {"type": "exit", "code": 130}   # 130 = SIGINT 语义，区别于超时 124 / 越权 126
    elif not timed_out:
        yield {"type": "exit", "code": rc}
    else:
        yield {"type": "exit", "code": 124}
