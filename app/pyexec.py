# -*- coding: utf-8 -*-
"""Python 代码执行通道（py_exec）：Agent 意图直出代码 → 宿主解释器执行 → 流式回传。

设计对齐「Intent Engineering」：让模型对单点任务直接写一小段 Python（HTTP 交互优先
requests/httpx），而不是把它圈在「选工具→解析输出」的串行循环里。

安全边界（配合 agent 风险闸门使用）：
- 该通道在 registry 中被定级为 L3：执行前需用户确认 + 勾选书面授权（二次确认）。
- 代码在本机后端解释器运行，能力等同本机命令行，请仅在授权目标范围内使用；
  提示词/描述反复约束，但最终边界由风险闸门 + 用户确认承担。
- 每段代码写入 data/scripts/exec/<目标>/ 留档，便于审计复盘。
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from pathlib import Path
from typing import AsyncIterator

from . import config
from .scope import check_scope, find_hosts

logger = None  # 延迟引入 logging，避免无谓开销


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


async def run_py_exec(code: str, target: str = "") -> AsyncIterator[dict]:
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

    env = dict(os.environ)
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-u", str(script),
        cwd=str(base), env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    deadline = time.monotonic() + config.PY_EXEC_TIMEOUT
    timed_out = False
    try:
        # 逐行流式回传；超时则中断并保留已回传部分
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                proc.kill()
                yield {"type": "error",
                       "data": f"执行超时（>{config.PY_EXEC_TIMEOUT}s），已中断。请把代码拆小或增加单步耗时上限后再试。"}
                break
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=min(remaining, 5.0))
            except asyncio.TimeoutError:
                continue
            if not raw:
                break
            text = raw.decode("utf-8", "replace").rstrip()
            if not text:
                continue
            if len(text) > 2000:
                text = text[:2000] + "…（行过长已截断）"
            yield {"type": "output", "data": text}
    except Exception as e:
        yield {"type": "error", "data": f"执行通道异常：{e}"}
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass
        rc = await proc.wait()
    if not timed_out:
        yield {"type": "exit", "code": rc}
    else:
        yield {"type": "exit", "code": 124}
