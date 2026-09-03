# -*- coding: utf-8 -*-
"""执行器抽象层。

设计要点：
1. Executor 是抽象基类，当前只有 LocalExecutor（Windows 宿主）。
   以后接 Kali 虚拟机只需实现 SSHExecutor，上层代码不用动。
2. 工作目录必须切到工具自身目录（工具箱原程序就是这么做的），
   否则依赖同目录配置文件的工具会失败。
3. 输出按流实时产出，供 SSE 推送到前端。
4. Windows 中文环境工具输出常为 GBK，解码需容错。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncIterator

from . import config
from .registry import Tool


def load_templates() -> dict[str, dict]:
    """加载调用模板。兼容两种写法：
        "ehole": "{exe} finger -u {target} {args}"            （旧，无目标形式）
        "ehole": {"cmd": "...", "target": "url"}              （新，带目标形式）
    """
    p = config.DATA_DIR / "invocation_templates.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for k, v in data.items():
        if k.startswith("_"):
            continue
        if isinstance(v, str):
            out[k] = {"cmd": v, "target": "raw"}
        else:
            out[k] = {"cmd": v.get("cmd", ""), "target": v.get("target", "raw")}
    return out


def normalize_target(target: str, form: str) -> str:
    """把目标归一化为工具期望的形式。

    不把格式负担甩给模型——小模型最常在这里出错，
    而错了往往只是静默失败（如 ehole 传裸域名直接返回空）。
    """
    t = (target or "").strip()
    if not t:
        return t

    # 去掉 scheme、路径与查询串，拿到 host。
    # 注意保留 CIDR：192.168.1.0/24 被截断成 192.168.1.0 会让扫描器只打一个 IP。
    def to_host(s: str) -> str:
        s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", s)
        s = s.split("?")[0].strip()
        head, sep, tail = s.partition("/")
        if sep and re.fullmatch(r"[\d.]+", tail):   # CIDR 掩码，保留
            return head + sep + tail
        return head

    if form == "url":
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", t):
            return t
        return "https://" + t.lstrip("/")

    if form == "host":
        return to_host(t)

    if form == "domain":
        h = to_host(t)
        # 子域名工具要裸域名：带端口无法作为根域名，必须去掉
        if re.fullmatch(r"[\d.]+", h):   # 纯 IP / CIDR 原样返回
            return h
        h = h.split(":")[0]
        return re.sub(r"^www\.", "", h, flags=re.IGNORECASE)

    return t  # raw


def _target_flag(tmpl: str) -> str | None:
    """从模板里取出紧跟 {target} 前面的参数旗标，如 `-u` / `-t` / `--target`。"""
    # 旗标后必须是空白或模板占位符，避免误把 `--target-extra` 这种长旗标截断
    m = re.search(r"(-{1,2}[\w-]+)(?![-\w])\s*=?\s*\{target\}", tmpl)
    return m.group(1) if m else None


def _strip_target_arg(args: str, flag: str | None) -> str:
    """删掉模型在 args 里重复填写的目标旗标（含其值），避免与模板冲突。

    例：模板 `dirsearch.py -u {target} {args}`，模型却传入 args=`-u "http://x/-"`，
    拼出来变成 `-u https://x -u "http://x/-"`，dirsearch 直接栈溢出崩溃（0xC0000004）。
    这里把第二个 `-u ...` 整段剥掉，只保留真正「额外」的参数。
    """
    if not flag or not args:
        return args
    esc = re.escape(flag)
    # 旗标后不能是 - 或单词字符，避免误伤 `--target-extra` 这类长旗标
    # 匹配：flag[=值] 或 flag 值（值可带引号）；值可选，顺带剥掉孤立的 flag
    pat = re.compile(
        r"(?P<lead>\s|^)" + esc + r"(?![-\w])" +
        r"(?:=(?:\"[^\"]*\"|'[^']*'|\S+)|\s+(?:\"[^\"]*\"|'[^']*'|\S+))?"
    )
    return pat.sub(r"\g<lead>", args).strip()


def _strip_one_layer_quotes(tok: str) -> str:
    """递归去掉 token 最外层所有成对的匹配引号（" 或 '）。

    模型常把路径多包若干层引号（如 `'"C:/a/b.txt"'`：外层单引号 + 内层双引号），
    逐层剥掉直到没有外层引号，避免工具收到带字面引号的路径而找不到文件。
    """
    while len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
        tok = tok[1:-1]
    return tok


def _strip_args_quotes(args: str) -> str:
    """剥掉每个参数 token 最外层的一层引号。

    小模型常把路径多包一层引号（如 `-w '"C:/a/b.txt"'`），
    shlex 会保留内部那层字面引号，工具收到带引号路径而找不到文件。
    这里统一去掉最外层引号，让路径第一次就能被正确识别。
    """
    if not args:
        return args
    try:
        toks = shlex.split(args, posix=False)
    except ValueError:
        return args
    return shlex.join(_strip_one_layer_quotes(t) for t in toks)


def _filter_unknown_flags(args: str, allowed: list[str], value_flags: list[str]) -> str:
    """按工具白名单剥掉模型臆造的非法旗标（含其值）。

    小模型常给工具编出不存在的参数（如给 dirsearch 传 `--depth`），
    工具会直接报错退出。这里把不在 allowed 里的旗标整段丢弃，只保留
    合法旗标与其取值，让工具按预期运行而不是失败。

    - allowed 为空列表表示「不校验」，原样返回。
    - value_flags 标记哪些旗标会吞掉下一个 token（取值旗标）；
      布尔旗标不带值，不吞下一个 token，避免误删真正的位置参数。
    """
    if not args or not allowed:
        return args
    allowed_set = set(allowed)
    value_set = set(value_flags or [])
    try:
        toks = shlex.split(args, posix=False)
    except ValueError:
        return args
    out: list[str] = []
    i, n = 0, len(toks)
    while i < n:
        tok = _strip_one_layer_quotes(toks[i])
        if tok.startswith("-"):
            flag = tok.split("=", 1)[0]
            if flag in allowed_set:
                out.append(tok)
                # 空格形式的取值旗标：若下一个 token 不像旗标则吞掉它
                if "=" not in tok and i + 1 < n and not _strip_one_layer_quotes(toks[i + 1]).startswith("-"):
                    if flag in value_set:
                        out.append(_strip_one_layer_quotes(toks[i + 1]))
                        i += 1
                # 否则视为布尔旗标，不吞下一个 token
            else:
                # 非法旗标：若有 `=` 整段丢弃；否则连同下一个非旗标值一起丢弃
                if "=" not in tok and i + 1 < n and not _strip_one_layer_quotes(toks[i + 1]).startswith("-"):
                    i += 1
            # 非法旗标本身不加入 out
        else:
            out.append(tok)
        i += 1
    return shlex.join(out) if out else ""


def _decode(raw: bytes) -> str:
    """Windows 中文环境下工具输出可能是 GBK，逐个尝试常见编码。"""
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class Executor(ABC):
    """执行器抽象：子类需实现 run（取回输出）与 launch（仅启动）。"""

    @abstractmethod
    async def run(self, tool: Tool, target: str, args: str = "") -> AsyncIterator[dict]:
        """执行工具并流式产出输出行。"""
        ...

    @abstractmethod
    async def launch(self, tool: Tool) -> dict:
        """仅启动工具（用于图形界面工具，不取回输出）。"""
        ...


class LocalExecutor(Executor):
    """在 Windows 宿主机上本地执行。"""

    def __init__(self) -> None:
        self.templates = load_templates()

    # ---------- 命令构造 ----------
    def build_command(self, tool: Tool, target: str, args: str = "") -> list[str]:
        """按工具类型构造命令行。

        - Python：用工具箱内置 python3/python.exe
        - JAVA8 / JAVA11：用对应版本的 java.exe -jar
        - 命令行 / 批处理：直接执行（.vbs 走 wscript）
        """
        exe = tool.executable
        ttype = tool.type

        if ttype == "Python":
            python_exe = str(config.TOOLBOX_PYTHON)
            if not Path(python_exe).exists():
                python_exe = "python"
            return self._from_template(tool, target, args, prefix=[python_exe])

        if ttype in ("JAVA8", "JAVA11"):
            java_bin = config.JAVA8_BIN if ttype == "JAVA8" else config.JAVA11_BIN
            java_exe = java_bin / "java.exe"
            if not java_exe.exists():
                java_exe = Path("java")
            return self._from_template(tool, target, args, prefix=[str(java_exe), "-jar"])

        if ttype == "批处理":
            ext = Path(exe).suffix.lower()
            if ext == ".vbs":
                return ["wscript", exe, *(shlex.split(args, posix=False) if args else [])]
            return self._from_template(tool, target, args)

        # 命令行
        return self._from_template(tool, target, args)

    def _tmpl(self, tool: Tool) -> dict | None:
        return self.templates.get(tool.alias)

    def _from_template(self, tool: Tool, target: str, args: str, prefix: list[str] | None = None) -> list[str]:
        cmd = list(prefix or [])
        entry = self.templates.get(tool.alias)
        tmpl = entry.get("cmd") if entry else None
        if tmpl:
            # 按工具声明的形式归一化目标，避免「参数明明对却静默失败」
            norm = normalize_target(target, (entry or {}).get("target", "raw"))
            # 剥掉模型在 args 里重复填写的目标旗标（如 dirsearch 传了 -u "x"，
            # 模板本身已有 -u {target}，拼出来 -u a -u b 会让工具栈溢出崩溃）
            flag = _target_flag(tmpl)
            clean_args = _strip_target_arg(args, flag)
            # 按工具白名单剥掉模型臆造的非法旗标（如 dirsearch 的 --depth）
            clean_args = _filter_unknown_flags(clean_args, tool.allowed_flags, tool.value_flags)
            rendered = tmpl.format(exe=tool.executable, target=norm, args=clean_args or "")
            # 模板里的 {args} 可能为空，需清理多余空白
            cmd.extend([p for p in shlex.split(rendered, posix=False) if p])
        else:
            cmd.append(tool.executable)
            if args:
                args = _strip_args_quotes(args)
                args = _filter_unknown_flags(args, tool.allowed_flags, tool.value_flags)
                cmd.extend(shlex.split(args, posix=False))
            if target:
                cmd.append(target)
        return cmd

    # ---------- 执行 ----------
    async def run(self, tool: Tool, target: str, args: str = "") -> AsyncIterator[dict]:
        if not tool.executable:
            yield {"type": "error", "data": f"工具文件不存在：{tool.name}（{tool.rel_path}）"}
            return

        cmd = self.build_command(tool, target, args)
        yield {"type": "command", "data": " ".join(f'"{c}"' if " " in c else c for c in cmd)}

        env = os.environ.copy()
        # 注入工具箱运行时，避免依赖系统环境
        if config.TOOLBOX_PYTHON.exists():
            env["PATH"] = str(config.TOOLBOX_PYTHON.parent) + os.pathsep + env.get("PATH", "")
            env.pop("PYTHONHOME", None)
            env.pop("PYTHONPATH", None)

        # 防御性补全 Windows 关键环境变量：服务可能从精简环境的 shell 启动，
        # 缺 APPDATA 会让 pyfiglet（dirsearch 依赖）等直接 KeyError 崩溃。
        home = str(Path.home())
        env.setdefault("APPDATA", home + os.sep + "AppData" + os.sep + "Roaming")
        env.setdefault("LOCALAPPDATA", home + os.sep + "AppData" + os.sep + "Local")
        env.setdefault("TEMP", env.get("TEMP") or home + os.sep + "AppData" + os.sep + "Local" + os.sep + "Temp")
        env.setdefault("TMP", env["TEMP"])

        try:
            # 需要喂入 stdin 绕开交互式 input() 提问时，才挂 PIPE；否则保持 None
            # 以免无谓占用管道。喂入后立刻关闭，让子进程的 input() 拿到 EOF。
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=tool.workdir or None,
                stdin=asyncio.subprocess.PIPE if tool.stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
        except FileNotFoundError as e:
            yield {"type": "error", "data": f"无法启动：{e}"}
            return
        except Exception as e:
            yield {"type": "error", "data": f"启动异常：{e}"}
            return

        # 异步喂入 stdin（如 packerfuzzer 的两处 input() 提问），与 stdout 读取
        # 流水线并行，避免互相阻塞造成死锁。写入后关闭以触发 EOF。
        if tool.stdin_input and proc.stdin is not None:
            async def _feed_stdin() -> None:
                try:
                    proc.stdin.write(tool.stdin_input.encode("utf-8", errors="ignore"))
                    await proc.stdin.drain()
                    proc.stdin.close()
                except Exception:
                    pass
            asyncio.create_task(_feed_stdin())

        # 双重超时：
        #  - idle：单块输出的等待上限，卡死无输出时能兜底
        #  - 总时长：工具从启动到结束的绝对上限。
        #    仅靠 idle 是不够的——像 enscan 这类工具会每 10 秒刷一行
        #    "需要安全验证"，输出不断流，idle 永不触发，进程将无限跑下去。
        total = tool.tool_timeout or config.TOOL_TIMEOUT
        deadline = time.time() + total
        truncated = False
        lines = 0
        limit = config.MAX_OUTPUT_LINES

        try:
            buf = ""
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    proc.kill()
                    yield {"type": "error",
                           "data": f"工具执行超过总时长上限（{total}s），已终止"}
                    break
                # 按块读取而不是 readline：dirsearch 等工具用 \r 刷新进度条，
                # 积压成超长行会把 readline 的 64KB 缓冲打爆（Separator not found）。
                try:
                    chunk = await asyncio.wait_for(
                        proc.stdout.read(4096),
                        timeout=min(remaining, config.TOOL_IDLE_TIMEOUT),
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    yield {"type": "error",
                           "data": f"工具超过 {config.TOOL_IDLE_TIMEOUT}s 无输出，已终止"}
                    break
                if not chunk:
                    break
                buf += _decode(chunk)
                # 按 \r\n / \n / \r 切行，进度条也能实时流出
                while True:
                    m = re.search(r"\r\n|\n|\r", buf)
                    if not m:
                        break
                    line, buf = buf[: m.start()], buf[m.end():]
                    if not line.strip():
                        continue
                    lines += 1
                    if lines > limit:
                        # 只丢弃多余行，保留已回传的部分，避免撑爆上下文
                        truncated = True
                        continue
                    yield {"type": "output", "data": line}
            # 进程结束后冲刷残余缓冲（最后一行可能不带换行符）
            if buf.strip():
                lines += 1
                if lines <= limit:
                    yield {"type": "output", "data": buf}
                else:
                    truncated = True
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
            if truncated:
                yield {"type": "output",
                       "data": f"（输出超过 {limit} 行，已截断，仅保留前 {limit} 行）"}
            yield {"type": "exit", "code": proc.returncode}
        except Exception as e:
            yield {"type": "error", "data": f"执行异常：{e}"}
            try:
                proc.kill()
            except Exception:
                pass

    # ---------- 图形界面工具启动 ----------
    async def launch(self, tool: Tool) -> dict:
        """启动图形界面工具。完全复刻工具箱原有分派逻辑，不取回输出。"""
        if not tool.executable:
            return {"ok": False, "message": f"工具文件不存在：{tool.name}"}

        ttype = tool.type
        exe = tool.executable
        cwd = tool.workdir

        try:
            if ttype == "Python":
                python_exe = str(config.TOOLBOX_PYTHON)
                proc = await asyncio.create_subprocess_exec(
                    python_exe, exe, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            elif ttype.startswith("JAVA"):
                is_gui = "图形化" in ttype
                java_bin = config.JAVA8_BIN if "8" in ttype else config.JAVA11_BIN
                java_exe = java_bin / ("javaw.exe" if is_gui else "java.exe")
                if not java_exe.exists():
                    java_exe = Path("javaw" if is_gui else "java")
                args = ["-jar", exe]
                proc = await asyncio.create_subprocess_exec(
                    str(java_exe), *args, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            elif Path(exe).suffix.lower() == ".vbs":
                proc = await asyncio.create_subprocess_exec(
                    "wscript", exe, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    exe, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            return {"ok": True, "pid": proc.pid, "message": f"已启动 {tool.name}"}
        except Exception as e:
            return {"ok": False, "message": f"启动失败：{e}"}


executor = LocalExecutor()
