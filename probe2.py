# -*- coding: utf-8 -*-
"""第二轮探测：子命令用法 + 首轮未确定的工具。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app import config                      # noqa: E402
from app.registry import registry           # noqa: E402
from app.executor import _decode            # noqa: E402

# (别名, [附加参数...])
PROBE = [
    ("ehole", ["finger", "--help"]),
    ("ehole", ["finger"]),
    ("p1finger", ["finger", "--help"]),
    ("p1finger", []),
    ("rscan", []),
    ("enscan", ["--help"]),
    ("ez_scan", []),
    ("xscan", []),
    ("springboot_scan", ["--help"]),
    ("golin_compliance", ["--help"]),
    ("serein", ["--help"]),
    ("dddd_scan", ["-t", "127.0.0.1", "-h"]),
]


async def run(exe, extra, cwd, prefix=None, timeout=15):
    cmd = [*(prefix or []), exe, *extra]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return _decode(out)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return "[超时]"
    except Exception as e:
        return f"[异常] {e}"


def base_cmd(tool):
    if tool.type == "Python":
        return [str(config.TOOLBOX_PYTHON)], tool.executable
    if tool.type in ("JAVA8", "JAVA11"):
        jb = config.JAVA8_BIN if tool.type == "JAVA8" else config.JAVA11_BIN
        return [str(jb / "java.exe"), "-jar"], tool.executable
    return [], tool.executable


async def main():
    registry.load()
    for alias, extra in PROBE:
        tool = registry.get_by_alias(alias)
        if not tool:
            print(f"\n### {alias} 未找到")
            continue
        prefix, exe = base_cmd(tool)
        out = await run(exe, extra, tool.workdir, prefix)
        print(f"\n{'=' * 66}")
        print(f"### {alias}  <-  {tool.name}   参数: {extra}")
        lines = [l.rstrip() for l in out.splitlines() if l.strip()]
        for l in lines[:18]:
            print(f"  {l[:140]}")


if __name__ == "__main__":
    asyncio.run(main())
