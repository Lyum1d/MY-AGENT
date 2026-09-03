# -*- coding: utf-8 -*-
"""探测各工具的真实命令行用法（--help / -h），用于校准调用模板。

只发 --help / -h，不产生任何扫描行为。
"""
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app import config                      # noqa: E402
from app.registry import registry           # noqa: E402
from app.executor import _decode            # noqa: E402

# 重点校准 SRC 常用工具
PROBE = [
    "enscan", "oneforall", "httpx", "ehole", "tidefinger", "p1finger",
    "veo_finger", "packerfuzzer", "dirsearch", "nuclei", "afrog",
    "fscan", "kscan", "xscan", "ez_scan", "dddd_scan", "rscan",
    "serein", "sharpscan", "springboot_scan", "golin_compliance",
]


async def run_help(exe: str, arg: str, cwd: str, prefix: list[str] | None = None):
    cmd = [*prefix, exe, arg] if prefix else [exe, arg]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        return _decode(out)
    except asyncio.TimeoutError:
        return "[超时]"
    except Exception as e:
        return f"[异常] {e}"


def base_cmd(tool):
    """构造最小可执行命令（不含业务参数）。"""
    if tool.type == "Python":
        return [str(config.TOOLBOX_PYTHON)], tool.executable
    if tool.type in ("JAVA8", "JAVA11"):
        jb = config.JAVA8_BIN if tool.type == "JAVA8" else config.JAVA11_BIN
        return [str(jb / "java.exe"), "-jar"], tool.executable
    return [], tool.executable


async def main():
    registry.load()
    for alias in PROBE:
        tool = registry.get_by_alias(alias)
        if not tool:
            print(f"\n=== {alias} === 未找到")
            continue
        prefix, exe = base_cmd(tool)
        print(f"\n{'=' * 66}")
        print(f"=== {alias}  <-  {tool.name}  [{tool.type}]")
        print(f"文件: {Path(tool.executable).name}")

        for flag in ("--help", "-h"):
            out = await run_help(exe, flag, tool.workdir, prefix)
            if out and not out.startswith("[") and len(out.strip()) > 20:
                # 提取关键行
                lines = [l.rstrip() for l in out.splitlines() if l.strip()]
                keep = []
                for l in lines[:40]:
                    if re.search(r"(Usage|用法|Flags|Options|参数|Examples|示例|-u|-t|-h |--)", l):
                        keep.append(l)
                print(f"--- {flag} ---")
                for l in (keep or lines)[:22]:
                    print(f"  {l[:150]}")
                break
            else:
                print(f"--- {flag} --- {out[:80]}")


if __name__ == "__main__":
    asyncio.run(main())
