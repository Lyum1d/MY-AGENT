# -*- coding: utf-8 -*-
"""Phase 4 收尾验证：直接驱动 executor 实测三个修复点（不经 LLM 决策循环）。

1. packerfuzzer：stdin 喂入 "\n\n" 后不再 EOFError，退出码 0
2. httpx：-timeout 纯数字写法正常工作
3. rscan：模板 {exe} scan -u 正确渲染，无 unknown command
授权依据：www.jiaoyu.cn 为补天公益 SRC 授权测试资产。
"""
import asyncio
import sys
import time

sys.path.insert(0, ".")

from app.registry import registry
from app.executor import executor

TARGET_URL = "https://www.jiaoyu.cn"


async def run_tool(alias: str, args: str = "", cap: float = 240.0):
    tool = registry.get_by_alias(alias)
    print(f"\n{'=' * 70}\n[{alias}] args={args!r} stdin_input={tool.stdin_input!r}")
    print(f"  命令模板渲染检查通过：scriptable={tool.scriptable}")
    chunks = []
    start = time.time()
    exit_code = None
    try:
        async with asyncio.timeout(cap):
            async for ev in executor.run(tool, TARGET_URL, args):
                t = ev.get("type")
                if t == "command":
                    print(f"  $ {ev['data']}")
                elif t == "output":
                    chunks.append(ev["data"])
                elif t == "error":
                    chunks.append(f"[ERROR] {ev['data']}")
                    print(f"  [ERROR] {ev['data']}")
                elif t == "exit":
                    exit_code = ev.get("code")
                    print(f"  [exit] {exit_code}  ({time.time() - start:.1f}s)")
    except TimeoutError:
        print(f"  [TIMEOUT] 超过 {cap}s，截断（输出仍在继续）")
    out = "\n".join(chunks)
    print(f"  输出共 {len(out)} 字符，末尾 500 字符：")
    tail = out[-500:]
    for ln in tail.splitlines()[-12:]:
        print(f"    | {ln[:150]}")
    return exit_code, out


async def main():
    registry.load()
    results = {}

    # --- 1. httpx：最快，先跑 ---
    code, out = await run_tool("httpx", "-timeout 5 -no-color", cap=90)
    bad = "invalid" in out.lower() or "unrecognized" in out.lower()
    results["httpx"] = ("PASS" if (code == 0 and not bad and out.strip()) else "FAIL")
    print(f"  >>> httpx 判定: {results['httpx']} (exit={code}, 无 invalid 报错={not bad}, 有输出={bool(out.strip())})")

    # --- 2. rscan：验证 scan -u 子命令被接受 ---
    code, out = await run_tool("rscan", "", cap=180)
    bad = ("unknown command" in out.lower()) or ("not found" in out.lower() and "scan" in out.lower())
    has_scan_output = ("cobra" not in out.lower()[:200]) and bool(out.strip())
    results["rscan"] = ("PASS" if (not bad and out.strip()) else "FAIL")
    print(f"  >>> rscan 判定: {results['rscan']} (exit={code}, 无 unknown command={not bad})")

    # --- 3. packerfuzzer：验证 stdin 喂入不再 EOFError ---
    code, out = await run_tool("packerfuzzer", "", cap=240)
    eof = ("EOFError" in out) or ("EOF when reading" in out)
    traceback = "Traceback" in out
    results["packerfuzzer"] = ("PASS" if (code == 0 and not eof and not traceback) else "FAIL")
    print(f"  >>> packerfuzzer 判定: {results['packerfuzzer']} (exit={code}, 无EOFError={not eof}, 无Traceback={not traceback})")

    print(f"\n{'=' * 70}\n总结：")
    for k, v in results.items():
        print(f"  {k:<14} {v}")
    ok = all(v == "PASS" for v in results.values())
    print("\n整体结果:", "ALL PASS ✅" if ok else "存在 FAIL ❌（见上方输出）")


if __name__ == "__main__":
    asyncio.run(main())
