# -*- coding: utf-8 -*-
"""py_exec 沙箱回归（v010 P0-1）。

为什么单独一个文件：py_exec 是「模型直出任意 Python」的通道，v010 之前
子进程完整继承宿主环境变量（凭据整锅端）、proc.kill() 只杀直接子进程
（脚本再起的进程会残留）。这组用例钉住三条沙箱防线不被后续重构悄悄拆掉：

    python test_sandbox.py

不做任何网络请求、不碰真实目标：env 构造为纯函数测试，杀树用例只对
本机自起的 sleep 子进程。
"""
import asyncio
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402
from app.pyexec import (build_sandbox_env,               # noqa: E402
                        _WinJobTree, _load_env_allow_extra)

# 把 TEMP/TMP 等改道临时目录，防止测试触碰真实 data/（沿用套件惯例）
_TMP = Path(__import__("tempfile").mkdtemp(prefix="src_agent_sandbox_test_"))
config.PY_EXEC_TMP_ROOT = _TMP
config.PY_EXEC_ENV_ALLOW_JSON = _TMP / "allow.json"

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


# ---------------------------------------------------------------------------
print("=== 1. 环境变量白名单（凭据不得进入子进程）===")
# 在测试进程里伪造一批「宿主敏感变量」，断言它们不会漏进沙箱 env
_PROBE_VARS = {
    "DEEPSEEK_API_KEY": "sk-FAKEKEY000111222",
    "FOFA_KEY": "fake-fofa-key",
    "FOFA_EMAIL": "x@y.z",
    "HTTP_PROXY": "http://127.0.0.1:9999",
    "HTTPS_PROXY": "http://127.0.0.1:9999",
    "SRC_AGENT_SECRET_TEST": "top-secret-value",
    "GITHUB_TOKEN": "ghp_FAKEfakeFAKEfake",
}
_orig = {k: os.environ.get(k) for k in _PROBE_VARS}
for k, v in _PROBE_VARS.items():
    os.environ[k] = v
try:
    env = build_sandbox_env(_TMP)
    for k, v in _PROBE_VARS.items():
        check(f"敏感变量不继承：{k}", k not in env)
    leak = [k for k, v in env.items() if "FAKE" in str(v) or "fake-fofa" in str(v)]
    check("无任何伪造凭据值泄漏", not leak, leak)
    check("PATH 被替换为精简系统目录", env.get("PATH", "").endswith("v1.0"), env.get("PATH"))
    check("TEMP/TMP 指向沙箱工作目录", env.get("TEMP") == str(_TMP) and env.get("TMP") == str(_TMP))
    check("SystemRoot 必须存在（否则 python 起不来）", bool(env.get("SystemRoot")))
    check("PYTHONUTF8 已强制开启", env.get("PYTHONUTF8") == "1")
    check("返回的 env 与 os.environ 无共享（改副本不影响宿主）",
          env is not os.environ)
finally:
    for k, v in _orig.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

print("=== 2. 用户扩展白名单 ===")
config.PY_EXEC_ENV_ALLOW_JSON.write_text(
    '["MY_TOOL_TOKEN", "BAD JSON BINDING"]', encoding="utf-8")
os.environ["MY_TOOL_TOKEN"] = "user-allowed-value"
try:
    env2 = build_sandbox_env(_TMP)
    check("用户显式允许的变量被注入", env2.get("MY_TOOL_TOKEN") == "user-allowed-value")
    check("扩展文件里非字符串项被忽略", "BAD JSON BINDING" not in env2)
finally:
    os.environ.pop("MY_TOOL_TOKEN", None)
    config.PY_EXEC_ENV_ALLOW_JSON.write_text("{ broken", encoding="utf-8")
    env3 = build_sandbox_env(_TMP)
    check("扩展文件损坏 → 退回内置白名单（不炸）", env3.get("PATH") == env.get("PATH"))
config.PY_EXEC_ENV_ALLOW_JSON = _TMP / "no_such_allow.json"

print("=== 3. Job Object 进程树终止（真实子进程）===")
if os.name != "nt":
    print("  （非 Windows 环境，跳过杀树用例）")
else:
    import subprocess
    job = _WinJobTree()
    check("Job Object 句柄创建成功", job.job is not None)
    if job.job is not None:
        # 用同步 Popen（避免 asyncio subprocess 跨事件循环 wait 永远挂起的坑）。
        # 时序关键：child 先睡 1.5s 再创建孙子 —— 保证孙子在 assign **之后**
        # 创建，从而按 Job 的继承语义自动入 Job（assign 之前创建的进程不会
        # 被追溯加入，那是调用方时序错误，不是 Job 的问题）。
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import subprocess,sys,time\n"
             "time.sleep(1.5)\n"
             "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
             "print('grandchild', p.pid, flush=True)\n"
             "time.sleep(60)\n"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assigned = job.assign(child.pid)
        check("子进程已挂入 Job", assigned)
        import re as _re
        line = child.stdout.readline().strip()   # 等 child 真的创建出孙子
        _m = _re.search(r"grandchild (\d+)", line)
        check("孙子进程已创建（assign 之后，自动继承入 Job）", bool(_m), line)

        t0 = time.monotonic()
        job.close()          # KILL_ON_JOB_CLOSE → 整树（child + grandchild）终止
        try:
            child.wait(timeout=8)
            died = True
        except subprocess.TimeoutExpired:
            died = False
            child.kill()
            child.wait()
        dt = time.monotonic() - t0
        check("关闭 Job 句柄后子进程被终止（<8s）", died and dt < 8, f"{dt:.2f}s")

        # 孙子也要没：整树终止是 Job 相比 proc.kill() 的核心价值。
        # 注意：进程对象终止后其内核对象要等所有句柄释放才消失，且系统负载
        # 高时终止通知有延迟——全量回归并发跑时此处曾偶发误报，故给 3 次重试。
        if _m:
            import ctypes
            gpid = int(_m.group(1))

            def _grand_alive(pid: int) -> bool:
                h = ctypes.windll.kernel32.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE
                if not h:
                    return False      # 进程已不存在
                w = ctypes.windll.kernel32.WaitForSingleObject(h, 0)
                ctypes.windll.kernel32.CloseHandle(h)
                return w == 0x00000102   # WAIT_TIMEOUT = 还活着

            grand_alive = True
            for _ in range(3):
                grand_alive = _grand_alive(gpid)
                if not grand_alive:
                    break
                time.sleep(0.5)   # 给内核清理时间再判一次
            check("孙子进程一并被终止（整树语义）", not grand_alive)
        job = None

    # taskkill 兜底路径存在性
    from app.pyexec import _kill_tree_fallback
    check("taskkill 杀树兜底函数存在且可导入", callable(_kill_tree_fallback))

print("=== 4. 沙箱配置自洽 ===")
check("pyexec.py 不再完整继承 os.environ",
      "env = dict(os.environ)" not in (ROOT / "app" / "pyexec.py").read_text(encoding="utf-8"))
check("run_py_exec 已接入沙箱 env 构造",
      "build_sandbox_env(workdir)" in (ROOT / "app" / "pyexec.py").read_text(encoding="utf-8"))
_cfgsrc = (ROOT / "app" / "config.py").read_text(encoding="utf-8")
check("配置里临时工作目录根默认在 data/scripts/tmp 下",
      "PY_EXEC_TMP_ROOT" in _cfgsrc and '"scripts" / "tmp"' in _cfgsrc)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
