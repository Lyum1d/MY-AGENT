# -*- coding: utf-8 -*-
"""启动 SRC 渗透 Agent 控制台。

用法：
    python run.py
    python run.py --port 8770
    python run.py --no-browser

解释器自愈（重要）：
    双击「启动控制台.bat」或在没有装依赖的 Python 下直接跑 run.py 时，
    常见症状是窗口一闪或报 ModuleNotFoundError（找不到 uvicorn / fastapi），
    看上去就是「程序打不开」。根因是探测到的解释器不是本工程的 venv。
    这里在启动前自查依赖：当前解释器不满足时，自动切换到带依赖的解释器并重启自身。
"""
import argparse
import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# 依赖自检只导这些：足以代表「装了项目依赖」的最小集合
_REQUIRED_IMPORTS = "import uvicorn, fastapi, httpx, pydantic"
_SELF_SCRIPT = Path(__file__).resolve()


def _has_deps(python: str) -> bool:
    """判断某个解释器是否装有项目依赖。"""
    if not python or not Path(python).exists():
        return False
    try:
        r = subprocess.run([python, "-c", _REQUIRED_IMPORTS],
                           capture_output=True, timeout=60)
    except Exception:
        return False
    return r.returncode == 0


def _candidates() -> list[str]:
    """可能装了依赖的解释器，按优先级排列。"""
    out: list[str] = []
    env_py = (os.environ.get("SRC_AGENT_PY") or "").strip()
    if env_py:
        out.append(env_py)
    # 1) 项目内 venv（开发机常规位置）
    out.append(str(ROOT / ".venv" / "Scripts" / "python.exe"))
    # 2) 本机 WorkBuddy 托管 venv（本工程实际使用的位置）
    home = os.environ.get("USERPROFILE") or str(Path.home())
    out.append(str(Path(home) / ".workbuddy" / "binaries" / "python"
                   / "envs" / "src-agent" / "Scripts" / "python.exe"))
    # 3) PATH 里的 python / python3
    for name in ("python", "python3"):
        found = shutil.which(name)
        if found:
            out.append(found)
    return out


def _bootstrap() -> None:
    """当前解释器缺依赖时，自动切换到可用解释器并重启自身。"""
    if os.environ.get("SRC_AGENT_REEXEC") == "1":
        return                      # 已重启过一次，不再递归
    if _has_deps(sys.executable):
        return

    me = Path(sys.executable).resolve()
    for cand in _candidates():
        try:
            if Path(cand).resolve() == me:
                continue
        except Exception:
            continue
        if not _has_deps(cand):
            continue
        print(f"[启动] 当前解释器 {sys.executable} 缺少项目依赖，已自动切换：")
        print(f"       {cand}")
        env = os.environ.copy()
        env["SRC_AGENT_REEXEC"] = "1"
        try:
            sys.exit(subprocess.call([cand, str(_SELF_SCRIPT)] + sys.argv[1:], env=env))
        except KeyboardInterrupt:
            sys.exit(130)


def _browser_url(host: str, port: int) -> str:
    """把监听地址转成浏览器可访问的地址（0.0.0.0 之类的通配地址换成回环）。"""
    h = host if host not in ("0.0.0.0", "::", "", "*") else "127.0.0.1"
    return f"http://{h}:{port}"


def _warn_if_exposed(host: str) -> None:
    """非回环绑定时给出显式警告。

    为什么要警告：本服务**没有任何鉴权层**（没有 token、没有会话校验、没有 CORS 限制），
    默认只绑 127.0.0.1，安全性依赖「只有本机能访问」这一条。一旦改绑 0.0.0.0 / 具体网卡地址，
    同网段任何人都能直接调用：启动工具箱内任意可执行文件、执行任意 Python 代码、
    对白名单内目标发起扫描——等价于把本机控制权交出去。
    """
    if host in ("127.0.0.1", "localhost", "::1"):
        return
    print("!" * 60)
    print("  ⚠ 正在监听非回环地址：{}".format(host))
    print("  本服务没有鉴权层，任何能访问该地址的人都能：")
    print("    · 启动工具箱内任意可执行文件")
    print("    · 提交并执行任意 Python 代码（L3 通道，仅需一次点击确认）")
    print("    · 对授权白名单内的目标发起扫描与请求")
    print("  仅在你能确定该网段可信时使用；否则请去掉 --host 参数走默认的 127.0.0.1。")
    print("!" * 60)


def _open_browser_when_ready(url: str, timeout: float = 30.0) -> None:
    """等后端真的能响应请求后，再打开浏览器。

    原先是在 uvicorn.run() 之前直接 webbrowser.open()——那一刻端口还没开始监听，
    浏览器打开就是「无法访问」，需要手动刷新一下才正常。这里改为后台线程轮询
    一个轻量接口（/api/models，不发起任何外部请求），拿到 200 再打开。

    注意：探测必须绕开系统代理（本机可能配了 HTTP_PROXY），否则请求会被代理劫持，
    与项目里其它 HTTP 客户端统一使用 trust_env=False 的做法保持一致。
    """
    import threading
    import time
    import urllib.request

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    probe = url + "/api/models"

    def worker() -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with opener.open(probe, timeout=2.0) as resp:
                    if resp.status == 200:
                        print(f"[启动] 服务已就绪，正在打开浏览器：{url}")
                        webbrowser.open(url)
                        return
            except Exception:
                time.sleep(0.25)
        # 兜底：超时也打开，让用户看到具体报错，而不是「什么都没发生」
        print(f"[启动] 等待服务就绪超时，仍尝试打开浏览器：{url}")
        webbrowser.open(url)

    threading.Thread(target=worker, daemon=True).start()


def main():
    _bootstrap()

    try:
        import uvicorn
    except ImportError:
        print("=" * 60)
        print("  启动失败：当前 Python 没有安装项目依赖。")
        print("=" * 60)
        print(f"  当前解释器：{sys.executable}")
        print("  请任选一种方式解决：")
        print("   1) 安装依赖：pip install -r requirements.txt")
        print("   2) 指定解释器：set SRC_AGENT_PY=<带依赖的 python.exe 路径>")
        print("   3) 使用已装好依赖的解释器：")
        for c in _candidates():
            print(f"        [{'√' if _has_deps(c) else '×'}] {c}")
        print("=" * 60)
        sys.exit(1)

    from app import config

    parser = argparse.ArgumentParser(description="SRC 渗透 Agent 控制台")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.PORT)
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args()

    url = _browser_url(args.host, args.port)

    print("=" * 60)
    print("  SRC 渗透 Agent · 本地控制台")
    print("=" * 60)
    print(f"  工具箱：{config.TOOLBOX_ROOT}")
    print(f"  工具箱存在：{config.TOOLBOX_ROOT.exists()}")
    print(f"  模型：{config.OLLAMA_MODEL} @ {config.OLLAMA_BASE_URL}")
    print(f"  地址：{url}")
    print("=" * 60)
    print("  仅限已获得书面授权的目标测试。")
    print("=" * 60)

    _warn_if_exposed(args.host)

    if not args.no_browser:
        _open_browser_when_ready(url)

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
