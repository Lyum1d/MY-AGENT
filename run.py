# -*- coding: utf-8 -*-
"""启动 SRC 渗透 Agent 控制台。

用法：
    python run.py
    python run.py --port 8770
"""
import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn  # noqa: E402

from app import config  # noqa: E402


def _open_browser_when_ready(host: str, port: int, timeout: float = 30.0) -> None:
    """等后端端口真正可连接后再打开浏览器。

    修复「启动后未连接后端」：此前 webbrowser.open 先于 uvicorn 监听执行，
    浏览器加载时后端尚未就绪，前端健康检查失败显示未连接。
    """
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                time.sleep(0.5)  # 端口通了再给应用半秒完成初始化
                webbrowser.open(url)
                print(f"  浏览器已打开：{url}")
                return
        except OSError:
            time.sleep(0.4)
    print(f"  后端 {timeout}s 内未就绪，请手动打开：{url}")


def main():
    parser = argparse.ArgumentParser(description="SRC 渗透 Agent 控制台")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.PORT)
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args()

    print("=" * 60)
    print("  SRC 渗透 Agent · 本地控制台")
    print("=" * 60)
    print(f"  工具箱：{config.TOOLBOX_ROOT}")
    print(f"  工具箱存在：{config.TOOLBOX_ROOT.exists()}")
    print(f"  模型：{config.OLLAMA_MODEL} @ {config.OLLAMA_BASE_URL}")
    print(f"  地址：http://{args.host}:{args.port}")
    print("=" * 60)
    print("  仅限已获得书面授权的目标测试。")
    print("=" * 60)

    if not args.no_browser:
        threading.Thread(target=_open_browser_when_ready,
                         args=(args.host, args.port), daemon=True).start()

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
