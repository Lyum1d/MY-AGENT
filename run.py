# -*- coding: utf-8 -*-
"""启动 SRC 渗透 Agent 控制台。

用法：
    python run.py
    python run.py --port 8770
"""
import argparse
import sys
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn  # noqa: E402

from app import config  # noqa: E402


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
        webbrowser.open(f"http://{args.host}:{args.port}")

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
