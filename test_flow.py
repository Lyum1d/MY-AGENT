# -*- coding: utf-8 -*-
"""v017.5 流程绕过检测回归：本地 HTTP server 夹具。

    python test_flow.py

网络：仅访问 127.0.0.1 随机端口夹具。
夹具行为：
  /flow/step1  → 200（前置步骤，需登录）
  /flow/step2?code=X → 需登录；secure 模式校验 code（X=ok 才 200）
  /bug/step2   → 只要带登录就 200（模拟「跳过前置仍成功」的缺陷后端）
"""
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_flow_test_"))
scope_file = _TMP / "scope_v0175.json"
scope_file.write_text(json.dumps({"targets": [{"host": "127.0.0.1"}]}), encoding="utf-8")
config.SCOPE_FILE = scope_file

import asyncio                                           # noqa: E402
from app import flowtest                                 # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        authed = bool(self.headers.get("Authorization"))
        if self.path.startswith("/flow/step1"):
            if authed:
                self._json(200, {"step": 1, "state": "done"})
            else:
                self._json(401, {"error": "unauthorized"})
        elif self.path.startswith("/flow/secure/step2"):
            # 安全后端：必须带 code=ok（前置产物），否则 403
            if not authed:
                self._json(401, {"error": "unauthorized"})
            elif "code=ok" in self.path:
                self._json(200, {"step": 2, "result": "submitted"})
            else:
                self._json(403, {"error": "missing code"})
        elif self.path.startswith("/bug/step2"):
            # 缺陷后端：只要带登录就 200（前置可跳过）
            if authed:
                self._json(200, {"step": 2, "result": "submitted"})
            else:
                self._json(401, {"error": "unauthorized"})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

AUTH = {"Authorization": "T1"}
NOAUTH = {}


def run(coro):
    return asyncio.run(coro)


print("== A. 流程保护有效（安全后端） ==")
steps_secure = [
    {"url": f"{BASE}/flow/step1", "method": "GET", "body": ""},
    {"url": f"{BASE}/flow/secure/step2?code=ok", "method": "GET", "body": ""},
]
r1 = run(flowtest.run_flow_check(steps_secure, AUTH, {}))
check("按序执行 → flow_protected（跳步/匿名均被拒）",
      r1["verdict"] == "flow_protected", r1["verdict"])

print("== B. 跳步绕过（缺陷后端） ==")
steps_bug = [
    {"url": f"{BASE}/flow/step1", "method": "GET", "body": ""},
    {"url": f"{BASE}/bug/step2", "method": "GET", "body": ""},
]
r2 = run(flowtest.run_flow_check(steps_bug, AUTH, {}))
check("跳步仍成功 → suspect_flow_bypass", r2["verdict"] == "suspect_flow_bypass", r2)

print("== C. 未授权线索（匿名直访成功） ==")
# 变体：目标端点匿名也 200（模拟无需登录的敏感接口）
class Fixture2(Fixture):
    def do_GET(self):
        if self.path.startswith("/bug/step2"):
            self._json(200, {"step": 2, "result": "leaked"})
            return
        super().do_GET()


srv2 = ThreadingHTTPServer(("127.0.0.1", 0), Fixture2)
BASE2 = f"http://127.0.0.1:{srv2.server_address[1]}"
threading.Thread(target=srv2.serve_forever, daemon=True).start()
steps_leak = [
    {"url": f"{BASE2}/flow/step1", "method": "GET", "body": ""},
    {"url": f"{BASE2}/bug/step2", "method": "GET", "body": ""},
]
r3 = run(flowtest.run_flow_check(steps_leak, AUTH, {}))
check("匿名直访成功 → suspect_unauthorized", r3["verdict"] == "suspect_unauthorized", r3)

print("== D. 基准不可信 ==")
steps_bad = [
    {"url": f"{BASE}/flow/step1", "method": "GET", "body": ""},
    {"url": f"{BASE}/flow/secure/step2?code=bad", "method": "GET", "body": ""},
]
r4 = run(flowtest.run_flow_check(steps_bad, AUTH, {}))
check("基准链路失败 → flow_invalid", r4["verdict"] == "flow_invalid", r4)
r5 = run(flowtest.run_flow_check(steps_bad, NOAUTH, {}))
check("基准前置 401（匿名跑）→ flow_invalid", r5["verdict"] == "flow_invalid", r5)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
