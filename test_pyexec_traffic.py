# -*- coding: utf-8 -*-
"""v023.2 回归：py_exec 受控网络通道 + 扫描器速率声明。

    python test_pyexec_traffic.py

网络：只访问 127.0.0.1 随机端口夹具（scope 白名单含 127.0.0.1）。
"""
import asyncio
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

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_pyet_"))
config.SCOPE_FILE = _TMP / "scope_v0232.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.PY_EXEC_TMP_ROOT = _TMP / "tmp"
config.PY_EXEC_DIR = _TMP / "scripts"
config.TRAFFIC_TEST_MODE = False
config.TRAFFIC_MAX_REQUESTS = 100
config.TRAFFIC_BURST = 100
config.PY_EXEC_MAX_REQUESTS = 3          # 便于验证脚本预算
config.PY_EXEC_REQUEST_TIMEOUT = 10

from app import pyexec, pyexec_bridge, store, traffic     # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


class Fixture(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Fixture.hits.append(self.path)
        body = json.dumps({"path": self.path, "n": len(Fixture.hits)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

print("== A. 静态检测（事故模式识别） ==")
d1 = pyexec_bridge.detect_direct_network(
    "import requests\nfor i in range(50):\n    requests.get('https://x.com/a.zip')\n")
check("网络库+循环+URL → risky", d1["risky"] is True, d1)
d2 = pyexec_bridge.detect_direct_network("import requests\nrequests.get('https://x.com/a')\n")
check("网络库但无循环 → 不算事故模式", d2["risky"] is False, d2)
d3 = pyexec_bridge.detect_direct_network(
    "from srcagent import safe_http_request\nfor i in range(3):\n    safe_http_request('https://x.com')\n")
check("受控接口 + 循环 → 不算事故模式（这是推荐用法）", d3["risky"] is False, d3)
d4 = pyexec_bridge.detect_direct_network("import socket\nfor i in range(9):\n    socket.socket()\n")
check("socket 也算网络库", d4["has_net_lib"] is True, d4)

print("== B. safe 模式拒绝事故脚本 ==")
code_bad = ("import requests\n"
            "for i in range(50):\n"
            "    requests.get('" + BASE + "/x' + str(i))\n")
evs = []


async def _run_bad():
    async for ev in pyexec.run_py_exec(code_bad, target="127.0.0.1"):
        evs.append(ev)
asyncio.run(_run_bad())
types = [e["type"] for e in evs]
check("事故脚本被拒绝（error + 126）",
      "error" in types and any(e.get("code") == 126 for e in evs), types)
check("拒绝原因提到受控接口 safe_http_request",
      any("safe_http_request" in str(e.get("data", "")) for e in evs))
check("脚本未实际发出请求", len(Fixture.hits) == 0, Fixture.hits)

print("== C. 受控通道：safe_http_request 正常取回响应 ==")
code_ok = ("from srcagent import safe_http_request\n"
           f"r = safe_http_request('{BASE}/api/a')\n"
           "print('STATUS', r.get('status_code'))\n"
           "print('BODY', (r.get('text') or '')[:40])\n")
evs2 = []


async def _run_ok():
    async for ev in pyexec.run_py_exec(code_ok, target="127.0.0.1"):
        evs2.append(ev)
asyncio.run(_run_ok())
out = "\n".join(str(e.get("data", "")) for e in evs2)
check("脚本拿到 200 与响应体",
      "STATUS 200" in out and "/api/a" in out, out[-200:])
check("实际请求已发出（夹具收到 1 次）", len(Fixture.hits) == 1, Fixture.hits)
exit_codes = [e.get("code") for e in evs2 if e["type"] == "exit"]
check("脚本正常退出 0", exit_codes == [0], exit_codes)

print("== D. 脚本请求预算（宿主侧计数，脚本绕不过） ==")
Fixture.hits.clear()
code_over = ("from srcagent import safe_http_request\n"
             "for i in range(5):\n"
             "    r = safe_http_request('" + BASE + "/api/n' + str(i))\n"
             "    print('GOT', r.get('status_code') or r.get('error'))\n")
evs3 = []


async def _run_over():
    async for ev in pyexec.run_py_exec(code_over, target="127.0.0.1"):
        evs3.append(ev)
asyncio.run(_run_over())
out3 = "\n".join(str(e.get("data", "")) for e in evs3)
check("超预算后返回 TRAFFIC_BUDGET_EXCEEDED", "TRAFFIC_BUDGET_EXCEEDED" in out3,
      out3[-260:])
check("夹具最多收到预算数量 3 次", len(Fixture.hits) <= 3, len(Fixture.hits))
check("预算耗尽后脚本被终止（error 事件）", any(e["type"] == "error" for e in evs3))

print("== E. 写方法在脚本通道被拒 ==")
Fixture.hits.clear()
code_post = ("from srcagent import safe_http_request\n"
             f"r = safe_http_request('{BASE}/api/w', method='POST', body='a=1')\n"
             "print('R', r.get('error'))\n")
evs4 = []


async def _run_post():
    async for ev in pyexec.run_py_exec(code_post, target="127.0.0.1"):
        evs4.append(ev)
asyncio.run(_run_post())
out4 = "\n".join(str(e.get("data", "")) for e in evs4)
check("POST 被拒（WRITE_METHOD_NOT_ALLOWED_IN_SCRIPT）",
      "WRITE_METHOD_NOT_ALLOWED" in out4, out4[-200:])

print("== F. 目标暂停 → 脚本终止 ==")
Fixture.hits.clear()
traffic.governor.pause("127.0.0.1", "测试暂停")
code_held = ("from srcagent import safe_http_request\n"
             f"r = safe_http_request('{BASE}/api/held')\n"
             "print('R', r.get('error'))\n"
             "import time; time.sleep(20)\n")
evs5 = []


async def _run_held():
    async for ev in pyexec.run_py_exec(code_held, target="127.0.0.1"):
        evs5.append(ev)
import time as _t                                    # noqa: E402
t0 = _t.monotonic()
asyncio.run(_run_held())
elapsed = _t.monotonic() - t0
out5 = "\n".join(str(e.get("data", "")) for e in evs5)
check("暂停后受控请求被拒（TRAFFICPAUSED）", "TRAFFICPAUSED" in out5.upper(), out5[-200:])
check("脚本被提前终止（未跑满 sleep 20）", elapsed < 15, f"{elapsed:.1f}s")
check("暂停期间夹具未收到请求", len(Fixture.hits) == 0, Fixture.hits)
traffic.governor.resume("127.0.0.1")

print("== G. 扫描器声明（network_control） ==")
from app import registry                             # noqa: E402
reg = registry.ToolRegistry()
reg.load()
from app.registry import Tool                        # noqa: E402
t_declared = Tool(name="假扫描器", alias="fake_scanner", category="扫描", type="命令行",
                  rel_path="x.exe", scriptable=True, executable="builtin://x",
                  allowed_flags=["-rate-limit", "-t"],
                  network_control={"declared": True, "supports_rate": True,
                                   "supports_concurrency": True,
                                   "rate_flags": ["-rate-limit"],
                                   "concurrency_flags": ["-t"],
                                   "traffic_class": "high"})
from app.executor import _apply_network_control       # noqa: E402
new_args, notes = _apply_network_control(t_declared, "")
check("已声明工具注入速率与并发参数",
      "-rate-limit 5" in new_args and "-t 2" in new_args, new_args)
check("注入有说明", len(notes) >= 1, notes)
new_args2, _ = _apply_network_control(t_declared, "-rate-limit 1")
check("用户显式给出则不覆盖", new_args2.count("-rate-limit") == 1, new_args2)
t_whitelist_miss = Tool(name="白名单未含", alias="fake2", category="扫描", type="命令行",
                        rel_path="x.exe", scriptable=True, executable="builtin://x",
                        allowed_flags=["--other"],
                        network_control={"declared": True, "supports_rate": True,
                                         "rate_flags": ["-rate-limit"]})
_, notes2 = _apply_network_control(t_whitelist_miss, "")
check("注入旗标不在白名单 → 明确提示（不静默）",
      any("allowed_flags" in n for n in notes2), notes2)
t_undeclared = Tool(name="未声明", alias="fake3", category="扫描", type="命令行",
                    rel_path="x.exe", scriptable=True, executable="builtin://x")
check("未声明工具 network_control 为空 dict",
      (t_undeclared.network_control or {}) == {})

print("== H. 真实 overrides 声明解析 ==")
reg.loaded = True
reg.load()
declared = sorted(t.alias for t in reg.tools if (t.network_control or {}).get("declared"))
# v023.6：httpx/ehole 已按实战反馈补声明（此前为空、全部走警告路径）
check("已声明工具包含 httpx 与 ehole（v023.6 补声明后）",
      {"httpx", "ehole"} <= set(declared), declared)
undeclared = [t.alias for t in reg.tools
              if not (t.network_control or {}).get("declared")
              and t.risk_level in ("L2", "L3") and t.scriptable]
check("仍有未声明的 L2/L3 工具（待补，但已在清单里提示）",
      len(undeclared) > 0, len(undeclared))
reg.loaded = True
reg.load()

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
