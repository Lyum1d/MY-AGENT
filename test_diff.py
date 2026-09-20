# -*- coding: utf-8 -*-
"""v017.3 只读身份差分回归：本地 HTTP server 夹具 + 判定逻辑单测。

    python test_diff.py

网络：只访问 127.0.0.1 随机端口的本机夹具服务（scope 白名单加入 127.0.0.1），
不碰任何外部目标。
"""
import json
import re
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# v023.1 起所有出网请求走统一流量调度器（默认 10 分钟 30 请求 / 10 秒 5 突发）。
# 本套件对本地 fixture 的请求量会超突发阈值——测试模式显式放大（生产不设即保守）。
import os
os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_diff_test_"))

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


# ---------------------------------------------------------------------------
print("== A. 本地夹具服务 ==")
# 三类行为，由 token 决定（模拟真实鉴权）：
#   token=OWNER_TOKEN + /api/order/<自有id>     → 200 返回该订单（归属 user_a）
#   token=OWNER_TOKEN + /api/order/<他人id>     → 403（正常拒绝场景）
#   无 token + 任意                             → 401
#   /api/order/20002 公开接口                   → 200 返回数据（未授权场景）
ORDER_DATA = {
    "20001": {"orderId": 20001, "userId": 10001, "item": "教材一", "price": 42},
    "20002": {"orderId": 20002, "userId": 10002, "item": "教材二", "price": 55},
}
PUBLIC = {"orderId": 20002, "public": True}


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *a):      # 静默
        pass

    def do_GET(self):
        token = self.headers.get("Authorization", "")
        m = re.search(r"/api/order/(\d+)", self.path)
        oid = m.group(1) if m else ""
        if self.path.startswith("/api/public/order/"):
            body = json.dumps(PUBLIC).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not token:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": "unauthorized"}')
            return
        if oid in ORDER_DATA and ORDER_DATA[oid]["userId"] == 10001:
            body = json.dumps(ORDER_DATA[oid]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"error": "forbidden"}')


srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{port}"

scope_file = _TMP / "scope_v0173.json"
scope_file.write_text(json.dumps({"targets": [{"host": "127.0.0.1"}]}), encoding="utf-8")
config.SCOPE_FILE = scope_file

import asyncio                                          # noqa: E402
from app import difftest                                # noqa: E402


def run(coro):
    return asyncio.run(coro)


print("== B. 判定逻辑：三类夹具场景 ==")

# 场景 1：正常拒绝——A 访问他人订单 → 403
base_ok = run(difftest.execute_readonly(f"{BASE}/api/order/20001", "GET",
                                        {"Authorization": "OWNER"}, None))
var_denied = run(difftest.execute_readonly(f"{BASE}/api/order/20002", "GET",
                                           {"Authorization": "OWNER"}, None))
v1 = difftest.classify(base_ok, var_denied, "20002")
check("正常拒绝 → access_denied（不产生候选）", v1["verdict"] == "access_denied", v1)

# 场景 2：真实越权——模拟后端缺陷：owner 校验只查登录不查归属（用 ALLOW 夹具）
# 夹具无法同时表达两种后端，用独立端点 /api/bug/order/<id>：任何登录 token 都返回订单
class Fixture2(Fixture):
    def do_GET(self):
        m = re.search(r"/api/bug/order/(\d+)", self.path)
        if m and self.headers.get("Authorization"):
            oid = m.group(1)
            body = json.dumps(ORDER_DATA.get(oid, PUBLIC)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


srv2 = ThreadingHTTPServer(("127.0.0.1", 0), Fixture2)
BASE2 = f"http://127.0.0.1:{srv2.server_address[1]}"
threading.Thread(target=srv2.serve_forever, daemon=True).start()

base2 = run(difftest.execute_readonly(f"{BASE2}/api/bug/order/20001", "GET",
                                      {"Authorization": "OWNER"}, None))
var2 = run(difftest.execute_readonly(f"{BASE2}/api/bug/order/20002", "GET",
                                     {"Authorization": "OWNER"}, None))
v2 = difftest.classify(base2, var2, "20002")
check("真实跨用户数据 → suspect_idor", v2["verdict"] == "suspect_idor", v2)
check("证据含变体归属字段（userId=10002）",
      any(k.lower().startswith("user") and v == "10002"
          for k, v in v2.get("variant_owners", [])), v2.get("variant_owners"))

# 场景 3：公开数据——无归属差异 → no_diff
pub1 = run(difftest.execute_readonly(f"{BASE}/api/public/order/20002", "GET",
                                     {"Authorization": "OWNER"}, None))
pub2 = run(difftest.execute_readonly(f"{BASE}/api/public/order/20002", "GET",
                                     {"Authorization": "OWNER"}, None))
v3 = difftest.classify(pub1, pub2, "20002")
check("公开数据 → no_diff（不误报）", v3["verdict"] == "no_diff", v3)

# 场景 4：基准失败 → invalid_baseline
bad_base = {"status_code": 401}
v4 = difftest.classify(bad_base, var_denied, "20002")
check("基准 401 → invalid_baseline（结果不可信）", v4["verdict"] == "invalid_baseline")

print("== C. 对象替换 ==")
rec = {"url": "https://example.com/api/order/20001/detail?full=1",
       "method": "GET", "body": ""}
r1 = difftest.apply_replacement(rec, "order", "path", "20002")
check("path 替换（语义段后数字）", "/api/order/20002/detail" in r1["url"], r1["url"])
rec2 = {"url": "https://example.com/api/detail?orderId=20001",
        "method": "GET", "body": ""}
r2 = difftest.apply_replacement(rec2, "orderId", "query", "20002")
check("query 替换", "orderId=20002" in r2["url"])
rec3 = {"url": "https://example.com/api/detail", "method": "POST",
        "body": '{"orderId": 20001}'}
r3 = difftest.apply_replacement(rec3, "orderId", "body", "20002")
check("body JSON 替换（保持数字类型）",
      json.loads(r3["body"])["orderId"] == 20002)

print("== D. 真实端到端：差分执行走 scope+限速 ==")
# 夹具服务在 scope 内（127.0.0.1），走 execute_readonly 完整路径
e1 = run(difftest.execute_readonly(f"{BASE2}/api/bug/order/20001", "GET",
                                   {"Authorization": "OWNER"}, None))
check("端到端执行成功（scope 放行 + 返回 JSON）",
      e1.get("status_code") == 200 and e1.get("body_json", {}).get("orderId") == 20001)
out = run(difftest.execute_readonly(f"{BASE}/api/order/1", "DELETE",
                                    {"Authorization": "OWNER"}, None))
check("写方法在模块层拒绝（硬白名单）", "error" in out and "只读" in out["error"])
out2 = run(difftest.execute_readonly("http://evil.com/x", "GET", {}, None))
check("scope 外 URL 拒绝", "error" in out2)

print("== E. 噪声过滤与稳定性 ==")
n1 = {"status_code": 200, "body_json": {"orderId": 1, "ts": 1, "traceId": "a"}}
n2 = {"status_code": 200, "body_json": {"orderId": 1, "ts": 2, "traceId": "b"}}
v5 = difftest.classify(n1, n2, "1")
check("仅噪声字段不同 → no_diff", v5["verdict"] == "no_diff", v5)

srv.shutdown()
srv2.shutdown()

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
