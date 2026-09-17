# -*- coding: utf-8 -*-
"""云端外发脱敏回归（v010 P0-4）。

为什么单独一个文件：默认路由是「云端优先」，工具输出里的 Cookie/凭据/隐私
会原样进入云端 LLM 请求。这组用例钉住 redact 的规则、模式语义与「不污染原文」
三条契约，防止后续调正则时把其中一条改丢：

    python test_redact.py

纯字符串处理，无网络请求。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config, redact   # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


_ORIG_MODE = config.CLOUD_EGRESS_MODE

# ---------------------------------------------------------------------------
print("=== 1. 脱敏规则命中 ===")
cases = [
    # (原文, 必须出现在脱敏结果里的占位符, 原文片段必须消失)
    ("Cookie: session=abc123def; path=/", "[REDACTED_COOKIE]", "abc123def"),
    ("Set-Cookie: sid=xyz; HttpOnly", "[REDACTED_COOKIE]", "sid=xyz; HttpOnly"[:6]),
    ("Authorization: Bearer eyJhbGciOiJub25lIn0.ABC.ABCdef12345678", "[REDACTED_AUTH]",
     "eyJhbGciOiJub25lIn0.ABC.ABCdef12345678"),
    ("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.aBcDeFgHiJkLmNoPqRsT",
     "[REDACTED_JWT]", "aBcDeFgHiJkLmNoPqRsT"),
    ("password=Admin@123! 不许泄漏", "[REDACTED_SECRET]", "Admin@123!"),
    ('"api_key": "sk-abcdef123456"', "[REDACTED_SECRET]", "sk-abcdef123456"),
    ("access_token: AT-999888777", "[REDACTED_SECRET]", "AT-999888777"),
    ("管理员邮箱 admin@jiaoyu.cn 请联系", "[REDACTED_EMAIL]@jiaoyu.cn", "admin@jiaoyu.cn"),
    ("拨打电话 13812345678 核实", "[REDACTED_PHONE]", "13812345678"),
]
for text, must_have, must_lose in cases:
    out, n = redact.redact_text(text)
    check(f"命中脱敏：{text[:28]}…", must_have in out and must_lose not in out,
          out[:60])

print("=== 2. 正常内容零误伤 ===")
clean_cases = [
    "https://www.jiaoyu.cn/admin/login.php",
    "目标 192.168.0.1 开放 80/443 端口",
    "SQLite version 3.45.0, Python 3.13",
    "版本号 13812.345678 无关手机号",
    "普通中文说明，无任何敏感信息。",
]
for text in clean_cases:
    out, n = redact.redact_text(text)
    check(f"零误伤：{text[:28]}…", n == 0 and out == text, f"hits={n}")

print("=== 3. 模式语义 ===")
config.CLOUD_EGRESS_MODE = "redact"
check("redact：云端可用", redact.cloud_allowed() is True)
check("redact 模式识别", redact.egress_mode() == "redact")
config.CLOUD_EGRESS_MODE = "local_only"
check("local_only：云端不可用", redact.cloud_allowed() is False)
config.CLOUD_EGRESS_MODE = "allow"
check("allow：云端可用", redact.cloud_allowed() is True)
config.CLOUD_EGRESS_MODE = "unknown-garbage"
check("未知模式按 redact 处理（宁严不松）", redact.egress_mode() == "redact")
config.CLOUD_EGRESS_MODE = _ORIG_MODE

print("=== 4. egress_messages 深拷贝契约 ===")
config.CLOUD_EGRESS_MODE = "redact"
orig_msgs = [
    {"role": "user", "content": "测试 jiaoyu.cn"},
    {"role": "tool", "tool_call_id": "t1",
     "content": "Cookie: sid=keepme-original; HttpOnly"},
    {"role": "assistant", "content": "",
     "tool_calls": [{"id": "c1", "type": "function",
                     "function": {"name": "py_exec",
                                  "arguments": "{\"code\": \"pwd=Secret123\"}"}}]},
]
import copy as _copy
snapshot = _copy.deepcopy(orig_msgs)
new_msgs, hits = redact.egress_messages(orig_msgs)
check("原文 messages 不被修改", orig_msgs == snapshot)
check("副本中凭据已被打码", "[REDACTED_COOKIE]" in new_msgs[1]["content"])
check("tool_calls.arguments 字符串也脱敏",
      "Secret123" not in new_msgs[2]["tool_calls"][0]["function"]["arguments"])
check("命中计数正确（Cookie + pwd = 2）", hits == 2, hits)
empty, h0 = redact.egress_messages([])
check("空消息列表安全", empty == [] and h0 == 0)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
