# -*- coding: utf-8 -*-
"""v042 回归：截断标志恒存在 + 已知泄露模式索引 + 密钥材料处置固化。

    python test_042_fixes.py

依据（lsnu.edu.cn 第四轮实战）：
  ① **`truncated` 只在被截断时才出现** → 脚本不主动检查就**根本不知道有这回事**。
     实测在 128KB 的 JS 包上「靠长度巧合才发现被截断」，存在假阴性风险
     （与 v032 给 `error` 补默认值同源：**恒存在的键比按需出现的键更不容易误用**）。
  ② **「产品指纹 → 已知泄露模式」索引缺失**（agent 连续两轮提为 P0）——
     本轮靠它才把联奕认证平台的 `private_exponent` 定位下来，否则要凭记忆猜。
  ③ **密钥材料的处置未固化**：本轮正是靠「本地验算可用性 + 跨资产 modulus 比对」
     两步**零出网**分析，把结论从「可疑字符串」升级为「影响全部接入系统的私钥泄露」。

覆盖：
A. `truncated` 恒存在（未截断时为 False，且文档说明）
B. 指纹索引含「已知泄露模式速查」与联奕条目；含跨资产比对与本地验算的做法
C. SOP 含「拿到密钥材料必做两件事」
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import agent as agent_mod                        # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


br = Path(__import__("app.pyexec_bridge", fromlist=["x"]).__file__).read_text(encoding="utf-8")
SYS = agent_mod.SYSTEM_PROMPT

print("=" * 68)
print("A. truncated 字段恒存在")
print("=" * 68)
check("A1 resp 字面量里给出 truncated 默认值",
      '"truncated": False' in br)
check("A2 注释说明了「恒存在」的理由", "恒存在" in br and "假阴性" in br)
doc = __import__("app.pyexec_bridge", fromlist=["x"]).SCRIPT_MODULE_SOURCE
check("A4 脚本文档提到 truncated 字段", "truncated" in doc)
check("A5 仍保留截断时的完整告知（truncation_note）",
      "truncation_note" in br)

print()
print("B. 产品指纹索引：已知泄露模式 + 联奕条目 + 处置方法")
print("=" * 68)
idx = ROOT / "data" / "kb" / "product-fingerprint-index.md"
doc2 = idx.read_text(encoding="utf-8")
check("B1 含「已知泄露模式速查」小节", "已知泄露模式速查" in doc2)
check("B2 含联奕认证平台条目", "联奕" in doc2 and "lyuap" in doc2)
check("B3 联奕条目点明「前端包可能含 private_exponent」",
      "private_exponent" in doc2)
check("B4 速查表覆盖 RainLoop 的 /?/Admin/", "?/Admin/" in doc2)
check("B5 速查表覆盖 KodExplorer 的 /data/", "/data/" in doc2)
check("B6 速查表覆盖 TRS 的 CustomerNO", "CustomerNO" in doc2)
check("B7 含「跨资产密钥比对」做法", "跨资产" in doc2)
check("B8 含「本地零出网验证可用性」做法",
      "零出网" in doc2 or "本地零出网" in doc2)
check("B9 指出命中比对即升严重度", "升严重度" in doc2)

print()
print("C. SOP：拿到密钥材料必做两件事")
print("=" * 68)
check("C1 SOP 含该条（⑥）", "拿到密钥/凭据材料时必做两件事" in SYS)
check("C2 要求先本地验证可用性", "pow(pow(m,e,n),d,n)==m" in SYS)
check("C3 要求跨资产比对", "跨资产比对" in SYS)
check("C4 点明「命中即升严重度」", "命中即升严重度" in SYS)
check("C5 说明这是零出网动作", "零出网" in SYS)

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
