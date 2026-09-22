# -*- coding: utf-8 -*-
"""v043 回归：加密密钥材料必须被云端外发脱敏（且不得误伤取证用摘要值）。

    python test_043_fixes.py

现场（campus.test 第四轮）：目标前端 JS 里明文硬编码了 RSA 私钥。该材料被写进本地事实库，
而**事实库会注入每轮上下文、上下文会外发到云端模型**（model-studio）。原有 `_SECRET_RE`
只认 `private_key` 这类关键词，**不匹配 `private_exponent`**，于是**私钥会原样出网** ——
违反公益 SRC「严禁保存、传播、泄露测试中获取的任何数据」。

处置：① 已清理本地事实库与落盘文件；② 本版把规则补进脱敏通道，防止再次发生。

**边界必须守住**：`md5(32)` / `sha1(40)` / `sha256(64)` 这类**取证用摘要值不能被打码** ——
它们正是证据比对（差分、指纹核验）的依据，误伤会直接破坏证据链。
故长 hex 规则的阈值取 **128 字符**（远高于 sha256 的 64，又低于 RSA 私钥的 256）。

覆盖：
A. **行为测试：私钥材料被脱敏**（字段键值 / 超长 hex / PEM 块）
B. **行为测试：取证摘要值不被误伤**（md5 / sha1 / sha256 / 短 hex）
C. 原有规则未被破坏（Cookie / JWT / 手机号 / password=）
D. 规则顺序合理（密钥字段规则在超长 hex 之前）
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import redact                                    # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


# 用假造的（非真实的）密钥材料做测试数据
FAKE_D = "a1b2c3d4" * 32          # 256 字符 = 128 字节，等同 RSA 私钥指数长度
FAKE_N = "00" + "f" * 256         # 258 字符，等同 modulus 长度

print("=" * 68)
print("A. 私钥材料必须被脱敏")
print("=" * 68)
t1 = f'var a={{public_exponent:"010001",private_exponent:"{FAKE_D}",modulus:"{FAKE_N}"}}'
out1, hit1 = redact.redact_text(t1)
check("A1 private_exponent 的值被脱敏", FAKE_D not in out1, out1[:120])
check("A2 modulus 的值被脱敏", FAKE_N not in out1, out1[:120])
check("A3 有命中计数", hit1 > 0, str(hit1))
check("A4 字段名保留（模型仍能理解上下文）",
      "private_exponent" in out1, out1[:160])

out_pem, hit_pem = redact.redact_text(
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nZZZ\n-----END RSA PRIVATE KEY-----")
check("A5 PEM 私钥块被整体打码", "MIIEowIBAAKCAQEA" not in out_pem)
check("A6 PEM 命中计数 > 0", hit_pem > 0)

out_long, _ = redact.redact_text(f"key={FAKE_D}")
check("A7 裸超长 hex（≥128 字符）也被打码", FAKE_D not in out_long)

print()
print("B. ⚠️ 取证用摘要值**不得**被误伤（否则证据链断裂）")
print("=" * 68)
md5 = "d4b2b8794a1c7e3f5b6a8c9d0e1f2a3b"                       # 32 字符
sha1 = "a" * 40                                                  # 40 字符
sha256 = "b" * 64                                                # 64 字符
out_b, _ = redact.redact_text(f"md5={md5} sha1={sha1} sha256={sha256}")
check("B1 md5(32) 原样保留", md5 in out_b, out_b[:120])
check("B2 sha1(40) 原样保留", sha1 in out_b)
check("B3 sha256(64) 原样保留", sha256 in out_b)
check("B4 全非密文的响应片段不被改动",
      redact.redact_text("<html><title>乐山师范学院</title></html>")[0]
      == "<html><title>乐山师范学院</title></html>")

print()
print("C. 原有规则未被破坏")
print("=" * 68)
out_c, _ = redact.redact_text("Cookie: KOD_SESSION_ID_bdc5e=abc123def456")
check("C1 Cookie 仍被脱敏", "abc123def456" not in out_c, out_c)
out_j, _ = redact.redact_text("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh")
check("C2 JWT 仍被脱敏", "eyJhbGciOiJIUzI1NiJ9" not in out_j)
out_p, _ = redact.redact_text("password=SuperSecret123")
check("C3 password= 仍被脱敏", "SuperSecret123" not in out_p)
out_ph, _ = redact.redact_text("手机号 13812345678")
check("C4 手机号仍被脱敏", "13812345678" not in out_ph)

print()
print("D. 规则与执行顺序")
print("=" * 68)
src = Path(redact.__file__).read_text(encoding="utf-8")
check("D1 源码含 private_exponent 规则", "private[_-]?exponent" in src)
check("D2 含 PEM 规则", "PRIVATE KEY" in src)
check("D3 长 hex 阈值注释说明为 128（保住摘要值）",
      "{128,}" in src and "摘要" in src)
check("D4 注释记录了合规缺口与现场", "合规缺口" in src or "违反" in src)

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
