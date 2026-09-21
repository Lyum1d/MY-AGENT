# -*- coding: utf-8 -*-
"""v033 回归：落盘/写入的换行污染（第五轮 shhxqh 实战暴露）。

    python test_033_fixes.py

背景：第五轮实战中，Agent 认为「`r.text` 被静默截断」（10671 字符）与「落盘全文」
（10976 字符）冲突，**差点把换行污染造成的伪差异写成 IDOR 差分**。真因不是
`r.text` 截断，而是：
  · Windows 上 `Path.write_text()`（newline=None）把正文里的每个 `\\n` 改写成 `\\r\\n`；
  · 10741 字节的响应因此落盘成 11046 字节（多 305 = 305 个 CRLF）；
  · 脚本用 `open(path,'rb')` 读回，凭空多出 305 个 `\\r`，与 `r.text` 对不上。

覆盖：
A. `_dump_full_text` 落盘**原始字节**，与输入逐字节一致
B. 输入里的裸 `\\n` 不会被改写成 `\\r\\n`（污染回归）
C. 落盘文件为 .bin、实现用 `write_bytes`、签名收 bytes
D. 调用处传 `r.content`（与流量审计 bytes_in 同口径，可交叉核验）
E. py_exec 两处脚本写入都带 `newline=""`（避免改坏三引号字符串字面量内容）
F. `save_artifact` 带 `newline=""`（证据类产物必须可复核）
G. 脚本文档要求「差分两边用同一口径」并给出 rb 读法
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_033_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.PY_EXEC_TMP_ROOT = _TMP / "scripts" / "tmp"

from app import pyexec_bridge, store                      # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


print("=" * 68)
print("A/B. 落盘原始字节：裸 \\n 不得被改写成 \\r\\n")
print("=" * 68)
raw = ("line1\nline2\r\nline3\n" * 40).encode("utf-8")
p = pyexec_bridge._dump_full_text("rid033", raw)
check("A1 落盘成功", p is not None)
if p:
    back = Path(p).read_bytes()
    check("A2 与输入逐字节一致", back == raw, f"{len(back)} vs {len(raw)}")
    check("B1 文件长度 == 输入长度（无膨胀）", len(back) == len(raw),
          f"{len(back)} vs {len(raw)}")
    check("B2 裸 \\n 数量未变（关键回归）",
          back.count(b"\n") == raw.count(b"\n"),
          f"{back.count(b'\\n')} vs {raw.count(b'\\n')}")
    check("B3 CRLF 数量未变", back.count(b"\r\n") == raw.count(b"\r\n"),
          f"{back.count(b'\\r\\n')} vs {raw.count(b'\\r\\n')}")
    check("C1 落盘文件扩展名为 .bin", Path(p).suffix == ".bin", Path(p).suffix)

print()
print("C/D. 实现与调用口径")
print("=" * 68)
br_src = Path(pyexec_bridge.__file__).read_text(encoding="utf-8")
check("C2 实现用 write_bytes（非 write_text）", "p.write_bytes(data)" in br_src)
check("C3 签名接收 bytes", "def _dump_full_text(rid: str, data: bytes)" in br_src)
check("D1 调用处传 r.content（与 bytes_in 同口径）",
      "_dump_full_text(rid, r.content)" in br_src)
check("D2 不再把 str 传进落盘函数",
      "_dump_full_text(rid, text)" not in br_src)

print()
print("E. py_exec 两处脚本写入都不做换行转换")
print("=" * 68)
pe_src = Path(__import__("app.pyexec", fromlist=["x"]).__file__).read_text(encoding="utf-8")
check("E1 留档脚本写入带 newline=\"\"",
      'script.write_text(code, encoding="utf-8", newline="")' in pe_src)
check("E2 执行副本写入带 newline=\"\"",
      'run_path.write_text(code, encoding="utf-8", newline="")' in pe_src)

print()
print("F. 产物落盘可复核")
print("=" * 68)
st_src = Path(store.__file__).read_text(encoding="utf-8")
check("F1 save_artifact 带 newline=\"\"",
      'path.write_text(content, encoding="utf-8", newline="")' in st_src)

print()
print("G. 脚本文档：读取口径与差分纪律")
print("=" * 68)
check("G1 文档给出 rb 读原始字节的写法",
      'open(r["saved_text_path"], "rb").read()' in br_src)
check("G2 文档要求差分两边用同一口径", "同一口径" in br_src)
check("G3 文档点明落盘是原始字节", "原始响应字节" in br_src)

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
