# -*- coding: utf-8 -*-
"""v032 回归：受控接口可用性修复（第四轮 shhxqh 实战暴露）。

    python test_032_fixes.py

背景：第四轮实战中，脚本两次崩溃、白烧 2 次真实目标请求，根因是受控接口的
**文档与实现不一致**：
  ① `Resp` 没有 `error` 键，但 docstring/工具描述都教 `if r["error"]:` → KeyError；
  ② `tmpdir` 导出的是函数，示例易写成 `os.path.join(tmpdir, ...)` → TypeError；
  ③ 脚本崩溃时，已成功取回的正文随内存对象一起丢失 → 同一路径被迫重请。

覆盖：
A. `Resp` 恒有 error 键（成功路径 `r["error"]` / `r.error` 都可访问）
B. 失败响应 error 非空、语义不变
C. `TMPDIR` 常量存在且是可用路径；`tmpdir()` 函数仍可用
D. 大响应总是落盘（阈值可配）；小响应不落盘（避免垃圾文件）
E. 落盘内容完整可回读（崩溃后找回正文的保证）
F. 脚本文档已声明上述三条纪律
"""
import importlib
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

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_032_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.PY_EXEC_TMP_ROOT = _TMP / "scripts" / "tmp"

from app import pyexec_bridge                             # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


# 在受控沙箱里加载脚本侧模块（SRC_AGENT_TMPDIR 指向临时目录，避免污染真实目录）
os.environ["SRC_AGENT_TMPDIR"] = str(_TMP / "persist")
_ns = {"__file__": str(_TMP / "srcagent.py"), "__name__": "srcagent"}
exec(compile(pyexec_bridge.SCRIPT_MODULE_SOURCE, "srcagent.py", "exec"), _ns)
Resp = _ns["Resp"]
_wrap = _ns["_wrap"]

print("=" * 68)
print("A/B. Resp 恒有 error 键（第四轮崩溃的直接根因）")
print("=" * 68)
r_ok = _wrap({"status_code": 200, "headers": {"server": "BWS"},
              "text": "hello", "elapsed": 0.12})
check("A1 成功响应含 error 键", "error" in r_ok, repr(sorted(r_ok.keys())))
check("A2 成功响应 error 为空串", r_ok["error"] == "", repr(r_ok.get("error")))
try:
    hit = bool(r_ok["error"])
    check("A3 `if r['error']:` 不再抛 KeyError（文档示例可用）", hit is False)
except KeyError as e:
    check("A3 `if r['error']:` 不再抛 KeyError（文档示例可用）", False, repr(e))
try:
    check("A4 `r.error` 属性访问同样可用", r_ok.error == "")
except Exception as e:
    check("A4 `r.error` 属性访问同样可用", False, repr(e))

r_bad = _wrap({"error": "TIMEOUT_WAITING_HOST_BRIDGE", "hint": "宿主未响应"})
check("B1 失败响应 error 非空", r_bad["error"] == "TIMEOUT_WAITING_HOST_BRIDGE")
check("B2 失败响应不含 status_code（语义不变）", "status_code" not in r_bad)

r_missing = _wrap({})
check("B3 无 status_code 且无 error 时仍给 warning 提示",
      "warning" in r_missing and r_missing["error"] == "")

print()
print("C. TMPDIR 常量（tmpdir 误用的直接修复）")
print("=" * 68)
TMPDIR = _ns.get("TMPDIR")
check("C1 模块导出 TMPDIR 常量", TMPDIR is not None)
if TMPDIR is not None:
    check("C2 TMPDIR 是字符串路径（可直接 os.path.join）", isinstance(TMPDIR, str), type(TMPDIR).__name__)
    check("C3 TMPDIR 目录真实存在", Path(TMPDIR).is_dir(), str(TMPDIR))
    try:
        p = os.path.join(TMPDIR, "probe.txt")
        Path(p).write_text("x", encoding="utf-8")
        check("C4 可直接在 TMPDIR 下写文件", Path(p).exists())
    except Exception as e:
        check("C4 可直接在 TMPDIR 下写文件", False, repr(e))
check("C5 tmpdir() 函数仍可用且与 TMPDIR 一致",
      _ns["tmpdir"]() == TMPDIR, f"{_ns['tmpdir']()} vs {TMPDIR}")

print()
print("D. 大响应落盘阈值（崩溃后能找回正文的前提）")
print("=" * 68)
check("D1 PY_EXEC_SAVE_THRESHOLD 默认 1024（v034 下调，覆盖短响应取证）",
      config.PY_EXEC_SAVE_THRESHOLD == 1024, str(config.PY_EXEC_SAVE_THRESHOLD))
check("D2 阈值小于 TEXT_LIMIT（截断前就已落盘）",
      config.PY_EXEC_SAVE_THRESHOLD < config.PY_EXEC_TEXT_LIMIT)
os.environ["AGENT_PY_EXEC_SAVE_THRESHOLD"] = "16384"
_c = importlib.reload(config)
check("D3 环境变量 AGENT_PY_EXEC_SAVE_THRESHOLD 可覆盖",
      _c.PY_EXEC_SAVE_THRESHOLD == 16384, str(_c.PY_EXEC_SAVE_THRESHOLD))
os.environ.pop("AGENT_PY_EXEC_SAVE_THRESHOLD", None)
config = importlib.reload(_c)

_src = Path(pyexec_bridge.__file__).read_text(encoding="utf-8")
check("D4 实现里按阈值落盘（非仅截断时）",
      ">= config.PY_EXEC_SAVE_THRESHOLD" in _src)
check("D5 落盘分支在截断分支之前", _src.index("PY_EXEC_SAVE_THRESHOLD")
      < _src.index('resp["truncated"] = True'))
check("D6 未截断但已落盘时也回传 saved_text_path",
      'resp["saved_text_path"] = str(saved)' in _src)

print()
print("E. 落盘内容完整可回读")
print("=" * 68)
big = ("HEAD" + ("m" * 12000) + "TAIL").encode("utf-8")
p = pyexec_bridge._dump_full_text("rid032", big)
check("E1 落盘成功", p is not None)
if p:
    back = Path(p).read_bytes()
    check("E2 全文逐字节一致（崩溃后可据此找回）", back == big, f"{len(back)} vs {len(big)}")

print()
print("F. 脚本文档声明了三条纪律")
print("=" * 68)
check("F1 声明 error 恒存在", "恒存在" in _src)
check("F2 声明 TMPDIR 常量与 tmpdir() 两种写法", "TMPDIR" in _src and "tmpdir()" in _src)
check("F3 声明大响应自动落盘 + 不要为重取再发请求",
      "自动落盘" in _src and "不要" in _src)

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
