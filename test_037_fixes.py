# -*- coding: utf-8 -*-
"""v037 回归：清理临时目录时 SystemExit 不得穿透（服务曾被它整个搞崩）。

    python test_037_fixes.py

现场（cread.com 首轮实战）：服务在 `pyexec.py` 清理 py_exec 工作目录时**整个进程退出**，
编排脚本随即因 SSE 断流报 `RemoteProtocolError`。根因不是网络，而是：

    [safe-delete][SAFE_DELETE_BULK_CONFIRM_REQUIRED] {"count":54,"threshold":50,...}
      → raise SystemExit(1)

WorkBuddy 沙箱的 sitecustomize 把 `shutil.rmtree` 劫持成「移入回收站」实现，并带批量删除
守卫（一次 ≥50 文件需确认）。而 `ignore_errors=True` **只吞 OSError** —— SystemExit
直接穿透，一次普通的临时目录清理把 uvicorn 主进程干掉了。

覆盖：
A. `_safe_rmtree` 存在且返回 bool
B. **SystemExit 不再穿透**（直接复现崩溃场景）
C. 普通异常也不穿透
D. 三处 rmtree 调用点全部改走 `_safe_rmtree`（源码层回归）
E. cleanup 会兜底回收 `pyexec_*` 一次性目录（沙箱拦下即时清理后的收尾）
"""
import os
import shutil as _sh
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_037_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.PY_EXEC_TMP_ROOT = _TMP / "scripts" / "tmp"

from app import pyexec                                    # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


src = Path(pyexec.__file__).read_text(encoding="utf-8")

print("=" * 68)
print("A. `_safe_rmtree` 存在且返回 bool")
print("=" * 68)
check("A1 函数存在", hasattr(pyexec, "_safe_rmtree"))
target = _TMP / "d1"
target.mkdir(parents=True, exist_ok=True)
(target / "a.txt").write_text("x", encoding="utf-8")
r = pyexec._safe_rmtree(target)
check("A2 正常删除返回 True", r is True, repr(r))
check("A3 目录确已删除", not target.exists())

print()
print("B. **SystemExit 不得穿透**（复现崩溃现场）")
print("=" * 68)
_orig = _sh.rmtree


def _boom(*a, **kw):
    raise SystemExit(1)


_sh.rmtree = _boom
try:
    t2 = _TMP / "d2"
    t2.mkdir(parents=True, exist_ok=True)
    try:
        ret = pyexec._safe_rmtree(t2)
        check("B1 SystemExit 被吞掉，未穿透", True)
        check("B2 返回 False（表明未删除成功）", ret is False, repr(ret))
    except SystemExit:
        check("B1 SystemExit 被吞掉，未穿透", False, "SystemExit 仍穿透了！")
        check("B2 返回 False（表明未删除成功）", False, "异常已抛出")
finally:
    _sh.rmtree = _orig

print()
print("C. 普通异常同样不穿透")
print("=" * 68)


def _boom2(*a, **kw):
    raise PermissionError("模拟权限不足")


_sh.rmtree = _boom2
try:
    t3 = _TMP / "d3"
    t3.mkdir(parents=True, exist_ok=True)
    try:
        ret = pyexec._safe_rmtree(t3)
        check("C1 PermissionError 被吞掉", True)
        check("C2 返回 False", ret is False, repr(ret))
    except Exception as e:
        check("C1 PermissionError 被吞掉", False, repr(e))
        check("C2 返回 False", False, "异常已抛出")
finally:
    _sh.rmtree = _orig

print()
print("D. 三处调用点全部改走 _safe_rmtree")
print("=" * 68)
check("D1 源码里已无裸 shutil.rmtree(..., ignore_errors=True)",
      "shutil.rmtree(" not in src.replace("def _safe_rmtree", "")
      or src.count("shutil.rmtree(") == 1,
      f"shutil.rmtree 出现 {src.count('shutil.rmtree(')} 次")
check("D2 使用 _safe_rmtree(workdir) 收尾", "_safe_rmtree(workdir)" in src)
check("D3 cleanup 中使用 _safe_rmtree(d)", "_safe_rmtree(d)" in src)

print()
print("E. cleanup 兜底回收 pyexec_* 一次性目录")
print("=" * 68)
root = Path(config.PY_EXEC_TMP_ROOT)
root.mkdir(parents=True, exist_ok=True)
old_work = root / "pyexec_stale"
old_work.mkdir(parents=True, exist_ok=True)
(old_work / "resp.bin").write_bytes(b"x" * 10)
ts = time.time() - 10 * 86400
os.utime(old_work, (ts, ts))
new_work = root / "pyexec_fresh"
new_work.mkdir(parents=True, exist_ok=True)

n = pyexec.cleanup_persist_dirs()
check("E1 过期的一次性工作目录被回收", not old_work.exists(), str(old_work))
check("E2 新鲜的一次性工作目录保留", new_work.exists(), str(new_work))
check("E3 返回计数包含它", n >= 1, str(n))

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
