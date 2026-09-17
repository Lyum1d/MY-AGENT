# -*- coding: utf-8 -*-
"""py_exec 代码执行通道回归测试（L3，安全相关）。

py_exec 能力等同本机命令行，是本项目等级最高（L3）的操作，因此这个文件重点测
**安全边界**而不是执行能力：

    python test_pyexec.py

不联网、不打任何目标。只有「正常执行」那一节会真的起一个子进程，
跑的是 `print(...)` / `time.sleep(...)` 这类无害代码。
"""
import asyncio
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_pyexec_test_"))
_ORIG = {
    "SCOPE_FILE": config.SCOPE_FILE,
    "PY_EXEC_DIR": config.PY_EXEC_DIR,
    "PY_EXEC_TIMEOUT": config.PY_EXEC_TIMEOUT,
    "PY_EXEC_MAX_CHARS": config.PY_EXEC_MAX_CHARS,
    "PY_EXEC_TMP_ROOT": config.PY_EXEC_TMP_ROOT,
}
(config.SCOPE_FILE).parent  # 保持导入顺序清晰
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text(
    json.dumps({"domains": ["example.com", "10.0.0.5"]}, ensure_ascii=False),
    encoding="utf-8")
config.PY_EXEC_DIR = _TMP / "exec"
config.PY_EXEC_TMP_ROOT = _TMP / "tmp"   # v010 沙箱临时工作目录同样改道测试目录

from app.pyexec import _sanitize, _scope_check_target, run_py_exec   # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def collect(code: str, target: str = "") -> list[dict]:
    async def _run():
        return [e async for e in run_py_exec(code, target)]
    return asyncio.run(_run())


# ---------------------------------------------------------------------------
print("=== 1. 留档目录名（_sanitize）：不能有路径穿越 ===")
check("普通域名保持原样", _sanitize("example.com") == "example.com")
check("斜杠被替换", _sanitize("a/b") == "a_b")
check("多级穿越被拆掉", "/" not in _sanitize("../../evil"), _sanitize("../../evil"))
# 安全断言：「.」是允许字符（域名需要），但纯点名拼进路径就是穿越
check('".." 必须被挡住（否则留档写到上一级目录）',
      _sanitize("..") not in ("..", ""), _sanitize(".."))
check('"." 必须被挡住', _sanitize(".") not in (".", ""), _sanitize("."))
check('"..." 必须被挡住', not _sanitize("...").strip(".") == "", _sanitize("..."))
check("超长名字被截断（避免超长路径）", len(_sanitize("a" * 200)) <= 60)

# ---------------------------------------------------------------------------
print("=== 2. 授权校验（_scope_check_target）===")
check("已授权域名放行", _scope_check_target("example.com") is None)
check("已授权域名的 URL 形态放行", _scope_check_target("https://example.com/x") is None)
check("已授权 IP 放行", _scope_check_target("10.0.0.5") is None)
check("未授权域名拒绝", isinstance(_scope_check_target("evil.com"), str))
check("未授权 IP 拒绝", isinstance(_scope_check_target("1.2.3.4"), str))
check("企业名等自由文本放行（模型常填企业名做资产扩展）",
      _scope_check_target("腾讯") is None and _scope_check_target("腾讯公司") is None)
check("版本号之类不像主机的串放行（不误伤）",
      _scope_check_target("v1.2.3") is None and _scope_check_target("L3") is None)

# 下面三条是核心：旧实现「含空格/含非 ASCII 就跳过」，加个空格就能绕过白名单
check("未授权域名 + 空格 + 中文，不能因此绕过",
      isinstance(_scope_check_target("evil.com 腾讯"), str))
check("未授权域名 + 空格 + 英文，不能因此绕过",
      isinstance(_scope_check_target("evil.com foo"), str))
check("未授权域名带前后空格，不能因此绕过",
      isinstance(_scope_check_target("  evil.com  "), str))
check("多个主机里只要有一个未授权就拒绝",
      isinstance(_scope_check_target("example.com evil.com"), str))

# ---------------------------------------------------------------------------
print("=== 3. 执行前的拒绝路径 ===")
ev = collect("print('x')", target="evil.com")
check("未授权目标在**执行前**就被拒（不产生任何输出事件）",
      not any(e.get("type") == "output" for e in ev))
check("拒绝时给出 error 事件", any(e.get("type") == "error" for e in ev))
check("拒绝时退出码 126（区别于普通失败）",
      any(e.get("type") == "exit" and e.get("code") == 126 for e in ev),
      [e.get("code") for e in ev if e.get("type") == "exit"])
check("未授权时没有留下任何代码文件",
      not any(config.PY_EXEC_DIR.rglob("exec_*.py")) if config.PY_EXEC_DIR.exists() else True)

ev = collect("")
check("空代码被拒", any(e.get("type") == "error" for e in ev))
config.PY_EXEC_MAX_CHARS = 50
ev = collect("x = 1\n" * 100)
check("超长代码被拒并说明上限",
      any(e.get("type") == "error" and "代码过长" in str(e.get("data")) for e in ev))
config.PY_EXEC_MAX_CHARS = _ORIG["PY_EXEC_MAX_CHARS"]

print("=== 4. 正常执行（无害代码）===")
ev = collect("print('hello-from-test')", target="example.com")
outs = " ".join(str(e.get("data")) for e in ev if e.get("type") == "output")
check("能拿到子进程输出", "hello-from-test" in outs, outs[:60])
check("正常结束带 exit 事件", any(e.get("type") == "exit" and e.get("code") == 0 for e in ev))

print("=== 5. 留档与超时 ===")
files = list(config.PY_EXEC_DIR.rglob("exec_*.py"))
check("代码按目标归类留档（便于审计复盘）", len(files) >= 1, f"{len(files)} 个文件")
check("留档目录没有逃出 PY_EXEC_DIR",
      all(str(f.resolve()).startswith(str(config.PY_EXEC_DIR.resolve())) for f in files))

# target 用 ".." 也不能把留档写到外面
ev = collect("print('traversal')", target="..")
check('target 为 ".." 时留档仍落在 PY_EXEC_DIR 内',
      all(str(f.resolve()).startswith(str(config.PY_EXEC_DIR.resolve()))
          for f in config.PY_EXEC_DIR.rglob("exec_*.py")))

config.PY_EXEC_TIMEOUT = 1
ev = collect("import time\ntime.sleep(9)\nprint('never')", target="example.com")
check("超时会被中断", any(e.get("type") == "error" and "超时" in str(e.get("data")) for e in ev))
check("超时退出码 124",
      any(e.get("type") == "exit" and e.get("code") == 124 for e in ev),
      [e.get("code") for e in ev if e.get("type") == "exit"])
config.PY_EXEC_TIMEOUT = _ORIG["PY_EXEC_TIMEOUT"]

for k, v in _ORIG.items():
    setattr(config, k, v)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
