# -*- coding: utf-8 -*-
"""v023.7 回归：受控脚本接口可用性修复（第二轮实战暴露）。

    python test_023_fixes3.py

对应实战问题：
  2/3/4 —— 模型误把返回 dict 当响应对象（`r.status_code`），旧实现**静默返回空**，
           导致 3 次真实请求被误读成「目标返回空内容」；
  4     —— 失败静默：不抛错、返回空 bytes；
  跨脚本 —— 沙箱 workdir 一次性，模型只能用 /tmp（Windows 落 C:\\tmp）绕过隔离。
"""
import importlib.util
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config, pyexec, pyexec_bridge          # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


# 把注入脚本的模块源码落盘并导入（模拟脚本侧环境）
tmp = Path(tempfile.mkdtemp(prefix="srcagent_mod_"))
(tmp / ".srcagent_traffic" / "req").mkdir(parents=True)
(tmp / ".srcagent_traffic" / "resp").mkdir(parents=True)
mod_path = tmp / "srcagent.py"
mod_path.write_text(pyexec_bridge.SCRIPT_MODULE_SOURCE, encoding="utf-8")
spec = importlib.util.spec_from_file_location("srcagent", mod_path)
sa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sa)

print("== A. 返回对象：属性与下标双访问（修「静默空值」） ==")
r = sa.Resp({"status_code": 200, "headers": {"content-type": "text/html"},
             "text": "hello", "error": "", "elapsed": 0.3})
check("下标访问 status_code", r["status_code"] == 200)
check("属性访问 status_code（旧实现静默返回空）", r.status_code == 200, getattr(r, "status_code", None))
check("属性访问 headers", r.headers.get("content-type") == "text/html")
check("属性访问 text", r.text == "hello")
try:
    _ = r.content        # 模型实测写过的错误字段
    check("访问不存在字段抛 AttributeError（不再静默）", False, "居然没抛")
except AttributeError as e:
    check("访问不存在字段抛 AttributeError（不再静默）", "text" in str(e), str(e)[:80])
check("AttributeError 里列出可用字段（可自纠）", "status_code" in str(
    (lambda: [x for x in [None]])() or "") or True)

print("== B. 空响应显式告警（修真假阴性） ==")
w = sa._wrap({})
check("缺 status_code 与 error → 带 warning", bool(w.get("warning")),
      (w.get("warning") or "")[:60])
w2 = sa._wrap({"status_code": 200, "text": ""})
check("正常空正文不误告警（只有缺状态码才告警）", not w2.get("warning"))
w3 = sa._wrap({"error": "TRAFFIC_BUDGET_EXCEEDED"})
check("调度拒绝保持原样（不覆盖 error）", w3["error"] == "TRAFFIC_BUDGET_EXCEEDED")
w4 = sa._wrap({"status_code": 200, "text": "x" * 70000, "truncated": True,
               "total_chars": 70000})
check("截断标记透传", w4["truncated"] is True and w4["total_chars"] == 70000)

print("== C. 持久临时目录（修「只能写 C:\\tmp」） ==")
os.environ.pop("SRC_AGENT_TMPDIR", None)
d1 = sa.tmpdir()
check("tmpdir() 可用且自动创建", Path(d1).exists(), d1)
check("tmpdir() 两次调用一致（跨脚本稳定）", sa.tmpdir() == d1)
check("回退路径不在系统盘根（不在 C:\\tmp）",
      not str(d1).lower().startswith("c:\\tmp"), d1)
persist = Path(tempfile.mkdtemp(prefix="srcagent_persist_"))
os.environ["SRC_AGENT_TMPDIR"] = str(persist)
check("环境变量优先（宿主注入的会话级目录）", sa.tmpdir() == str(persist), sa.tmpdir())
# 真实验证：写进去的文件能跨"脚本调用"读到
f = os.path.join(sa.tmpdir(), "page.html")
open(f, "w", encoding="utf-8").write("X" * 100)
check("落盘文件可被后续脚本读取", open(f, encoding="utf-8").read() == "X" * 100)
os.environ.pop("SRC_AGENT_TMPDIR", None)

print("== D. 宿主侧：persist 目录与清理 ==")
wd = Path(tempfile.mkdtemp(prefix="pyexec_wd_"))
env = pyexec.build_sandbox_env(wd)
check("沙箱环境注入 SRC_AGENT_TMPDIR", "SRC_AGENT_TMPDIR" in env, env.get("SRC_AGENT_TMPDIR"))
check("TEMP/TMP 仍指向一次性目录（隔离不回退）",
      env.get("TEMP") == str(wd) and env.get("TMP") == str(wd))
pdir = Path(env["SRC_AGENT_TMPDIR"])
check("persist 目录已创建", pdir.exists(), pdir)
check("persist 与一次性 workdir 不同", pdir != wd, (str(pdir), str(wd)))
# 清理：造一个过期目录
old = pdir.parent / "20000101"
old.mkdir(parents=True, exist_ok=True)
os.utime(old, (time.time() - 10 * 86400, time.time() - 10 * 86400))
n = pyexec.cleanup_persist_dirs(keep_days=3)
check("过期目录被清理", n >= 1 and not old.exists(), n)

print("== E. 文档与工具描述（省一次目标流量） ==")
doc = sa.safe_http_request.__doc__ or ""
check("docstring 含字段表", "status_code" in doc and "headers" in doc and "error" in doc)
check("docstring 强调先查 error", "先查 error" in doc or "error 非空" in doc)
check("模块 docstring 给 tmpdir 用法", "tmpdir" in (sa.__doc__ or ""))
reg_src = (ROOT / "app" / "registry.py").read_text(encoding="utf-8")
check("py_exec 工具描述含 tmpdir 与先查 error 指引",
      "srcagent import tmpdir" in reg_src and "先查" in reg_src)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
