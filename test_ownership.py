# -*- coding: utf-8 -*-
"""数据归属校验回归（v010 P1-3）。

为什么单独一个文件：删除接口此前只按记录 ID 删、不校验 project_id——
拿着别项目的 fid 就能跨项目误删。这组用例钉住「跨项目删除必须被拒」：

    python test_ownership.py

数据库改道临时目录，不触碰本机 projects.db。
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_own_test_"))
config.DATA_DIR = _TMP                      # store.py 的 DB_PATH 在 import 时由 DATA_DIR 拼出
import importlib                            # noqa: E402
from app import store                       # noqa: E402
importlib.reload(store)                     # 让 DB_PATH 指到临时目录
store.DB_PATH = _TMP / "projects.db"

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


# ---------------------------------------------------------------------------
print("=== 1. 事实（facts）归属校验 ===")
p1 = store.create_project("项目甲", "example.com")["id"]
p2 = store.create_project("项目乙", "test.example")["id"]

f1 = store.add_fact(p1, "站点使用 Nginx 1.24", source="agent", session_id="s1")
check("事实创建成功", bool(f1.get("id")))

check("属主项目删除 → 成功", store.delete_fact(p1, f1["id"]) is True)
f2 = store.add_fact(p1, "第二条事实", source="agent")
check("跨项目删除 → 拒绝（返回 False）",
      store.delete_fact(p2, f2["id"]) is False)
check("跨项目删除后记录仍在（属主项目可见）",
      any(r["id"] == f2["id"] for r in store.list_facts(p1)))
check("不存在的 fid → 拒绝",
      store.delete_fact(p1, "no_such_fid") is False)

print("=== 2. 漏洞发现（findings）归属校验 ===")
v1 = store.add_finding(p1, "示例漏洞", "中危", "example.com", detail="测试")
check("发现创建成功", bool(v1.get("id")))
check("属主项目删除 → 成功", store.delete_finding(p1, v1["id"]) is True)
v2 = store.add_finding(p1, "第二条发现", "低危", "example.com")
check("跨项目删除 → 拒绝", store.delete_finding(p2, v2["id"]) is False)
check("跨项目删除后记录仍在",
      any(r["id"] == v2["id"] for r in store.list_findings(p1)))

print("=== 3. 接口层接入断言 ===")
main_src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
check("remove_fact 路由按 (pid, fid) 调用 store",
      "store.delete_fact(pid, fid)" in main_src)
check("remove_finding 路由按 (pid, fid) 调用 store",
      "store.delete_finding(pid, fid)" in main_src)
check("删除路由对项目不存在返回 404",
      main_src.count('raise HTTPException(404, "项目不存在")') >= 1)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
