# -*- coding: utf-8 -*-
"""v023.7 回归：项目已证实事实自动注入（第二轮实战暴露）。

    python test_023_fixes4.py

背景：shhxqh 第二轮实战中，第一轮已经证实的事实（CMS 后端入口泄露、
免权限控制器未认证可达）只能靠**人工写进任务书**复述；平台不注入，模型
要么重新发现（白烧预算与流量），要么在上下文压缩后彻底失忆。

覆盖：
A. verified 事实注入（含标题/条目前缀）
B. candidate / rejected 不注入（不把猜测当既定前提）
C. 条数与单条长度上限（防上下文膨胀）
D. 无项目 / 无事实时返回空串（零副作用）
E. 开关 AGENT_INJECT_FACTS=0 可关闭
F. 接线到 _build_reminder：随每轮提醒一起出现，且位于「本次任务目标」之后
G. 注入内容明确要求「不要重复验证」（防重复探测）
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

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_237_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False

from app import agent as agent_mod, store                # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


prj = store.create_project("v0237注入", "site-a.test")["id"]
prj_empty = store.create_project("空事实项目", "x.com")["id"]

# ---- 造数：verified 2 条 / candidate 1 条 / rejected 1 条 ----
store.add_fact(prj, "CMS 后端入口泄露：https://site-a.test/hxqhcms/ 可直接访问",
               source="manual", status="verified")
store.add_fact(prj, "SyncNoRightAction.do 免权限控制器未认证可达，返回管理端门户外壳",
               source="manual", status="verified")
store.add_fact(prj, "疑似存在 attguid 越权（未证实）", source="agent", status="candidate")
store.add_fact(prj, "门户页不是空模板（已被证否，实为空模板）", source="manual", status="rejected")


def facts_note(pid: str, target: str = "") -> str:
    s = agent_mod.Session(id="t" + pid[:6], project=pid, target=target)
    return agent_mod._facts_note(s)


print("== A. verified 事实注入 ==")
note = facts_note(prj)
check("非空", bool(note))
check("含标题", "【项目已证实事实" in note, note[:40])
check("含第 1 条 verified", "hxqhcms" in note)
check("含第 2 条 verified", "SyncNoRightAction" in note)
check("条目带 '- ' 前缀", "\n- " in note)

print("== B. candidate / rejected 不注入 ==")
check("candidate 不注入", "attguid" not in note)
check("rejected 不注入", "空模板" not in note)

print("== C. 条数与长度上限 ==")
old_max, old_chars = config.INJECT_FACTS_MAX, config.INJECT_FACTS_CHARS
config.INJECT_FACTS_MAX = 1
n1 = facts_note(prj)
check("条数上限生效（只出 1 条）", n1.count("\n- ") == 1, n1.count("\n- "))
check("超出部分给出提示", "另有" in n1 and "条见项目事实库" in n1, n1[-40:])
config.INJECT_FACTS_MAX = old_max

long_fact = "L" * 400
store.add_fact(prj, long_fact, source="manual", status="verified")
config.INJECT_FACTS_CHARS = 50
n2 = facts_note(prj)
check("单条长度截断生效", ("L" * 51) not in n2, len(n2))
check("截断后仍保留前缀", ("L" * 50) in n2)
config.INJECT_FACTS_CHARS = old_chars

print("== D. 无项目 / 无事实返回空串 ==")
check("无项目返回空串", facts_note("") == "")
check("有项目但无事实返回空串", facts_note(prj_empty) == "")

print("== E. 开关可关闭 ==")
config.INJECT_FACTS = False
check("关闭后返回空串", facts_note(prj) == "")
config.INJECT_FACTS = True
check("恢复后仍可注入", bool(facts_note(prj)))

print("== F. 接线到 _build_reminder ==")
_step = agent_mod.Step(id="s1", tool_alias="httpx", tool_name="httpx",
                       target="site-a.test", args="{}", risk={}, status="done")
s = agent_mod.Session(id="rem1", project=prj, target="site-a.test", steps=[_step])
rem = agent_mod.Agent._build_reminder(s, budget={"total": 30, "step_no": 3, "elapsed": 10})
check("提醒里含事实段", "【项目已证实事实" in rem)
check("提醒里仍含目标段", "【本次任务目标：site-a.test】" in rem)
check("事实段位于目标段之后", rem.index("【项目已证实事实") > rem.index("【本次任务目标"))
check("提醒里仍含工具历史段（接线未破坏既有顺序）", "【本轮已尝试过的工具】" in rem)
check("事实段位于工具历史段之前", rem.index("【项目已证实事实") < rem.index("【本轮已尝试过的工具"))

s2 = agent_mod.Session(id="rem2", project="", target="site-a.test")
rem2 = agent_mod.Agent._build_reminder(s2, budget=None)
check("无项目时提醒不含事实段（不报错）", "【项目已证实事实" not in rem2)

print("== G. 防重复验证口径 ==")
check("明确要求不要重复验证", "不要重复验证" in note)
check("明确可采信", "可直接采信" in note)

print()
print("=" * 52)
# 统计行必须用 run_all_tests.py 认识的两格式之一
# （RE_COUNT_CN：通过 N 项，失败 M 项 / RE_COUNT_SMOKE：结果：N 通过 / M 失败）
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    for f in fail:
        print("  FAILED:", f)
    sys.exit(1)
print("ALL PASS")
