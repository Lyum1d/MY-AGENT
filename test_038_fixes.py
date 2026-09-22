# -*- coding: utf-8 -*-
"""v038 回归：「扫路径」≠「遍历接口」——规则理解偏差修正。

    python test_038_fixes.py

背景（用户 2026-09-21 指示）：补天规则**明确允许「敏感目录扫描」**为轻量测试方式，
目的是**不漏掉普通漏洞**。而平台一度把它与「业务接口遍历」混为一谈——任务书模板里写了
「禁止批量遍历、目录爆破」，直接导致 **campus.test 首轮完全没跑目录扫描**，可能漏掉
备份文件 / 编辑器残留 / 上传目录 / 源码泄露等普通漏洞。

覆盖：
A. 系统提示明确区分「扫路径（允许）」与「遍历接口（禁止）」
B. 系统提示保留「敏感后缀连发」禁令（IPS 封 IP 的实战教训）
C. `dirsearch` 已补 network_control 声明（限速 + 并发）
D. 知识库含「轻量测试的边界」小节与对照表
E. 红线条目编号连续无重复（脚本重排正确）
"""
import json
import os
import re
import sys
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import agent as agent_mod, config                # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


SYS = agent_mod.SYSTEM_PROMPT

print("=" * 68)
print("A. 系统提示：明确区分「扫路径」与「遍历接口」")
print("=" * 68)
check("A1 明确「敏感目录/文件扫描」属许可的轻量测试",
      "敏感目录 / 文件扫描" in SYS or "敏感目录/文件扫描" in SYS)
check("A2 明确警告「不要把目录扫描误当成越界」",
      "不要把「目录扫描」误当成越界" in SYS or "不要把目录扫描误当成越界" in SYS)
check("A3 给出区分标准「扫路径 → 允许」", "扫路径" in SYS and "允许" in SYS)
check("A4 给出区分标准「遍历接口 → 禁止」", "遍历接口" in SYS and "禁止" in SYS)
check("A5 明确禁止的是「对核心业务接口自动化遍历」",
      "核心业务接口" in SYS and "自动化遍历" in SYS)
check("A6 提到教务/选课/成绩这类场景", "教务" in SYS)

print()
print("B. 保留「敏感后缀连发」禁令（实战教训不能丢）")
print("=" * 68)
check("B1 仍禁止敏感后缀连发", "敏感后缀连发" in SYS)
check("B2 说明后果是「封禁源 IP」", "封禁源 IP" in SYS or "封 IP" in SYS)
check("B3 保留原有 DoS / 爆破 / 拖库禁令",
      "拒绝服务" in SYS and "暴力破解" in SYS and "拖库" in SYS)

print()
print("C. dirsearch 补齐 network_control")
print("=" * 68)
ov = json.loads((ROOT / "data" / "tool_overrides.json").read_text(encoding="utf-8"))
ds = ov.get("dirsearch", {})
nc = ds.get("network_control") or {}
check("C1 dirsearch 有 network_control", bool(nc))
check("C2 declared 为真", nc.get("declared") is True)
check("C3 声明支持限速", nc.get("supports_rate") is True)
check("C4 声明支持并发控制", nc.get("supports_concurrency") is True)
check("C5 给出限速旗标 --max-rate", "--max-rate" in (nc.get("rate_flags") or []))
check("C6 给出并发旗标 -t", "-t" in (nc.get("concurrency_flags") or []))
check("C7 保留原有 caveat（target 自动注入 -u）",
      "-u" in (ds.get("caveat") or ""))

# 已声明 network_control 的工具数量（v038 后应为 3）
declared = [k for k, v in ov.items()
            if isinstance(v, dict) and (v.get("network_control") or {}).get("declared")]
check("C8 已声明 network_control 的工具数 ≥ 3", len(declared) >= 3, str(declared))

print()
print("D. 知识库：轻量测试的边界")
print("=" * 68)
kb = ROOT / "data" / "rules" / "compliance-redlines.md"
check("D1 知识库文件存在", kb.exists())
if kb.exists():
    doc = kb.read_text(encoding="utf-8")
    check("D2 含「轻量测试的边界」小节", "轻量测试的边界" in doc)
    check("D3 含「扫路径」≠「遍历接口」的表述",
          "扫路径" in doc and "遍历接口" in doc)
    check("D4 含对照表（敏感目录扫描标为允许）", "敏感目录 / 文件扫描" in doc and "✅" in doc)
    check("D5 保留敏感后缀连发禁令与 IPS 说明", "敏感后缀连发" in doc and "IPS" in doc)
    check("D6 结构完整：含通用红线行为检查小节", "通用红线行为检查" in doc)
    check("D7 小节编号连续（一~八）",
          all(f"## {c}、" in doc for c in "一二三四五六七八"))

print()
print("E. 红线条目编号连续无重复")
print("=" * 68)
src = Path(agent_mod.__file__).read_text(encoding="utf-8")
i = src.index("_P_REDLINES = ")
j = src.index('"""', src.index('"""', i) + 3)
seg = src[i:j]
nums = [int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\.\s", seg, re.M)]
check("E1 编号从 1 开始连续到 N", nums == list(range(1, len(nums) + 1)),
      f"共 {len(nums)} 条：{nums[:5]}...{nums[-3:]}")
check("E2 无重复编号", len(nums) == len(set(nums)), str(nums))
check("E3 条目数 ≥ 23（v038 扩写后）", len(nums) >= 23, str(len(nums)))

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
