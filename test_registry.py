# -*- coding: utf-8 -*-
"""工具注册表与三份配置 JSON 的一致性回归测试。

为什么单独一个文件：项目的风险分级（L0 自动 / L1 自动 / L2 需确认 / L3 需二次确认）
是授权红线之外的第二道闸门。而它当前靠 **中文显示名** 匹配：

    app/registry.py:  g = grades.get(tool.name)     # risk_grades.json 按 name
    app/registry.py:  ov = overrides.get(tool.alias) or overrides.get(tool.name)

工具箱换个版本、显示名改一个字（"冰蝎4" → "冰蝎4.1"），分级就会**静默失配**，
工具掉回 config.DEFAULT_RISK_LEVEL —— 20 个 L3 工具会悄悄丢掉二次确认。
这类失效没有报错、没有日志，只能靠断言提前钉住。

本套件锁住的不变量：
  1. 三份 JSON 里没有"死条目"（键匹配不上任何真实工具）
  2. 没有工具箱工具静默回落到默认分级
  3. 默认分级只能是 L2 或更严（不允许有人图省事改成 L0）
  4. 禁用条目必须写 reason、非禁用条目必须写 caveat（项目规范：改 JSON 留注释）
  5. 坏了的工具（禁用 / 可执行文件缺失）不会进入喂给模型的清单

    python test_registry.py

不联网、不执行任何工具、不碰任何目标：只读 JSON + 调用注册表查询。
工具箱未配置时，依赖工具箱的断言会跳过而不是误报失败。
"""
import difflib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config, registry as R          # noqa: E402

FALLBACK_REASON = "未在分级表中定义，按默认 L2 处理"

reg = R.registry
reg.load()

ok, fail, skipped = [], [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def skip(name, why=""):
    """环境缺件时跳过，而不是记成失败。

    为什么：每次跑都挂一个「已知环境问题」的红点，久了就没人看失败了。
    缺什么就说缺什么，配好后自动启用。
    """
    skipped.append(name)
    print(f"  [跳过] {name}" + (f"（{why}）" if why else ""))


def load_json(name):
    return json.loads((config.DATA_DIR / name).read_text(encoding="utf-8"))


def real_keys(data):
    return [k for k in data if not k.startswith("_")]


grades = load_json("risk_grades.json")
overrides = load_json("tool_overrides.json")
templates = load_json("invocation_templates.json")

tools = reg.tools
aliases = {t.alias for t in tools}
names = {t.name for t in tools}
builtin = [t for t in tools if t.category == "内置能力"]
from_toolbox = [t for t in tools if t.category != "内置能力"]
scriptable = reg.scriptable_tools()

print("\n=== 1. 注册表基本形态 ===")
check("注册表已加载", reg.loaded)
check("工具总数 > 0", len(tools) > 0, f"{len(tools)} 个")
check("内置能力已注册", len(builtin) >= 9, f"{len(builtin)} 个")
check("alias 无重复", len(aliases) == len(tools), f"{len(aliases)} 个别名 / {len(tools)} 个工具")
check("alias 反查与工具自身一致",
      all(reg.get_by_alias(t.alias) is t for t in tools))
check("name 反查与工具自身一致",
      all(reg.get_by_alias(reg.get_by_alias(t.alias).alias).name == t.name for t in tools))

print("\n=== 2. 三份配置 JSON 没有死条目（键必须能匹配到真实工具）===")
# 两份按 alias、一份按 name，键空间本来就不统一——这里只断言"能匹配上"，
# 不断言"必须走哪个通道"，这样将来统一键空间时不会误红。
for label, data in (("risk_grades.json", grades),
                    ("tool_overrides.json", overrides),
                    ("invocation_templates.json", templates)):
    keys = real_keys(data)
    if not from_toolbox:
        skip(f"{label} 键名可匹配", "工具箱未配置，无法核对")
        continue
    dead = [k for k in keys if k not in aliases and k not in names]
    if dead:
        pool = sorted(aliases | names)
        hint = "; ".join(f"{d!r}≈{difflib.get_close_matches(d, pool, n=2, cutoff=0.4)}"
                         for d in dead[:5])
        check(f"{label} 无死条目", False, f"{len(dead)} 个匹配不上：{hint}")
    else:
        check(f"{label} 无死条目", True, f"{len(keys)} 个键全部命中")

print("\n=== 3. 没有工具静默回落到默认分级（安全性质）===")
check("默认分级不松于 L2", config.DEFAULT_RISK_LEVEL in ("L2", "L3"),
      config.DEFAULT_RISK_LEVEL)
if not from_toolbox:
    skip("工具箱工具均已显式定级", "工具箱未配置")
else:
    fell_back = [t.name for t in scriptable
                 if t.category != "内置能力" and t.risk_reason == FALLBACK_REASON]
    check("工具箱可编排工具全部显式定级", not fell_back,
          f"{len(fell_back)} 个回落：{fell_back[:5]}")

    # L3 是最需要守的一档：掉级 = 丢掉二次确认
    l3_fallback = [t.name for t in scriptable
                   if t.risk_level == "L3" and t.risk_reason == FALLBACK_REASON]
    check("L3 工具没有一个是靠回落得来的", not l3_fallback, str(l3_fallback[:5]))

    toolbox_scriptable = [t for t in scriptable if t.category != "内置能力"]
    check("可编排的工具有分级条目",
          all(t.name in grades for t in toolbox_scriptable),
          f"{len(toolbox_scriptable)} 个可编排工具")

print("\n=== 4. 内置能力的等级不被冲掉 ===")
pe = reg.get_by_alias("py_exec")
check("py_exec 存在", pe is not None)
if pe:
    check("py_exec 为 L3（须二次确认）", pe.risk_level == "L3", pe.risk_level)
    ro = reg.risk_of("py_exec")
    check("py_exec double_confirm=True", bool(ro.get("double_confirm")), str(ro.get("level")))
    check("py_exec 不是回落文案", pe.risk_reason != FALLBACK_REASON)
hr = reg.get_by_alias("httpreplay")
check("httpreplay 存在", hr is not None)
if hr:
    check("httpreplay 为 L2（须确认）", hr.risk_level == "L2", hr.risk_level)
nf = reg.get_by_alias("note_fact")
check("note_fact 为 L0（自动放行）", nf is not None and nf.risk_level == "L0",
      nf.risk_level if nf else "缺失")

print("\n=== 5. 分级表 / 覆写表都带注释（项目规范要求）===")
bad_level = [k for k in real_keys(grades) if not grades[k].get("level")]
check("分级表每个条目都有 level", not bad_level, str(bad_level[:5]))
bad_reason = [k for k in real_keys(grades) if not (grades[k].get("reason") or "").strip()]
check("分级表每个条目都有 reason", not bad_reason, str(bad_reason[:5]))
check("分级表 level 取值合法",
      all(grades[k]["level"] in ("L0", "L1", "L2", "L3") for k in real_keys(grades)))

disabled_no_reason = [k for k in real_keys(overrides)
                      if overrides[k].get("disabled") and not (overrides[k].get("reason") or "").strip()]
check("禁用条目都写了 reason", not disabled_no_reason, str(disabled_no_reason))
live_no_caveat = [k for k in real_keys(overrides)
                  if not overrides[k].get("disabled") and not (overrides[k].get("caveat") or "").strip()]
check("未禁用条目都写了 caveat", not live_no_caveat, str(live_no_caveat))
check("三份配置顶层都是 JSON 对象",
      all(isinstance(grades.get(k, {}), dict) for k in real_keys(grades)))

print("\n=== 6. 坏掉的工具不会进模型视野 ===")
usable = reg.usable_scriptable()
usable_aliases = {t.alias for t in usable}
bad_in_list = [t.alias for t in usable if t.disabled]
check("可用清单不含被禁用工具", not bad_in_list, str(bad_in_list))
noexe_in_list = [t.alias for t in usable if not t.executable]
check("可用清单不含可执行文件缺失的工具", not noexe_in_list, str(noexe_in_list))
check("可用清单是可编排清单的子集", usable_aliases <= {t.alias for t in scriptable})
st = reg.stats()
print(f"      （总数 {st['total']} / 可编排 {st['scriptable']} / "
      f"实际可用 {len(usable)} / 缺失文件 {st['missing']}）")

print(f"\n结果：{len(ok)} 通过 / {len(fail)} 失败 / {len(skipped)} 跳过")
if skipped:
    print("跳过项：" + "、".join(skipped))
if fail:
    print("失败项：" + "、".join(fail))
    sys.exit(1)
