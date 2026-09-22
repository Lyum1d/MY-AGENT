# -*- coding: utf-8 -*-
"""v039 回归：落地两轮实战收集的优化点。

    python test_039_fixes.py

依据（campus.test 两轮实战收集，按投入产出比挑选）：
  ① **产品指纹索引缺失** —— `kb_search("KodExplorer 未授权")` 零命中，识别出产品后不知道打哪，
     实测白耗 2 次请求撞 403（两轮都记为最高优先级）；
  ② **dirsearch 跨执行环境读不到字典** —— 工具跑在工具箱目录、字典写在 py_exec 会话目录，
     报 "wordlist does not exist"，整个工具不可用 → 提供平台内置小字典 + caveat 说明；
  ③ **工具参数坑未文档化** —— ehole 不支持 `-timeout`、多 `-u` 只回 1 条（1 次调用报废）；
  ④ **规则模糊地带** —— 敏感后缀连发无量化阈值；扫路径判定口径（JS 200 算不算、403 是否上报、
     阴性要不要写）不明确。

覆盖：
A. 产品指纹索引篇目存在且含关键产品与差分法
B. 内置小字典存在、条数合理、**敏感后缀已分散**
C. dirsearch caveat 说明字典用法（含内置字典路径与跨环境坑）
D. ehole caveat 说明参数坑
E. 提示词含敏感后缀**量化边界**
F. 提示词含扫路径判定口径（JS 200 / 403 / 阴性）
G. 红线编号连续无重复（24 条）
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

from app import agent as agent_mod                         # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


SYS = agent_mod.SYSTEM_PROMPT

print("=" * 68)
print("A. 产品指纹索引（最高优先级优化点）")
print("=" * 68)
idx = ROOT / "data" / "kb" / "product-fingerprint-index.md"
check("A1 篇目存在", idx.exists(), str(idx))
if idx.exists():
    doc = idx.read_text(encoding="utf-8")
    for label, key in [("A2 TRS SiteBuilder", "TRS SiteBuilder"),
                       ("A3 RainLoop", "RainLoop"),
                       ("A4 KodExplorer", "KodExplorer"),
                       ("A5 Spring Boot Actuator", "Actuator"),
                       ("A6 Swagger/Knife4j", "Knife4j")]:
        check(f"{label} 在表内", key in doc)
    check("A7 含 404 双模板差分法", "404 差分" in doc or "双模板" in doc)
    check("A8 含「文档外壳 vs 接口定义」的区分告诫",
          "文档外壳" in doc and "接口定义" in doc)
    check("A9 含只读纪律声明", "只做只读" in doc or "只读 GET/HEAD" in doc)
    check("A10 含敏感后缀需分散的告诫", "分散" in doc)

print()
print("B. 内置小字典")
print("=" * 68)
wl = ROOT / "data" / "wordlists" / "common-small.txt"
check("B1 字典文件存在", wl.exists(), str(wl))
if wl.exists():
    lines = [l.strip() for l in wl.read_text(encoding="utf-8").splitlines()]
    words = [l for l in lines if l and not l.startswith("#")]
    check("B2 条数在 30~100 之间（小字典）", 30 <= len(words) <= 100, str(len(words)))
    check("B3 含常见后台路径", any(w in ("admin", "manage", "login") for w in words))
    check("B4 含配置/备份类", any(w in (".env", "config.php", "backup.zip") for w in words))
    # 敏感后缀分散：不应有连续 3 条以上都是敏感后缀
    sens = [w for w in words if re.search(r"\.(zip|sql|bak|env|git|svn|swp)$", w)
            or w in (".env", "bak", "backup")]
    run = best = 0
    for w in words:
        if re.search(r"\.(zip|sql|bak|env|git|svn|swp)$", w) or w in (".env", "bak", "backup"):
            run += 1
            best = max(best, run)
        else:
            run = 0
    check("B5 敏感后缀未连续堆叠（最长连续 ≤2）", best <= 2,
          f"最长连续 {best} 条；敏感词共 {len(sens)} 条")

print()
print("C. dirsearch caveat 说明字典用法")
print("=" * 68)
ov = json.loads((ROOT / "data" / "tool_overrides.json").read_text(encoding="utf-8"))
ds_cav = ov.get("dirsearch", {}).get("caveat", "")
check("C1 提到字典不存在的历史失败", "wordlist does not exist" in ds_cav)
check("C2 给出内置字典绝对路径", "common-small.txt" in ds_cav)
check("C3 说明两套执行环境", "两套执行环境" in ds_cav or "工具箱" in ds_cav)
check("C4 给出低配额场景的替代方案", "safe_http_request" in ds_cav)
check("C5 保留原有的 -u 冲突告诫", "不要在 args 里重复写 -u" in ds_cav)

print()
print("D. ehole caveat 说明参数坑")
print("=" * 68)
eh_cav = ov.get("ehole", {}).get("caveat", "")
check("D1 说明不支持 -timeout", "不支持 `-timeout`" in eh_cav)
check("D2 说明多 -u 只回 1 条", "只回传 1 条" in eh_cav or "只回 1 条" in eh_cav)
check("D3 给出正确限并发参数 -t", "-t" in eh_cav)
check("D4 保留「退出码 1 不代表失败」的既有说明", "退出码 1 不代表失败" in eh_cav)

print()
print("E. 提示词：敏感后缀量化边界")
print("=" * 68)
check("E1 给出量化阈值（同类 ≤2 条）", "≤2 条" in SYS or "≤ 2 条" in SYS)
check("E2 要求与普通路径交错", "交错" in SYS)
check("E3 给出间隔要求（≥3 秒）", "≥3 秒" in SYS or "≥ 3 秒" in SYS)
check("E4 保留 IPS 封禁源 IP 的后果说明", "封禁源 IP" in SYS)

print()
print("F. 提示词：扫路径判定口径")
print("=" * 68)
check("F1 明确公开静态资源 200 不算命中", "不算敏感目录命中" in SYS or "不算命中" in SYS)
check("F2 明确 403 只记存在性不上报", "不上报为漏洞" in SYS)
check("F3 明确阴性结论也要写", "阴性结论同样要写进报告" in SYS or "阴性结论" in SYS)
check("F4 要求先建 404 差分基线", "404 差分基线" in SYS)
check("F5 指向产品指纹篇目", "product-fingerprint-index" in SYS)

print()
print("G. 红线编号连续")
print("=" * 68)
src = Path(agent_mod.__file__).read_text(encoding="utf-8")
i = src.index("_P_REDLINES = ")
j = src.index('"""', src.index('"""', i) + 3)
nums = [int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\.\s", src[i:j], re.M)]
check("G1 编号连续无重复", nums == list(range(1, len(nums) + 1)), str(nums))
check("G2 条目数 ≥ 24（v039 扩写后）", len(nums) >= 24, str(len(nums)))

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
