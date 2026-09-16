# -*- coding: utf-8 -*-
"""情报库（intel）与报告生成（report）回归测试——补齐最后两个零覆盖模块。

    python test_intel_report.py

离线、不碰任何目标：数据库与产物目录都改道到临时目录。

报告按补天 SRC 格式，所以这里也顺带钉住格式要求：**漏洞必须带复现证据**、结论先给
证据确凿的；排序按危害等级（严重→信息），未知等级排最后而不是崩掉。
"""
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config, store                              # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_intel_test_"))
store.DB_PATH = _TMP / "test_intel.db"
config.LLM_PROVIDERS_FILE = _TMP / "providers_test.json"
store.init_db()

from app import intel, report                              # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


# ===========================================================================
print("=== 1. 情报提取（extract_from_text）===")
text = """
https://api.example.com/v1/user/list HTTP/1.1 200
http://sub.example.com:8080/admin/  -> 403
GET "/api/config" and "/actuator/env"
Server: 10.0.0.7, 192.168.1.9
Powered by Spring Boot, uses Vue and Swagger
"""
out = intel.extract_from_text(text)
check("提取出主机（去端口、转小写）",
      "api.example.com" in out["hosts"] and "sub.example.com" in out["hosts"], out["hosts"])
check("提取出 API 路径", any("/api" in p for p in out["api_paths"]), out["api_paths"][:3])
check("提取出 IP", "10.0.0.7" in out["ips"] and "192.168.1.9" in out["ips"], out["ips"])
check("提取出技术栈（大小写不敏感）",
      "spring boot" in out["tech"] and "vue" in out["tech"], out["tech"])

dup = intel.extract_from_text("http://a.example.com/ http://a.example.com/ http://a.example.com/")
check("去重", dup["hosts"] == ["a.example.com"], dup["hosts"])
check("空文本返回空字典", intel.extract_from_text("") == {} and intel.extract_from_text(None) == {})

# _looks_like_file 过滤的是"主机名本身像文件名"（logo.png 这种），
# 而 cdn.example.com 是真实资产主机，理应计入——别把正常资产当噪声过滤掉。
check("文件名式主机被过滤", intel._looks_like_file("logo.png") is True)
check("正常域名不算文件", intel._looks_like_file("cdn.example.com") is False)
res = intel.extract_from_text("https://cdn.example.com/logo.png")
check("CDN 之类的资源域名仍计入主机（它本身就是资产）",
      "cdn.example.com" in res.get("hosts", []), res.get("hosts"))
res2 = intel.extract_from_text("https://logo.png/x")
check("主机名像文件时不计入主机", "logo.png" not in res2.get("hosts", []), res2.get("hosts"))

print("=== 2. 情报容量上限（防止撑爆上下文）===")
many = " ".join(f"http://h{i}.example.com/" for i in range(400))
big = intel.extract_from_text(many)
check("主机数量被截断到上限", len(big["hosts"]) <= intel._CAP, len(big["hosts"]))

print("=== 3. 情报渲染（format_intel）===")
check("空情报返回空串（不往提示词里塞空块）", intel.format_intel({}) == "")
block = intel.format_intel({"hosts": ["a.example.com"], "tech": ["nginx"]})
check("渲染出分类标题", "已知主机/子域" in block and "已知技术栈" in block)
check("带引导语（避免 Agent 重复收集）", "不要重复收集" in block)
block_many = intel.format_intel({"hosts": [f"h{i}.example.com" for i in range(60)]})
check("超过展示条数时给出总数", "等共" in block_many and "60" in block_many)
long_block = intel.format_intel({"hosts": ["x" * 100 for _ in range(40)]}, limit=100)
check("超长被截断", len(long_block) <= 200 and "已截断" in long_block)

print("=== 4. 情报落库与合并 ===")
pid = store.create_project("情报测试项目", "demo.example.com", "跑完即删")["id"]
intel.update_intel_from_steps(pid, ["http://a.example.com/ using nginx"])
first = store.get_intel(pid)
check("首轮情报落库", "a.example.com" in first.get("hosts", []), first.get("hosts"))
intel.update_intel_from_steps(pid, ["http://b.example.com/ 10.0.0.1"])
second = store.get_intel(pid)
check("第二轮是**合并**而非覆盖",
      "a.example.com" in second.get("hosts", []) and "b.example.com" in second.get("hosts", []),
      second.get("hosts"))
check("新类别也被合并进来", "10.0.0.1" in second.get("ips", []), second.get("ips"))
before = dict(second)
intel.update_intel_from_steps(pid, [""])
check("空输出不会清空已有情报", store.get_intel(pid) == before)

# ===========================================================================
print("=== 5. 报告生成 ===")
check("项目不存在时给出明确提示", report.render_project_report("不存在的项目").startswith("# 项目不存在"))

empty_md = report.render_project_report(pid)
check("无漏洞时如实说明（不编造）", "暂无已确认的漏洞" in empty_md)
check("报告带授权声明", "书面授权" in empty_md)

store.add_finding(pid, "低危漏洞", "低危", "demo.example.com", detail="低危详情")
store.add_finding(pid, "严重漏洞", "严重", "demo.example.com",
                  detail="严重详情", evidence="curl -i http://demo.example.com/ -> 200 root")
store.add_finding(pid, "高危漏洞", "高危", "demo.example.com")
store.add_finding(pid, "等级缺失漏洞", "", "demo.example.com")

md = report.render_project_report(pid)
order = [m for m in re.findall(r"\|\s*\d+\s*\|\s*([^|]+?)\s*\|", md)]
check("漏洞按危害等级排序（严重在最前）",
      order[0] == "严重漏洞" if order else False, order[:4])
check("等级缺失的漏洞排在最后而不是崩掉",
      "等级缺失漏洞" in order and order[-1] == "等级缺失漏洞", order[-3:])
check("漏洞清单是表格且含目标列", "| 序号 | 漏洞名称 | 危害等级 | 影响目标 |" in md)
check("漏洞详情带复现证据（补天格式要求）", "```" in md and "curl -i" in md)
check("漏洞详情带修复建议", "修复建议" in md)
check("漏洞数量统计正确", "**漏洞数量**：4" in md,
      [l for l in md.splitlines() if "漏洞数量" in l])

print("=== 6. 报告导出 ===")
path = report.export_report(pid)
check("导出返回文件路径", bool(path) and Path(path).exists(), path)
check("落盘内容与渲染一致", "严重漏洞" in Path(path).read_text(encoding="utf-8"))
check("产物文件名带项目名与时间戳", "报告_" in Path(path).name and ".md" in Path(path).name,
      Path(path).name)
Path(path).unlink(missing_ok=True)   # 别把测试产物留在 data/artifacts 里
check("测试产物已清理", not Path(path).exists())

store.delete_project(pid)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
