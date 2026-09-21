# -*- coding: utf-8 -*-
"""v036 回归：按漏洞类型的专项作业纪律 + 报告合规 + 数据即清接口。

    python test_036_fixes.py

背景：用户追加了《补天公益SRC安全测试检查清单》，比前一份更细 ——
它在通用红线之外，额外给出 **6 类漏洞的专项纪律**（共 17 项）与 **报告/提交自查**，
并明确「测试完毕后删除测试记录及产生的测试数据」。原实现三处都缺：
  ① 系统提示只有通用红线，没有「按漏洞类型」的专项纪律；
  ② `data/rules/compliance-redlines.md` 只有六条红线展开版，没有专项清单与报告自查；
  ③ 只有启动时的过期清理，没有「测试完毕后立即清理」的入口。

覆盖：
A. 系统提示含 6 类漏洞专项纪律要点
B. 系统提示含报告脱敏与收尾要求
C. 知识库 compliance-redlines.md 已含完整清单（专项 6 类 + 报告自查 + 数据清理）
D. 手动清理接口已注册
E. 行为测试：keep_days=0 可全清、keep_days 大值则保留
"""
import os
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

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_036_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.PY_EXEC_TMP_ROOT = _TMP / "scripts" / "tmp"

from app import agent as agent_mod, pyexec                # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


SYS = agent_mod.SYSTEM_PROMPT

print("=" * 68)
print("A. 系统提示：6 类漏洞专项纪律")
print("=" * 68)
check("A1 权限获取类·拿到即停", "权限获取类" in SYS and "立即停止" in SYS)
check("A2 文件读取类·只用通用非核心文件证明",
      "通用非核心" in SYS and "/etc/passwd" in SYS)
check("A3 SQL 注入·禁 into outfile", "into outfile" in SYS)
check("A4 SSRF·要验证可构造、禁内网大范围扫描",
      "确实可构造" in SYS and "大范围端口扫描" in SYS)
check("A5 越权·自有双账号交叉验证",
      "两个测试账号" in SYS and "交叉验证" in SYS)
check("A6 XSS·只用弹窗截图、删插入数据",
      "XSS" in SYS and "备注插入点" in SYS)
check("A7 专项纪律指向完整清单", "compliance-redlines" in SYS)

print()
print("B. 系统提示：报告与收尾")
print("=" * 68)
check("B1 报告必须脱敏", "脱敏" in SYS)
check("B2 报告不得含违规操作截图或数据",
      "不得包含任何违规操作的截图" in SYS or "违规操作的截图或数据" in SYS)
check("B3 测试完毕删除测试数据", "删除测试记录与产生的数据" in SYS or "测试完毕删除" in SYS)

print()
print("C. 知识库 compliance-redlines.md 已含完整清单")
print("=" * 68)
kb = ROOT / "data" / "rules" / "compliance-redlines.md"
check("C1 知识库文件存在", kb.exists(), str(kb))
if kb.exists():
    doc = kb.read_text(encoding="utf-8")
    check("C2 含「按漏洞类型的专项作业纪律」小节", "按漏洞类型的专项作业纪律" in doc)
    for label, key in [("C3 权限获取类", "权限获取类（命令执行、文件上传、RCE）"),
                       ("C4 文件读取漏洞", "文件读取漏洞"),
                       ("C5 SQL 注入", "SQL 注入"),
                       ("C6 SSRF", "SSRF"),
                       ("C7 越权", "越权（IDOR"),
                       ("C8 XSS", "XSS")]:
        check(f"{label} 专项在库", key in doc)
    check("C9 含报告提交自查", "报告与提交自查" in doc)
    check("C10 含信息脱敏要求", "信息脱敏" in doc)
    check("C11 含数据清理要求（测试完毕删除）",
          "已删除测试记录及产生的测试数据" in doc or "测试完毕后" in doc)
    check("C12 保留原六条红线", "六条红线" in doc)
    check("C13 含机械闸门章节（并提到用完即清）",
          "机械闸门" in doc and "用完即清" in doc)

print()
print("D. 手动清理接口（测试完毕后立即清理）")
print("=" * 68)
main_src = Path(__import__("app.main", fromlist=["x"]).__file__).read_text(encoding="utf-8")
check("D1 已注册 cleanup-persist 路由", "cleanup-persist" in main_src)
check("D2 支持 keep_days 参数", "keep_days" in main_src)
check("D3 接口提到合规依据", "测试完毕后" in main_src)

print()
print("E. 行为测试：清理接口的两种语义")
print("=" * 68)
root = Path(config.PY_EXEC_TMP_ROOT) / "persist"


def mk(name, age_days):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "resp_x.bin").write_bytes(b"BODY-COPY")
    ts = time.time() - age_days * 86400
    os.utime(d, (ts, ts))
    return d


today = mk("today_bucket", 0)
old = mk("old_bucket", 10)

n1 = pyexec.cleanup_persist_dirs(3650)
check("E1 keep_days 很大 → 全部保留（含过期桶）",
      today.exists() and old.exists(), f"n={n1}")

n2 = pyexec.cleanup_persist_dirs(0)
check("E2 keep_days=0 → 全清（测试完毕后立即清理）",
      not today.exists() and not old.exists(), f"n={n2}")
check("E3 返回清理数量合理", n2 >= 2, str(n2))

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
