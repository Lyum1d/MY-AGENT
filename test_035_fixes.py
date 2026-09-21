# -*- coding: utf-8 -*-
"""v035 回归：公益 SRC 合规纪律 + 落盘数据「用完即清」。

    python test_035_fixes.py

背景（用户给定的补天「公益 SRC」规则）：
  · 原则：合法、合规、**最小影响**、必要授权；
  · 方式：**只做轻量测试**，且只允许以最小证据证明漏洞存在；
  · 红线：禁止破坏性攻击 / 禁止**对核心业务接口自动化遍历、并发请求、空参数模糊测试** /
          **获取权限后立即停止** / **严禁保存、传播、泄露测试中获取的任何数据**。

对照现有实现，发现两处缺口：
  ① 合规红线段只覆盖了 6 条（内网/爆破/拖库/后门/社工/横向），缺少「最小影响」「轻量测试」
     「禁止自动化遍历与并发」「拿到即停」「禁止保存数据」；
  ② `cleanup_persist_dirs()` **从未被任何地方调用** —— 而落盘文件里存的是**响应正文副本**，
     等于测试数据永久留存，与本规则的「严禁保存」**直接冲突**。

覆盖：
A. 系统提示含公益 SRC 规则要点
B. 落盘保留期配置存在且默认 1 天
C. `cleanup_persist_dirs` 默认取 config，且**确有调用点**（回归「从未被调用」）
D. 服务启动钩子已挂
E. 行为测试：过期分桶被真实清理、新鲜分桶保留
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

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_035_"))
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
print("A. 系统提示含公益 SRC 规则要点")
print("=" * 68)
check("A1 四条基本原则（合法/合规/最小影响/必要授权）",
      "最小影响" in SYS and "必要授权" in SYS)
check("A2 授权范围确认（项目大厅-公益 SRC / 授权域名 IP）",
      "公益 SRC" in SYS and "授权" in SYS)
check("A3 只做轻量测试（抓包改参/简单注入/敏感目录）",
      "轻量测试" in SYS and "抓包改参" in SYS)
check("A4 禁止对核心业务接口自动化遍历/并发/空参数模糊测试",
      "自动化遍历" in SYS and "并发请求" in SYS and "空参数模糊测试" in SYS)
check("A5 获取到即停（不深入、不读敏感数据）",
      "立即停止" in SYS and "不读取敏感数据" in SYS)
check("A6 严禁保存/传播/泄露测试数据",
      "严禁保存" in SYS and "泄露" in SYS)
check("A7 禁止破坏性攻击与暴力破解",
      "拒绝服务" in SYS and "暴力破解" in SYS)
check("A8 禁止拖库（批量下载/导出/爬取）",
      "拖库" in SYS or "批量下载" in SYS)
check("A9 红线段仍属系统提示且优先级最高",
      "绝对不能碰的合规红线" in SYS and "优先级高于" in SYS)
check("A10 保留原有 kb_read compliance-redlines 指引",
      "compliance-redlines" in SYS)

print()
print("B/C. 落盘数据保留期与清理调用点（合规：用完即清）")
print("=" * 68)
check("B1 保留期配置存在", hasattr(config, "PY_EXEC_PERSIST_KEEP_DAYS"))
check("B2 默认 1 天（不长期留存测试数据）",
      config.PY_EXEC_PERSIST_KEEP_DAYS == 1, str(config.PY_EXEC_PERSIST_KEEP_DAYS))

main_src = Path(__import__("app.main", fromlist=["x"]).__file__).read_text(encoding="utf-8")
pyexec_src = Path(pyexec.__file__).read_text(encoding="utf-8")
check("C1 main.py 确实调用了 cleanup_persist_dirs（修复「从未被调用」）",
      "cleanup_persist_dirs(" in main_src)
check("C2 调用时传入 config 保留期",
      "cleanup_persist_dirs(config.PY_EXEC_PERSIST_KEEP_DAYS)" in main_src)
check("C3 函数默认取 config（无参调用即合规保留期）",
      "keep_days = config.PY_EXEC_PERSIST_KEEP_DAYS" in pyexec_src
      or "None:" in pyexec_src and "config.PY_EXEC_PERSIST_KEEP_DAYS" in pyexec_src)

print()
print("D. 服务启动钩子")
print("=" * 68)
check("D1 main.py 挂了 startup 钩子", '@app.on_event("startup")' in main_src)
check("D2 钩子函数名体现清理语义", "_cleanup_stale_persist_dirs" in main_src)

print()
print("E. 行为测试：过期分桶真被清理、新鲜分桶保留")
print("=" * 68)
root = Path(config.PY_EXEC_TMP_ROOT) / "persist"
old_bucket = root / "20200101"
new_bucket = root / "20991231"
for d in (old_bucket, new_bucket):
    d.mkdir(parents=True, exist_ok=True)
    (d / "resp_x.bin").write_bytes(b"RESPONSE-BODY-COPY")
old_ts = time.time() - 10 * 86400
os.utime(old_bucket, (old_ts, old_ts))
os.utime(new_bucket, (time.time(), time.time()))

n = pyexec.cleanup_persist_dirs()
check("E1 过期分桶被删除", not old_bucket.exists(), str(old_bucket))
check("E2 新鲜分桶保留（本次会话仍可用）", new_bucket.exists(), str(new_bucket))
check("E3 返回清理数量为 1", n == 1, str(n))
check("E4 显式指定保留期仍可覆盖",
      isinstance(pyexec.cleanup_persist_dirs(3650), int))

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
