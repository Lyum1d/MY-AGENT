# -*- coding: utf-8 -*-
"""v023.6 补充回归：报告待修项的修复验证（第二批）。

    python test_023_fixes2.py

覆盖：
1. 上下文压缩保留关键命中行 + 自动落候选事实（P0）
2. py_exec 单次直连也提示并留痕（P0）
3. 长 URL 目标不再被误判「目标过长」；超长给出 -d 建议（P1）
4. traffic_states 脏数据清理（P2）
5. 拒绝文本含 for 展开范例（P2）
"""
import json
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

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_236b_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False

from app import agent as agent_mod, pyexec_bridge, store  # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


print("== A. 压缩保留关键命中（P0） ==")
Agent = agent_mod.Agent
kl = Agent._key_lines(
    "some random noise line here\n"
    "  [*] 目标 http://x.com 使用 nginx 1.21.4\n"
    "  [*] CMS 指纹: layui v2.9.22 命中\n"
    "<title>华鑫期货官网</title>\n"
    "HTTP/1.1 200 OK\n"
    "just another filler line\n")
check("识别 nginx 版本行", any("nginx 1.21.4" in k for k in kl), kl)
check("识别 title 行", any("title" in k.lower() for k in kl), kl)
check("最多 3 行（默认上限）", len(kl) <= 3, len(kl))
kl3 = Agent._key_lines("HTTP/1.1 200 OK\n[*] nginx 1.21.4\n<title>x</title>\n", max_lines=5)
check("放宽上限后可识别状态码行", any("200" in k for k in kl3), kl3)
kl2 = Agent._key_lines("no meaningful content at all\n\n")
check("无命中时返回空（回落到首行逻辑）", kl2 == [], kl2)

# 落候选事实
pid = store.create_project("压缩证据测试", "127.0.0.1")["id"]
sess = agent_mod.sessions.create(project=pid)
step = agent_mod.Step(id="call_x1", tool_alias="ehole", tool_name="EHole指纹",
                      target="www.test.com", args="", risk={})
step.status = "done"
step.output = "noise\n[*] 指纹: nginx 1.21.4\n"
sess.steps.append(step)
sess.messages = [{"role": "tool", "tool_call_id": "call_x1", "content": step.output}]
seen: set[str] = set()
# 直接调用实例方法（该方法不依赖实例状态，用 __new__ 绕过 __init__）
inst = Agent.__new__(Agent)
fid = inst._save_compressed_evidence(sess, step, Agent._key_lines(step.output), seen)
check("自动落候选事实并返回 id", bool(fid), fid)
facts = store.list_facts(pid)
check("事实已入库", len(facts) == 1, len(facts))
check("自动摘录标记为 candidate（不得自证已确认）",
      facts and facts[0].get("status") == "candidate", facts[0].get("status") if facts else None)
check("带 step_id 溯源（因果图连边）", facts and facts[0].get("step_id") == "call_x1")
seen2 = {(facts[0].get("content") or "").strip()}
fid2 = inst._save_compressed_evidence(sess, step, Agent._key_lines(step.output), seen2)
check("重复内容不重复落库（去重）", fid2 == "", fid2)

print("== B. py_exec 单次直连也提示（P0） ==")
det = pyexec_bridge.detect_direct_network(
    "import httpx\nH={'a':'b'}\nr=httpx.get('https://x.com/a')\nprint(r.status_code)\n")
check("单次直连被识别为 single_shot", det["single_shot"] is True and det["risky"] is False, det)
det2 = pyexec_bridge.detect_direct_network(
    "from srcagent import safe_http_request\nr=safe_http_request('https://x.com')\n")
check("受控接口不算单次直连", det2["single_shot"] is False, det2)
det3 = pyexec_bridge.detect_direct_network(
    "import os\nprint(os.getcwd())\n")
check("无网络库不触发", det3["single_shot"] is False, det3)
src = (ROOT / "app" / "pyexec.py").read_text(encoding="utf-8")
check("pyexec 对 single_shot 输出提示", "不经过**流量调度器" in src or "不经过" in src)
check("提示说明不受预算/暂停态约束", "不受目标暂停态约束" in src)

print("== C. 长 URL 目标（P1） ==")
u150 = "https://www.site-a.test/hxqhcms/SyncNoRightAction.do?_funccode_=C_CMS_W_Articles&" \
       "action=downloadatt&attguid=CB173DC2F97AB211E9961EBC5BCD7835&exe=view&ext=pdf&x=1"
check("151 字符 URL 通过校验（原先被拒）",
      agent_mod.validate_target(u150) is None, agent_mod.validate_target(u150))
check("超长 URL 给出 -d 建议",
      "-d" in (agent_mod.validate_target("https://a.com/" + "x" * 2100) or ""),
      agent_mod.validate_target("https://a.com/" + "x" * 2100))
check("非 URL 目标仍限 120（防自然语言）",
      agent_mod.validate_target("x" * 130) is not None)

print("== D. 脏数据清理（P2） ==")
store.upsert_traffic_state("", {"root_domain": "0.1", "state": "NORMAL", "reason": ""})
store.upsert_traffic_state("", {"root_domain": "127.0.0.1", "state": "NORMAL", "reason": ""})
store.upsert_traffic_state("", {"root_domain": "site-a.test", "state": "NORMAL", "reason": ""})
n = store.cleanup_traffic_states()
check("删除 1 条无效残留", n == 1, n)
left = {s["root_domain"] for s in store.list_traffic_states("")}
check("合法 IP 与域名保留", "127.0.0.1" in left and "site-a.test" in left, sorted(left))
check("残留已消失", "0.1" not in left)

print("== E. 拒绝文本含改写范例（P2） ==")
src2 = (ROOT / "app" / "pyexec.py").read_text(encoding="utf-8")
check("拒绝文本给循环展开示例", "把它展开为顺序调用" in src2 or "展开为顺序调用" in src2)
check("示例含 safe_http_request 别名写法", 'H = url' in src2 or "safe_http_request as H" in src2)

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
