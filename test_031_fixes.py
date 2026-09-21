# -*- coding: utf-8 -*-
"""v031 回归：证据可取回性（第三轮 shhxqh 实战暴露）。

    python test_031_fixes.py

背景：第三轮实战 16 次目标请求里约 6 次是**纯重复开销**，另有 1 次错误判定。
根因是三处截断层层叠加，且**没有任何取回完整数据的途径**：
  ① 受控接口 text 硬截断 65536、无 content 字节流 → 脚本只能改用 Range 再打一次目标；
  ② 步骤输出落库只留头 1500 + 尾 2000 → 中段清单（功能码全集等）永久丢失；
  ③ search_history 只回 220/300 字符片段 → 即使落库有 8KB 也拿不到中段。

覆盖：
A. 受控接口超限时**落盘完整正文**并回 saved_text_path（脚本可离线读全文）
B. 落盘目录与脚本侧 tmpdir() 同口径（否则脚本按 tmpdir() 找不到文件）
C. PY_EXEC_TEXT_LIMIT 默认 131072 且可被环境变量覆盖
D. 脚本侧模块文档声明了 saved_text_path 与「不要为此重发请求」的纪律
E. clip_output 头尾上限 4000/4000（中段丢失面大幅收窄）
F. search_history 片段长度 = SEARCH_SNIPPET_CHARS（step 与 fact 两类）
G. search_history 命中**中段**关键词时能返回该段（旧实现会切掉）
"""
import importlib
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AGENT_TRAFFIC_TEST_MODE", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_031_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.PY_EXEC_TMP_ROOT = _TMP / "scripts" / "tmp"        # 别污染真实目录

from app import agent as agent_mod, pyexec_bridge, store  # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


print("=" * 68)
print("A. 受控接口超限落盘：_dump_full_text 真实落盘且内容一致")
print("=" * 68)
big = "HEAD-" + ("x" * 200000) + "-TAIL"
p = pyexec_bridge._dump_full_text("rid123", big)
check("A1 落盘返回路径非空", p is not None, repr(p))
if p:
    check("A2 文件存在", Path(p).exists())
    read_back = Path(p).read_text(encoding="utf-8")
    check("A3 内容逐字节一致（完整正文，未截断）", read_back == big,
          f"len={len(read_back)} vs {len(big)}")
    check("A4 文件名含请求 id，可区分多次响应", "rid123" in Path(p).name)

print()
print("B. 落盘目录与脚本侧 tmpdir() 同口径")
print("=" * 68)
if p:
    import time as _t
    expect_dir = Path(config.PY_EXEC_TMP_ROOT) / "persist" / _t.strftime("%Y%m%d")
    check("B1 路径落在 PY_EXEC_TMP_ROOT/persist/<day> 下",
          Path(p).parent == expect_dir, f"{Path(p).parent} vs {expect_dir}")

print()
print("C. 上限配置：默认 131072，可被环境变量覆盖")
print("=" * 68)
check("C1 默认 131072（128KB，覆盖常见门户页 110KB）",
      config.PY_EXEC_TEXT_LIMIT == 131072, str(config.PY_EXEC_TEXT_LIMIT))
check("C2 大于旧的 65536 硬编码", config.PY_EXEC_TEXT_LIMIT > 65536)
os.environ["AGENT_PY_EXEC_TEXT_LIMIT"] = "262144"
_c = importlib.reload(config)
check("C3 环境变量 AGENT_PY_EXEC_TEXT_LIMIT 可覆盖",
      _c.PY_EXEC_TEXT_LIMIT == 262144, str(_c.PY_EXEC_TEXT_LIMIT))
os.environ.pop("AGENT_PY_EXEC_TEXT_LIMIT", None)
config = importlib.reload(_c)

print()
print("D. 脚本侧模块文档：声明 saved_text_path 与取全文纪律")
print("=" * 68)
src = pyexec_bridge.SCRIPT_MODULE_SOURCE
check("D1 文档提到 saved_text_path", "saved_text_path" in src)
check("D2 文档提到 total_bytes", "total_bytes" in src)
check("D3 文档明确「不要为此再向目标发请求」", "不要为了拿正文再向目标发请求" in src
      or "不要再向目标发请求" in src or "不要" in src and "再向目标发请求" in src)
check("D4 实现里真的写了 saved_text_path（非仅文档）",
      'resp["saved_text_path"]' in Path(pyexec_bridge.__file__).read_text(encoding="utf-8"))
check("D5 落盘失败时有降级文案", "落盘失败" in Path(pyexec_bridge.__file__).read_text(encoding="utf-8"))

print()
print("E. clip_output：头尾各 4000，中段折叠但标注")
print("=" * 68)
check("E1 STEP_OUTPUT_HEAD 默认 4000", config.STEP_OUTPUT_HEAD == 4000, str(config.STEP_OUTPUT_HEAD))
check("E2 STEP_OUTPUT_TAIL 默认 4000", config.STEP_OUTPUT_TAIL == 4000, str(config.STEP_OUTPUT_TAIL))
long_text = "S" * 3000 + "MIDDLE-MARKER-KEY" + "E" * 3000
clipped = agent_mod.clip_output("A" * 5000 + "MID" + "B" * 5000)
check("E3 总长 10003 的输出被折叠", "中略" in clipped, clipped[:80])
check("E4 头 4000 保留", clipped.startswith("A" * 4000))
check("E5 尾 4000 保留", clipped.endswith("B" * 4000))
short_text = "x" * 100
check("E6 短输出原样返回（不折叠）",
      agent_mod.clip_output(short_text) == short_text)

print()
print("F/G. search_history：片段长度提升 + 中段命中可取回")
print("=" * 68)
PID = "proj031"
with store._db() as c:                                     # noqa: SLF001
    c.execute("INSERT OR REPLACE INTO sessions (id,project_id,task,target,state,"
              "created_at,title,status) VALUES (?,?,?,?,?,?,?,?)",
              ("s031", PID, "枚举功能码", "www.example.com", "done", 1.0,
               "第三轮线索", "done"))
    # 中段才出现的关键词：旧实现（220 字符片段）必然取不到
    middle_heavy = "P" * 2000 + " FUNCCODE_SET=[C_CMS_W_Articles,C_CMS_CalendarInfo] " + "Q" * 2000
    c.execute("INSERT INTO steps (id,session_id,tool_alias,tool_name,target,args,"
              "risk_level,status,output,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
              ("st031", "s031", "py_exec", "py_exec", "www.example.com", "py",
               "L3", "done", middle_heavy, 10.0))

hits = store.search_history(PID, "FUNCCODE_SET")
check("F1 检索命中已落库 step", len(hits) >= 1, str(len(hits)))
step_hit = next((h for h in hits if h.get("kind") == "step"), None)
check("F2 命中项带 snippet", bool(step_hit and step_hit.get("snippet")))
if step_hit:
    sn = step_hit["snippet"]
    check("G1 片段包含关键词本体（中段可取回）", "FUNCCODE_SET" in sn, sn[:120])
    check("G2 片段包含关键词**之后**的内容（旧实现只到 pos+220 且更短）",
          "C_CMS_CalendarInfo" in sn, sn[:200])
    check("G3 片段长度受 SEARCH_SNIPPET_CHARS 约束且明显大于旧的 220",
          len(sn) <= config.SEARCH_SNIPPET_CHARS + 10 and len(sn) > 220,
          str(len(sn)))

# fact 类片段
with store._db() as c:                                     # noqa: SLF001
    c.execute("INSERT INTO facts (id,project_id,content,source,created_at,status)"
              " VALUES (?,?,?,?,?,?)",
              ("f031", PID, "M" * 500 + "FACTKEY-VALUE" + "N" * 500, "note_fact", 3.0, "verified"))
fhits = store.search_history(PID, "FACTKEY-VALUE")
fact_hit = next((h for h in fhits if h.get("kind") == "fact"), None)
check("F3 fact 类命中", fact_hit is not None)
if fact_hit:
    check("F4 fact 片段包含关键词且长度提升",
          "FACTKEY-VALUE" in fact_hit["snippet"]
          and len(fact_hit["snippet"]) > 300, str(len(fact_hit["snippet"])))

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
