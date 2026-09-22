# -*- coding: utf-8 -*-
"""v034 回归：口径一致性与短响应取证（第六轮 某企业站 实战暴露）。

    python test_034_fixes.py

背景：第六轮 Agent 做了非常扎实的验证，指出 v033 的三处遗留：
  ① `truncation_note` 里仍教 `open(path, encoding='utf-8').read()` —— **文本模式读**，
     会把刚修好的 `.bin` 重新做 `\\r\\n` 转换，**再次引入同型污染**；
  ② 模块文档示例同样写着 `encoding="utf-8"`；
  ③ `total_chars / total_bytes` 只在落盘或截断时才出现，导致 141 字节的 404 响应
     四个字段全为 None，「三方自洽核验」在小响应上**无法实测**；
  ④ 落盘阈值 8192 偏高 —— 7692 字节的 common.js 曾因此未落盘、脚本崩溃后只能重取。

覆盖：
A. `truncation_note` 教的是 rb 读法，且不再出现 encoding='utf-8' 读法
B. 模块文档示例为 rb 读法
C. `total_chars` / `total_bytes` 无条件给出（在 resp 字面量里，不受阈值门控）
D. 阈值默认 1024 且小于 TEXT_LIMIT
E. 文档新增「字节口径自检」说明
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

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_034_"))
config.SCOPE_FILE = _TMP / "scope.json"
config.SCOPE_FILE.write_text('{"targets": [{"host": "127.0.0.1"}]}', encoding="utf-8")
config.TRAFFIC_TEST_MODE = False
config.PY_EXEC_TMP_ROOT = _TMP / "scripts" / "tmp"

from app import pyexec_bridge                             # noqa: E402

ok, fail = [], []


def check(name, cond, detail=""):
    (ok if cond else fail).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{detail}]" if detail and not cond else ""))


src = Path(pyexec_bridge.__file__).read_text(encoding="utf-8")
# 取出 SCRIPT_MODULE_SOURCE（脚本侧文档）单独看
doc = pyexec_bridge.SCRIPT_MODULE_SOURCE

print("=" * 68)
print("A/B. 读法口径：一律 rb，不再教文本模式读落盘文件")
print("=" * 68)
check("A1 truncation_note 用 rb 读法",
      "open(r['saved_text_path'], 'rb').read()" in src)
check("A2 truncation_note 不再含 encoding='utf-8' 读法",
      "open(r['saved_text_path'], encoding='utf-8')" not in src)
check("A3 truncation_note 点明「原始字节」",
      "完整正文已落盘（原始字节）" in src)
check("B1 模块文档给出读落盘文件的**字节口径**写法",
      'open(r["saved_text_path"], "rb").read()' in doc or "load_bytes" in doc)
# v045.2 起，文档改成推荐受控接口 `load_bytes`，并明写「不要用 open()」——
# 因为裸 `open()` 会被能力分档器判为非只读，**被推荐的标准动作反而过不了自己的闸门**。
# 所以断言要跟着表达意图（字节口径 + 不推荐裸 open），而不是钉死某个具体写法
# —— 钉写法的测试会在实现改进时误报，这类「假阴性」比真失败更浪费排查时间。
check("B1b 文档不再推荐裸 open() 读落盘文件",
      'open(r["saved_text_path"], "rb")' not in doc)
check("B2 模块文档不再用 encoding=\"utf-8\" 读落盘文件",
      'open(r["saved_text_path"], encoding="utf-8")' not in doc)
check("B3 模块文档警告「口径混用产生伪差异」",
      "口径混用" in doc or "不是同一个东西" in doc)

print()
print("C. 字节/字符元数据无条件给出（短响应也能自洽核验）")
print("=" * 68)
check("C1 resp 字面量里直接含 total_chars",
      '"total_chars": len(text)' in src)
check("C2 resp 字面量里直接含 total_bytes",
      '"total_bytes": full_len' in src)
# 位置校验：元数据必须出现在 resp = {...} 块内，而不是只在 if 分支里
_i_resp = src.index('resp = {"status_code"')
_i_block_end = src.index("}", src.index('"total_bytes": full_len', _i_resp))
_i_save_branch = src.index("if len(text) >= config.PY_EXEC_SAVE_THRESHOLD")
check("C3 元数据在 resp 字面量内、且早于落盘分支",
      _i_block_end < _i_save_branch,
      f"block_end={_i_block_end} save_branch={_i_save_branch}")

print()
print("D. 落盘阈值下调")
print("=" * 68)
check("D1 默认 1024（v034）", config.PY_EXEC_SAVE_THRESHOLD == 1024,
      str(config.PY_EXEC_SAVE_THRESHOLD))
check("D2 仍小于 TEXT_LIMIT（截断前必已落盘）",
      config.PY_EXEC_SAVE_THRESHOLD < config.PY_EXEC_TEXT_LIMIT)
check("D3 覆盖 7692 字节量级（第四轮 common.js 的教训）",
      config.PY_EXEC_SAVE_THRESHOLD < 7692)
os.environ["AGENT_PY_EXEC_SAVE_THRESHOLD"] = "512"
_c = importlib.reload(config)
check("D4 环境变量仍可覆盖", _c.PY_EXEC_SAVE_THRESHOLD == 512)
os.environ.pop("AGENT_PY_EXEC_SAVE_THRESHOLD", None)
config = importlib.reload(_c)

print()
print("E. 文档新增口径自检说明")
print("=" * 68)
check("E1 文档说明每个响应都带 total_chars/total_bytes",
      "字节口径自检" in doc)

print()
print("=" * 68)
print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
if fail:
    print("失败项：")
    for f in fail:
        print("  - " + f)
print("=" * 68)
sys.exit(1 if fail else 0)
