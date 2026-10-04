# -*- coding: utf-8 -*-
"""v068 白盒 KB 篇目的回归测试（实施规格 §7.2 末项）。

## 这个文件防的是什么

`data/kb/` 的篇目是**给模型看的文档**，它有个特殊风险：**文档会漂移**。

具体说：篇目里会写「用 `code_search sink rce php` 这么查」「看到 `php.xss.echo_var`
要小心，它口径宽」「规则库 13 个 kind」这类**关于代码本身的事实**。
一旦代码改了（工具改名、规则增删、kind 变多），**文档就变成错的** ——
而错文档比没文档更坏：模型会照着不存在的工具名去调用、照着不存在的 kind 去过滤。

所以这里不测「文档写得好不好」（那是主观的），只测**文档里的断言与代码是否一致**：

  ① 两篇白盒篇目能被 kb 工具正常列出/检索/读取（**接入生效**）；
  ② 篇目里提到的每个 `code_*` 工具名**真实存在于 registry**；
  ③ 篇目里提到的每个 `rule_id` **真实存在于 sink_rules**；
  ④ 篇目里提到的「N 个 kind」**与规则库实际 kind 数一致**；
  ⑤ README 索引表的行数、合计数字、与磁盘实际文件数**三者一致**。

第 ②③④ 项是核心 —— 它们是**可判定**的，所以能卡住。

    python test_068_kb_whitebox_docs.py
"""
from __future__ import annotations

import re
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from app import kb as KB                                     # noqa: E402
from app import registry as REG                              # noqa: E402
from app.codebase import sink_rules as S                     # noqa: E402

KB_DIR = REPO / "data" / "kb"
DOCS = ["whitebox-audit-method.md", "whitebox-sink-triage.md"]

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def _doc_text(fn: str) -> str:
    return (KB_DIR / fn).read_text(encoding="utf-8")


def main() -> int:
    print("=" * 68)
    print("v068 白盒 KB 篇目（文档不漂移）")

    # ---------------------------------------------------------------- ① 接入
    print("\n=== ① 两篇能被 kb 工具正常列出 / 检索 / 读取 ===")
    for fn in DOCS:
        p = KB_DIR / fn
        check(f"{fn} 存在于 data/kb/", p.exists())
    topics = {t["file"] for t in KB.list_topics()}
    for fn in DOCS:
        check(f"{fn} 出现在 list_topics()", fn in topics)

    # 检索：篇目名关键词必须能命中自己
    for kw, expect in (("whitebox", DOCS), ("sink", ["whitebox-sink-triage.md"])):
        got = {h["file"] for h in KB.search(kw, limit=50)}
        hit = [f for f in expect if f in got]
        check(f"kb_search('{kw}') 能命中 {len(hit)}/{len(expect)} 篇",
              len(hit) == len(expect), f"实得 {sorted(got)[:3]}")

    # 读取：全文必须读得出来（默认 max_chars=8000，不长就不该截断）
    for fn in DOCS:
        r = KB.read(fn)
        body = r.get("content", "")
        check(f"kb_read('{fn}') 成功且非空", bool(body) and "error" not in r,
              r.get("error", ""))
        check(f"{fn} 读全文未截断（默认 8000 字符上限内）",
              not body.endswith("…（已截断）"), f"total_chars={r.get('total_chars')}")

    # 篇目里不该出现「本机路径」（与 v056 隐私护栏同一条纪律）
    bad_path = []
    for fn in DOCS:
        txt = _doc_text(fn)
        for m in re.finditer(r"[A-Za-z]:\\Users\\[^\s`\"]+", txt):
            bad_path.append(f"{fn}:{m.group(0)}")
    check("篇目里不含本机绝对路径（C:\\Users\\…）", not bad_path, str(bad_path[:3]))

    # ------------------------------------------------- ② 提到的 code_* 工具真实存在
    print("\n=== ② 篇目提到的每个 code_* 工具都真实存在于 registry ===")
    # registry 里内置工具的 alias 集合
    # ⚠️ 不能只读源码文本：那样「文档写了 code_xxx、但工具其实没注册」也会 PASS
    # （源码里根本没那个字符串，正则抽不到，等于没测）。必须走真实注册表。
    known_code_tools: set[str] = set()
    try:
        reg = REG.registry
        reg.load()                                   # 幂等（v051 已修）
        known_code_tools = {t.alias for t in reg.tools if t.alias.startswith("code_")}
    except Exception as e:                            # noqa: BLE001
        print(f"  （registry 装载失败，退化到源码文本抽取：{e}）")
        reg_src = (REPO / "app" / "registry.py").read_text(encoding="utf-8")
        known_code_tools = set(re.findall(r'"alias":\s*"(code_[a-z_]+)"', reg_src))
    check("能从 registry 里取到 code_* 工具清单", bool(known_code_tools),
          f"{sorted(known_code_tools)}")

    mentioned: dict[str, set[str]] = {}
    for fn in DOCS:
        names = set(re.findall(r"\bcode_[a-z_]+\b", _doc_text(fn)))
        mentioned[fn] = names
    all_mentioned = set().union(*mentioned.values()) if mentioned else set()
    missing = sorted(all_mentioned - known_code_tools)
    check("篇目里的 code_* 工具名全部真实存在（无幻觉工具）",
          not missing, f"不存在的：{missing}" if missing else
          f"提到 {len(all_mentioned)} 个：{sorted(all_mentioned)}")
    # 反向：每个真实存在的 code_* 至少在某篇里被提到过一次（覆盖率）
    never = sorted(known_code_tools - all_mentioned)
    check("每个 code_* 工具都至少被文档提到一次（无孤儿工具）",
          not never, f"未提及：{never}" if never else "")

    # --------------------------------------------------- ③ 提到的 rule_id 真实存在
    print("\n=== ③ 篇目提到的每个 rule_id 都真实存在于规则库 ===")
    real_ids = {r.id for r in S.ALL}
    for fn in DOCS:
        ids = set(re.findall(r"\b(?:php|py|java|js)\.[a-z0-9_.]+\b", _doc_text(fn)))
        bad = sorted(i for i in ids if i not in real_ids)
        check(f"{fn} 里的 rule_id 全部存在",
              not bad, f"不存在的：{bad}" if bad else f"提到 {len(ids)} 条：{sorted(ids)}")

    # ------------------------------------------------------ ④ kind 数与代码一致
    print("\n=== ④ 篇目里写的「N 个 kind」与规则库实际一致 ===")
    actual_kinds = set(S.stats().get("kinds") or [])
    triage = _doc_text("whitebox-sink-triage.md")
    # 从"**13 个 `kind`**"这种写法里抽数字
    m = re.search(r"\*\*(\d+)\s*个\s*`kind`\*\*", triage)
    check("分类篇写明了 kind 总数", bool(m), m.group(0) if m else "未找到「N 个 kind」")
    if m:
        check(f"篇目写的 kind 数（{m.group(1)}）等于实际（{len(actual_kinds)}）",
              int(m.group(1)) == len(actual_kinds),
              f"实际 kinds={sorted(actual_kinds)}")
    # 篇目里逐行列出的 kind（**只取「13 个 kind」那张表**，别把字段表/语言表也抓进来）
    # 做法：从"**N 个 `kind`**"那句开始，到下一个 `---` 或 `##` 为止，只在这个区块里找表行。
    kinds_block = ""
    if m:
        start = triage.find(m.group(0))
        tail = triage[start:]
        end = re.search(r"\n---|\n##", tail)
        kinds_block = tail[:end.start()] if end else tail
    listed = set(re.findall(r"^\|\s*`([a-z_]+)`\s*\|", kinds_block, re.M))
    unknown = sorted(k for k in listed if k not in actual_kinds)
    check("分类篇 kind 表里列出的名字全部真实（且无遗漏）",
          not unknown and listed == actual_kinds,
          (f"可疑：{unknown} " if unknown else "")
          + f"表内 {len(listed)} 个 / 实际 {len(actual_kinds)} 个"
          + (f"，缺失 {sorted(actual_kinds - listed)}" if actual_kinds - listed else ""))

    # 规则库总条数：流程篇/分类篇若写了数字，必须对得上
    total_re = re.search(r"\*\*(\d+)\*\*\s*\|\s*$", triage, re.M)
    if total_re:
        check(f"分类篇写的规则总数（{total_re.group(1)}）等于实际（{len(S.ALL)}）",
              int(total_re.group(1)) == len(S.ALL))

    # ------------------------------------------------- README 索引表三方一致
    print("\n=== ⑤ README 索引表 / 合计数字 / 磁盘文件数 三方一致 ===")
    readme = (KB_DIR / "README.md").read_text(encoding="utf-8")
    table_rows = re.findall(r"^\|\s*`([^`]+\.md)`\s*\|", readme, re.M)
    disk = sorted(p.name for p in KB_DIR.glob("*.md") if p.name != "README.md")
    check("索引表每行都不重复", len(table_rows) == len(set(table_rows)),
          f"{len(table_rows)} 行 / {len(set(table_rows))} 唯一")
    only_disk = sorted(set(disk) - set(table_rows))
    only_table = sorted(set(table_rows) - set(disk))
    check("磁盘有但表里没有的篇目 = 空", not only_disk, str(only_disk))
    check("表里有但磁盘没有的篇目 = 空", not only_table, str(only_table))
    check("索引表行数 == 磁盘文件数", len(table_rows) == len(disk),
          f"表 {len(table_rows)} / 磁盘 {len(disk)}")

    m2 = re.search(r"合计：\s*(\d+)\s*个知识文件", readme)
    check("README 写明合计数量", bool(m2), m2.group(0) if m2 else "未找到")
    if m2:
        check(f"合计数字（{m2.group(1)}）等于磁盘实际（{len(disk)}）",
              int(m2.group(1)) == len(disk), f"磁盘 {len(disk)} 个")
    # 新篇目必须在表里
    for fn in DOCS:
        check(f"{fn} 已注册进索引表", fn in table_rows)

    # --------------------------------------------------------- 内容抽查（非空）
    print("\n=== ⑥ 关键结论确实写进了篇目（防「写了但没写」）===")
    triage_kw = [
        ("forbid_in", "负样本范围限定"),
        ("impossible.php", "现成负样本"),
        ("跨文件", "链路归判定层"),
        ("extractor", "抽取精度字段"),
        ("lexical", "词法 vs AST"),
    ]
    for kw, desc in triage_kw:
        check(f"分类篇含「{kw}」（{desc}）", kw in triage)
    method = _doc_text("whitebox-audit-method.md")
    method_kw = [
        ("Phase 0", "起点"), ("Phase 6", "终点"),
        ("no_evidence", "闸门状态"), ("candidate", "候选状态"),
        ("不可达", "反向结论也要留痕"),
        ("code_ingest", "入库工具"), ("code_index", "索引工具"),
    ]
    for kw, desc in method_kw:
        check(f"流程篇含「{kw}」（{desc}）", kw in method)

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
