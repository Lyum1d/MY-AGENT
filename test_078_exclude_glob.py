# -*- coding: utf-8 -*-
"""v078 `exclude` 支持**文件模式**（`test_*.py` 这类）。

## 这个文件防的是什么

v076 给 `ingest` 加了 `exclude`，但只管**目录**。

随后在自审 src-agent 时量化到一个事实：sink 命中里 **119 个（49%）落在字符串字面量内**，
而它们的分布**不是散在字符串里，而是集中在测试文件**：

    test_077_rule_compile_fp.py 13 / test_047_fixes.py 8 / test_034_fixes.py 7 / …

原因很直白：**测试文件里内嵌着「被扫描的代码样本」**（测分档器、测 sink 规则用的），
这些样本字符串被当成了真实代码。

所以正确做法**不是**加一层「代码掩码」（实测：能安全掩掉的只有注释，仅占 8%；
而掩字符串会**误杀 f-string / 字面量规则**，那是真漏报），而是**把它们排出审计范围**。

这个文件锁住四件事：

  ① `test_*.py` 这类**文件名模式**能命中任意深度；
  ② `src/gen/*.java` 这类**相对路径模式**只在那个目录下命中；
  ③ 不含通配符的条目**仍然是目录语义**（`data` 排除目录，不会误伤同名文件）；
  ④ 只影响 `walk_source`（三层共用），**索引与检索同步生效**。

    python test_078_exclude_glob.py
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from app.codebase import ingest as IG        # noqa: E402

ok: list[str] = []
fail: list[str] = []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


FIXTURE = {
    "src/app.py": "x = 1\n",
    "src/util.py": "y = 2\n",
    "src/test_helper.py": "z = 3\n",                 # ← 该被 test_*.py 排掉
    "test_top.py": "w = 4\n",                        # ← 该被排掉（根目录）
    "tests/test_deep.py": "v = 5\n",                 # ← 该被排掉（深层）
    "tests/helper.py": "u = 6\n",                    # ← 不该被排掉
    "src/gen/Gen.java": "class G {}\n",              # ← 该被 src/gen/* 排掉
    "other/gen/Gen.java": "class H {}\n",            # ← 不该被排掉（不同目录）
    "web/app.min.js": "var a=1;\n",                  # ← 该被 *.min.js 排掉
    "web/app.js": "var b=2;\n",                      # ← 不该被排掉
    "data/keep.txt": "k\n",
    "datax/keep.txt": "m\n",                         # ← 诱饵：`data` 不该命中它
}


def _build(root: pathlib.Path):
    for rel, body in FIXTURE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def _files(root, **kw) -> set[str]:
    return {f"{d}/{n}" if d else n for d, n, _ in IG.walk_source(root, **kw)}


def main() -> int:
    print("=" * 68)
    print("v078 exclude 支持文件模式（glob）")

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="v078_glob_"))
    root = tmp / "proj"
    _build(root)
    try:
        base = _files(root)
        check("不排除时收到全部 %d 个文件" % len(FIXTURE),
              base == set(FIXTURE), f"{len(base)}")

        # ---------------------------------------------------------- ① 文件名模式
        print("\n=== ① 文件名模式（任意深度生效） ===")
        f1 = _files(root, exclude=["test_*.py"])
        check("`test_*.py` 排掉根目录的 test_top.py", "test_top.py" not in f1)
        check("`test_*.py` 排掉深层的 tests/test_deep.py", "tests/test_deep.py" not in f1)
        check("`test_*.py` 排掉 src/test_helper.py", "src/test_helper.py" not in f1)
        check("`test_*.py` **不**误伤 tests/helper.py", "tests/helper.py" in f1)
        check("`test_*.py` 不影响非测试文件", "src/app.py" in f1 and "src/util.py" in f1)

        f2 = _files(root, exclude=["*.min.js"])
        check("`*.min.js` 排掉 web/app.min.js", "web/app.min.js" not in f2)
        check("`*.min.js` **不**误伤 web/app.js", "web/app.js" in f2)

        # ---------------------------------------------------------- ② 相对路径模式
        print("\n=== ② 相对路径模式（只在指定目录下命中） ===")
        f3 = _files(root, exclude=["src/gen/*.java"])
        check("`src/gen/*.java` 排掉 src/gen/Gen.java", "src/gen/Gen.java" not in f3)
        check("`src/gen/*.java` **不**误伤 other/gen/Gen.java",
              "other/gen/Gen.java" in f3)

        # ---------------------------------------------------------- ③ 与目录语义不冲突
        print("\n=== ③ 不含通配符的仍是**目录**语义 ===")
        f4 = _files(root, exclude=["data"])
        check("`data` 排掉 data/ 下的文件", not any(x.startswith("data/") for x in f4))
        check("`data` **不**误伤同前缀的 datax/（按路径段匹配）",
              any(x.startswith("datax/") for x in f4))
        check("`data` 不会把**文件** data 当成模式", "src/app.py" in f4)
        f5 = _files(root, exclude=["tests"])
        check("裸目录名 `tests` 排掉整个 tests/",
              not any(x.startswith("tests/") for x in f5))

        # ---------------------------------------------------------- ④ 组合 & 边界
        print("\n=== ④ 组合与边界 ===")
        f6 = _files(root, exclude=["test_*.py", "*.min.js", "src/gen"])
        check("三种写法可以混用",
              {"test_top.py", "web/app.min.js", "src/gen/Gen.java"}.isdisjoint(f6)
              and "src/app.py" in f6)
        check("空/None 时不排除", _files(root, exclude=[]) == base
              and _files(root, exclude=None) == base)
        check("大小写敏感（`TEST_*.py` 不该命中 test_top.py）",
              "test_top.py" in _files(root, exclude=["TEST_*.py"]))
        check("`*` 能命中一切（极端写法不崩）",
              _files(root, exclude=["*"]) == set())

        print("\n=== ④b **精确文件名**也能排（无通配符时同时认目录与文件） ===")
        f7 = _files(root, exclude=["src/util.py"])
        check("`src/util.py` 精确相对路径生效", "src/util.py" not in f7)
        check("`src/util.py` 不影响同目录其它文件", "src/app.py" in f7)
        f8 = _files(root, exclude=["util.py"])
        check("裸文件名 `util.py` 在任意深度生效", "src/util.py" not in f8)
        f9 = _files(root, exclude=["data", "util.py"])
        check("目录名与文件名可混在一条 exclude 里",
              not any(x.startswith("data/") for x in f9) and "src/util.py" not in f9)
        f10 = _files(root, exclude=["src"])
        check("排掉目录 `src` 时其下文件全部不在", not any(x.startswith("src/") for x in f10))
        check("排掉目录 `src` 不影响别处同名文件",
              "tests/helper.py" in f10 and "web/app.js" in f10)

        # ---------------------------------------------------------- ⑤ 三层同步
        print("\n=== ⑤ ⭐ 文件排除必须贯通到索引与检索（不只是扫描统计） ===")
        from app.codebase import index as IX, paths as P, search as SE
        cid = "v078-glob-e2e"
        try:
            r = IG.ingest(root, codebase_id=cid, register_only=True,
                          exclude=["test_*.py"])
            check("报告里记了被排除的**文件**",
                  any("test_" in k for k in r.excluded_dirs), f"{r.excluded_dirs}")
            check("排除项落进 codebase 记录",
                  "test_*.py" in (P.get_codebase(cid).extra.get("exclude") or []))
            idx = IX.build(cid)
            seen = {s.file for s in idx.symbols}
            check("索引里没有 test_*.py 的文件",
                  not any(pathlib.Path(f).name.startswith("test_") for f in seen),
                  f"{sorted(f for f in seen if pathlib.Path(f).name.startswith('test_'))[:3]}")
            hits = SE.search_sinks(cid, limit=500)
            check("检索结果里也没有它们",
                  not any(pathlib.Path(h.file).name.startswith("test_") for h in hits))
        finally:
            P.save_codebases([c for c in P.load_codebases() if c.codebase_id != cid])
            try:
                IX.index_path(cid).unlink()
            except OSError:
                pass

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
