# -*- coding: utf-8 -*-
"""v076 `ingest(exclude=…)` 的回归测试。

## 这个文件防的是什么

`ingest` 原来的「跳过目录」只有 `SKIP_DIRS` 一个来源，而它是**全局通用名**
（`.git` / `node_modules` / `__pycache__`）。

自审 src-agent 时实测到后果：源目录 677 个文件里 **479 个根本不属源码**
（`data/scripts/` 258、`data/codebases/` 128、`data/kb/` 52、…），
sink 扫描 **670 个命中里 244 个（36%）落在这些数据目录里** —— 全是噪声。

于是加了**调用方显式指定**的 `exclude`。这个文件锁住四件事：

  ① **真的生效**：排除的目录不进 `files` / `by_lang` / `total_bytes`；
  ② **不静默**：被排除的目录记进 `excluded_dirs`，并打印进 `summary()` ——
     否则「没命中」变得不可解释（这正是**不**塞进 `SKIP_DIRS` 的理由）；
  ③ **不误伤**：前缀匹配必须按**路径段**（`data` 不能命中 `database/`）；
  ④ **不破坏既有行为**：`exclude` 不传 / 传空 / 传 None 时结果与改动前逐字节一致。

    python test_076_ingest_exclude.py
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from app.codebase import ingest as IG           # noqa: E402
from app.codebase import index as IX            # noqa: E402
from app.codebase import paths as P             # noqa: E402
from app.codebase import search as SE           # noqa: E402
from app.codebase import tools as T             # noqa: E402

ok: list[str] = []
fail: list[str] = []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


#: 造一棵**有代表性**的树：既含要排除的，也含「名字像但不是」的诱饵
FIXTURE = {
    "app/main.py": "import os\n",
    "app/util.py": "x = 1\n",
    "app/core/deep.py": "y = 2\n",
    "data/scripts/exec/t/run.py": "def g(y):\n    return eval(y)\n",   # ← 噪声源（含 eval）
    "app/sink.py": "def f(x):\n    return eval(x)\n",                    # ← 真源码（含 eval）
    "data/scripts/exec/t/more.py": "w = 4\n",
    "data/kb/note.md": "# n\n",
    "data/codebases/tmp1/Keep.java": "class A {}\n",
    "database/schema.py": "q = 5\n",        # ← 诱饵：不能被 `data` 误伤
    "datax/x.py": "r = 6\n",                # ← 诱饵
    "web/help/index.html": "<html/>\n",     # ← 裸目录名 `help`
    "modules/help/x.html": "<html/>\n",     # ← 同一个裸名，另一处
    "logs/app.log": "line\n",
    "web/app.js": "var a=1;\n",
}


def _build(root: pathlib.Path):
    for rel, body in FIXTURE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def main() -> int:
    print("=" * 68)
    print("v076 ingest(exclude=…)")

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="v076_excl_"))
    root = tmp / "proj"
    _build(root)
    try:
        base = IG.scan_tree(root)
        n_all = len(base.files)

        # ---------------------------------------------------------- ① 真的生效
        print("\n=== ① 排除真的生效（文件数 / 语言分布 / 体积都少） ===")
        s1 = IG.scan_tree(root, exclude=["data"])
        check("`exclude=['data']` 后文件数变少", len(s1.files) < n_all,
              f"{n_all} → {len(s1.files)}")
        check("`data/` 下的文件不再出现在 files 里",
              not any(f.startswith("data/") for f in s1.files))
        check("`data/` 不计入 by_lang",
              "java" not in s1.by_lang, f"by_lang={dict(s1.by_lang)}")
        check("体积相应减少", s1.total_bytes < base.total_bytes)

        s2 = IG.scan_tree(root, exclude=["data/scripts"])
        check("`exclude=['data/scripts']` 只砍这一棵子树",
              not any(f.startswith("data/scripts/") for f in s2.files)
              and any(f.startswith("data/kb/") for f in s2.files))

        # ---------------------------------------------------------- ② 不静默
        print("\n=== ② 排除**不是静默的**（记进 excluded_dirs 并进 summary） ===")
        check("excluded_dirs 记录了被排除的目录名",
              "data" in s1.excluded_dirs, f"{dict(s1.excluded_dirs)}")
        check("路径式写法记录的是相对路径",
              "data/scripts" in s2.excluded_dirs, f"{dict(s2.excluded_dirs)}")
        check("不传 exclude 时 excluded_dirs 为空",
              base.excluded_dirs == {}, f"{dict(base.excluded_dirs)}")

        res = IG.ingest(root, codebase_id="v076-fixture", register_only=True,
                        dry_run=True, exclude=["data", "logs"])
        check("ingest(...).excluded_dirs 带出来了",
              set(res.excluded_dirs) == {"data", "logs"}, f"{res.excluded_dirs}")
        txt = res.summary()
        check("summary() 打印「排除目录」", "排除目录" in txt)
        check("summary() 明确写着这是调用方指定的（不可当自动判断）",
              "显式指定" in txt)

        # ---------------------------------------------------------- ③ 不误伤
        print("\n=== ③ 前缀匹配按**路径段**，不误伤同前缀的兄弟目录 ===")
        check("`data` 不命中 `database/`",
              any(f.startswith("database/") for f in s1.files))
        check("`data` 不命中 `datax/`",
              any(f.startswith("datax/") for f in s1.files))
        s3 = IG.scan_tree(root, exclude=["data/script"])   # 差一个 s
        check("`data/script`（少个 s）不命中 `data/scripts/`",
              any(f.startswith("data/scripts/") for f in s3.files))
        s4 = IG.scan_tree(root, exclude=["help"])
        check("裸目录名 `help` 命中任意深度（web/help 与 modules/help 都没了）",
              not any("/help/" in f or f.startswith("help/") for f in s4.files))
        check("裸目录名写法不影响其它目录",
              any(f.startswith("app/") for f in s4.files))

        # ---------------------------------------------------------- ④ 不破坏既有
        print("\n=== ④ 不传 / 传空 / 传 None 时与改动前一致 ===")
        check("exclude 不传 == scan_tree(root)",
              len(IG.scan_tree(root).files) == n_all)
        check("exclude=[] == 不排除",
              len(IG.scan_tree(root, exclude=[]).files) == n_all)
        check("exclude=None == 不排除",
              len(IG.scan_tree(root, exclude=None).files) == n_all)
        check("exclude=() == 不排除",
              len(IG.scan_tree(root, exclude=()).files) == n_all)

        # ---------------------------------------------------------- ⑤ 归一化
        print("\n=== ⑤ 输入的归一化 ===")
        for raw, desc in (
            (["data/scripts", "data/scripts"], "重复项去重"),
            (["/data/scripts/"], "前后斜杠"),
            (["data\\scripts"], "反斜杠"),
            (["./data/scripts"], "./ 前缀"),
        ):
            e = IG.scan_tree(root, exclude=raw).excluded_dirs
            check(f"{desc} → 归一化成 `data/scripts`",
                  list(e) == ["data/scripts"], f"{raw} → {dict(e)}")
        e = IG.scan_tree(root, exclude=["data", 123, None, "logs"]).excluded_dirs
        check("非字符串项被忽略（不抛异常）",
              set(e) == {"data", "logs"}, f"{dict(e)}")

        # ---------------------------------------------------------- ⑥ 边界
        print("\n=== ⑥ 边界 ===")
        # `exclude` 的语义是**目录**：传文件路径不生效（这是刻意的，避免误以为能按文件排除）
        s_file = IG.scan_tree(root, exclude=["app/main.py"])
        check("`exclude` 只作用于目录 —— 传文件路径不生效",
              s_file.excluded_dirs == {} and len(s_file.files) == n_all,
              f"{dict(s_file.excluded_dirs)}")

        top_dirs = sorted({rel.split("/")[0] for rel in FIXTURE})
        s_all = IG.scan_tree(root, exclude=top_dirs)
        check("排掉全部顶层目录后 files 为空",
              s_all.files == [], f"剩 {len(s_all.files)} 个")
        try:
            IG.ingest(root, codebase_id="v076-empty", register_only=True,
                      dry_run=True, exclude=top_dirs)
            check("全排除时 ingest 报错（而不是静默出一个 0 文件库）", False)
        except IG.IngestError as e:
            check("全排除时 ingest 报可读的错（而不是静默出一个 0 文件库）",
                  True, str(e)[:80])
        except Exception as e:                                  # noqa: BLE001
            check("全排除时抛的是 IngestError", False, f"{type(e).__name__}: {e}")

        # ---------------------------------------------------------- ⑦ 工具接线
        print("\n=== ⑦ code_ingest handler 能传 exclude ===")
        out = T.handle("code_ingest", str(root), "dry_run exclude=data,logs")
        check("handler 输出里出现「排除目录」", "排除目录" in out)
        check("handler 输出里点了 `data` 与 `logs`",
              "data" in out and "logs" in out)

        # ---------------------------------------------------------- ⑧ 贯穿三层
        print("\n=== ⑧ ⭐ 排除必须**贯穿到索引与检索**（不能只是报告上写一句） ===")
        # 这是 v076 最该锁住的一条：第一版只在 ingest 里加了 exclude，
        # index.build / search._collect 各自还走自己的 os.walk ——
        # 结果是「summary 打印已排除、而检索结果一个都没少」，比不修更坏。
        cid = "v076-e2e"
        try:
            r2 = IG.ingest(root, codebase_id=cid, register_only=True,
                           exclude=["data/scripts"])
            check("ingest 报告确实写了「排除目录」", "排除目录" in r2.summary())
            check("排除项落进了 codebase 记录（index/search 才读得到）",
                  P.get_codebase(cid) is not None
                  and "data/scripts" in (P.get_codebase(cid).extra.get("exclude") or []),
                  f"{P.get_codebase(cid).extra.get('exclude') if P.get_codebase(cid) else None}")

            idx = IX.build(cid)
            idx_files = {s.file for s in idx.symbols} | {s.file for s in idx.strings}
            check("索引里**没有**被排除目录的文件",
                  not any(f.startswith("data/scripts/") for f in idx_files),
                  f"索引里还残留 {sorted(f for f in idx_files if f.startswith('data/scripts/'))[:3]}")
            check("索引里保留了**没被排除**的 data 子目录（排除是按路径的，不是一刀切 whole data）",
                  any(f.startswith("data/codebases/") for f in idx_files))
            check("索引里有真源码", any(f.startswith("app/") for f in idx_files))

            hits = SE.search_sinks(cid, limit=500)
            hit_files = sorted({h.file for h in hits})
            check("sink 检索结果里**没有**被排除目录的命中",
                  not any(f.startswith("data/") for f in hit_files), f"{hit_files[:5]}")
            check("sink 检索仍能命中真源码",
                  any(f == "app/sink.py" for f in hit_files), f"{hit_files[:5]}")

            # 反向对照：另建一个**不排除**的 codebase，应能命中 data/ 下的同名噪声
            cid2 = "v076-e2e-noexcl"
            IG.ingest(root, codebase_id=cid2, register_only=True)
            IX.build(cid2)
            hits2 = sorted({h.file for h in SE.search_sinks(cid2, limit=500)})
            check("（反向对照）不排除时 data/ 下的命中确实在",
                  any(f.startswith("data/") for f in hits2), f"{hits2[:5]}")
        finally:
            for _c in ("v076-e2e", "v076-e2e-noexcl"):
                P.save_codebases([c for c in P.load_codebases() if c.codebase_id != _c])
                try:
                    IX.index_path(_c).unlink()
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
