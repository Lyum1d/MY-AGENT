# -*- coding: utf-8 -*-
"""测试用的 codebase 临时沙箱：入库 → 用完**自动注销 + 删副本**。

## 为什么单独一个模块（v088）

`app/codebase/ingest.py` 默认会把源码**复制**到 `data/codebases/<id>/`，并写进
`data/codebases.json`。测试经常需要走**真实 ingest**（不 mock），于是：

- `test_069_taint_crossline.py` 三处 `G.ingest(...)` **用完从不清理**
  → 每跑一次测试就留一个 `tmp*` 目录 + 一条登记；
- 实测累积：**44 个 tmp 目录**，而 `data/codebases.json` 里 **96 条只有 5 条是真素材**
  （45 条指向 tmp 夹具 + 46 条指向早已消失的系统 Temp）。
- ⚠️ 这不是"占空间"那么轻：`code_list`（`app/codebase/tools.py`）**就读这份记录**
  → 模型每次让 Agent 看代码库清单，看到的是 91 条垃圾。

`test_074_variants.py` 自己写过一份 `_cleanup()`（注释还写着「不留垃圾：它会被
`code_list` 看见」），但它是**私有副本**，别的测试看不见、也就没照做。

⭐ 本项目已在 v076 立过同类判据：**「改一层不算修，收口成一份实现才算」** ——
所以这里不再抄第 N 份 `_cleanup()`，而是提供**一个可复用的上下文管理器**。

## 用法

    from codebase_testkit import temp_codebase

    with temp_codebase() as cb:          # cb 是 codebase_id
        hits = Q.search_sinks(cb, limit=500)

    # 退出 with：登记、data/codebases/<id>/ 副本、data/codebases_index/<id>.json
    # 三者都被清掉（异常路径也清）

需要「造几个文件再入库」时用 `make_source()` 配合 `ingest`：

    with temp_codebase(files={"A.java": "..."}) as cb:
        ...

## 边界

- **只清理本工具登记的 id** —— 不碰任何既有素材（`dvwa-e6a327` 这些绝不动）；
- 清理失败**不抛异常**（测试的清理不该把测试搞挂），但会打印一行提示；
- `register_only=True` 的情形**没有副本可删**，本工具只负责注销登记（索引若已建，仍会删）。
"""
from __future__ import annotations

import contextlib
import shutil
import tempfile
from pathlib import Path

from app.codebase import ingest as G
from app.codebase import paths as P


def cleanup_codebase(codebase_id: str) -> None:
    """注销一条登记 + 删掉它的落盘副本与**索引文件**。**清理失败不抛异常**（不该把测试搞挂）。

    适用于「测试里 `with` 不好包、想自己在 `finally` 统一清」的场景
    （如 `test_069` 三处 ingest 分散在多个 `with tempfile` 块里）。

    ⚠️ **v090：索引文件是第三个落盘位置，v088/v089 漏掉了它。**
    实测：v088/v089 把 `data/codebases/`（45→0）与 `codebases.json`（96→4）都清干净了，
    但 `data/codebases_index/` 里**仍堆着 54 个文件**（53 个 `tmp*.json` + `varstest-v074.json`），
    全是历史测试跑出来的孤儿索引 —— 因为 `index.build()` 把索引写在
    `index.INDEX_DIR/<codebase_id>.json`，与 codebase 副本**不在一起**，
    而本条清理原先只删 `G.CODEBASE_STORE / codebase_id`。

    复现（v090 实测）：跑一次 `test_069_taint_crossline.py`，索引目录 **54 → 55**（+1）。

    ⭐ 教训与 v089 同族：**「登记表 + 副本目录都清了」≠「这件事清了」** ——
    一处逻辑的落盘位置有几处，清理就得覆盖几处（`test_074` 的 `except: pass`、
    `test_059` 只 mock 一半，都是同一个形状）。
    """
    if not codebase_id:
        return
    try:
        items = [c for c in P.load_codebases() if c.codebase_id != codebase_id]
        P.save_codebases(items)
    except Exception as e:                                      # noqa: BLE001
        print(f"  [cbtk] 注销登记失败（不影响测试）：{e}")
    try:
        dst = G.CODEBASE_STORE / codebase_id
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
    except Exception as e:                                      # noqa: BLE001
        print(f"  [cbtk] 删除副本失败（不影响测试）：{e}")
    try:
        # ⚠️ 必须读**当时的** `INDEX_DIR`（不是 import 时的值）—— `recall._patched`
        # 会在跑基准时把它 mock 到临时目录，这里跟着走才不会删错地方。
        from app.codebase import index as I                     # noqa: PLC0415
        idx = I.INDEX_DIR / f"{codebase_id}.json"
        if idx.exists():
            idx.unlink()
    except Exception as e:                                      # noqa: BLE001
        print(f"  [cbtk] 删除索引文件失败（不影响测试）：{e}")


@contextlib.contextmanager
def temp_codebase(codebase_id: str | None = None, files: dict | None = None,
                  source_kind: str = "opensource"):
    """临时 codebase 沙箱：出 `with` 时**注销登记 + 删除落盘副本**。

    :param codebase_id: 指定 id（便于断言）；默认由 ingest 生成。
    :param files: `{相对路径: 内容}` —— 会先落成真实目录再入库；
                  为 None 时只建一个含单个占位文件的目录（够触发 ingest 流程）。
    :yield: codebase_id
    """
    src_dir = Path(tempfile.mkdtemp(prefix="cbtk_src_"))
    created_id: str | None = None
    try:
        payload = files if files else {"placeholder.java": "// cbtk\n"}
        for rel, text in payload.items():
            fp = src_dir / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(text, encoding="utf-8")

        res = G.ingest(str(src_dir), codebase_id=codebase_id,
                       source_kind=source_kind)
        created_id = res.codebase_id
        yield created_id
    finally:
        # ---- 清理：登记与落盘都不留垃圾 ----
        # ⚠️ 只处理**本次真的建出来**的那个 id；ingest 失败时 created_id 为 None，
        #    此时什么都不删（避免误删既有素材）。
        if created_id:
            cleanup_codebase(created_id)
        shutil.rmtree(src_dir, ignore_errors=True)


def purge_orphan_indexes(*, dry_run: bool = True) -> dict:
    """清掉**没有登记条目**的索引文件（孤儿索引）。

    ⚠️ **v090 新增：索引是第三个落盘位置，v088/v089 的清点漏了它。**

    判据：索引文件名就是 `codebase_id`（`index.INDEX_DIR/<id>.json`），
    而 `code_list` 只读**登记表** —— 所以「登记表里没有的 id」对应的索引文件
    **结构上再也无法被检索到**，留着只是垃圾。
    （与 `purge_orphan_codebases` 的判据同构：那边判「root 不存在」，
    这边判「登记不存在」。）

    ⚠️ **不动**登记表里仍存在的 id 的索引 —— 那是真素材（`dvwa-*` / `benchmarkjava-*`）。

    实测（2026-10-07，v090）：本机积累了 **52 个**孤儿索引（51 个 `tmp*.json` +
    `varstest-v074.json`），而真素材只有 3 个索引文件 —— 全部由历史测试跑出来，
    因为修复前的 `cleanup_codebase` 不删索引（已修）。

    :param dry_run: True 只报告不落盘。
    :return: {"orphan": [...], "kept": [...], "removed": n}
    """
    try:
        from app.codebase import index as I                     # noqa: PLC0415
        idx_dir = Path(I.INDEX_DIR)
    except Exception as e:                                      # noqa: BLE001
        print(f"  [cbtk] 读不到 INDEX_DIR（不清理）：{e}")
        return {"orphan": [], "kept": [], "removed": 0}
    live = {c.codebase_id for c in P.load_codebases()}
    orphan, kept = [], []
    if idx_dir.is_dir():
        for fp in sorted(idx_dir.glob("*.json")):
            (kept if fp.stem in live else orphan).append(fp.name)
    if not dry_run:
        for name in orphan:
            try:
                (idx_dir / name).unlink()
            except OSError as e:
                print(f"  [cbtk] 删除 {name} 失败（继续）：{e}")
    return {"orphan": orphan, "kept": kept,
            "removed": 0 if dry_run else len(orphan)}


def purge_orphan_codebases(*, dry_run: bool = True) -> dict:
    """清掉**已不存在的受控根**产生的登记条目（悬空条目）。

    判据：`root` 指向的目录**不存在** ⇒ 这条登记再也无法被检索
    （`ingest.walk_source` 会直接失败），留下只会污染 `code_list`。

    ⚠️ **不动**任何 root 仍存在的条目 —— 包括 tmp 夹具，
    那些要人看过才决定（它们可能还有追溯价值）。

    :param dry_run: True 只报告不落盘。
    :return: {"orphan": [...], "kept": n, "removed": n}
    """
    items = P.load_codebases()
    orphan, kept = [], []
    for c in items:
        r = Path(c.root) if isinstance(c.root, (str, Path)) else None
        if r is None or not r.exists():
            orphan.append(c)
        else:
            kept.append(c)
    if not dry_run and orphan:
        P.save_codebases(kept)
    return {"orphan": [c.codebase_id for c in orphan],
            "kept": len(kept), "removed": 0 if dry_run else len(orphan)}
