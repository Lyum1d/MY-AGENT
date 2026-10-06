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

    from _codebase_testkit import temp_codebase

    with temp_codebase() as cb:          # cb 是 codebase_id
        hits = Q.search_sinks(cb, limit=500)

    # 退出 with：登记与 data/codebases/<id>/ 副本都被清掉（异常路径也清）

需要「造几个文件再入库」时用 `make_source()` 配合 `ingest`：

    with temp_codebase(files={"A.java": "..."}) as cb:
        ...

## 边界

- **只清理本工具登记的 id** —— 不碰任何既有素材（`dvwa-e6a327` 这些绝不动）；
- 清理失败**不抛异常**（测试的清理不该把测试搞挂），但会打印一行提示；
- `register_only=True` 的情形**没有副本可删**，本工具只负责注销登记。
"""
from __future__ import annotations

import contextlib
import shutil
import tempfile
from pathlib import Path

from app.codebase import ingest as G
from app.codebase import paths as P


def cleanup_codebase(codebase_id: str) -> None:
    """注销一条登记 + 删掉它的落盘副本。**清理失败不抛异常**（不该把测试搞挂）。

    适用于「测试里 `with` 不好包、想自己在 `finally` 统一清」的场景
    （如 `test_069` 三处 ingest 分散在多个 `with tempfile` 块里）。
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
