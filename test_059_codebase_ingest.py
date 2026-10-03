# -*- coding: utf-8 -*-
"""v059 入库能力（`app/codebase/ingest.py`）的回归测试。

用**构造的假代码库**测试，不碰任何真实项目 —— 这样断言可以写得很死。

    python test_059_codebase_ingest.py
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.codebase import ingest as I                        # noqa: E402
from app.codebase import paths as P                          # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


TMP = pathlib.Path(tempfile.mkdtemp(prefix="v059_ing_"))


def write(p: pathlib.Path, text: str = "x"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def make_repo(name: str, *, with_build=True, with_deps=True, binary_only=False) -> pathlib.Path:
    """造一个像样的多语言"仓库"。"""
    d = TMP / name
    if binary_only:
        for i in range(5):
            (d / f"libs/mod{i}.class").parent.mkdir(parents=True, exist_ok=True)
            (d / f"libs/mod{i}.class").write_bytes(b"\xca\xfe\xba\xbe" * 20)
        write(d / "README.md", "# 只有字节码")
        return d
    write(d / "index.php", "<?php echo $_GET['a']; ?>")
    write(d / "lib/Util.php", "<?php class Util {} ?>")
    write(d / "src/Main.java", "public class Main {}")
    write(d / "app.py", "print('hi')")
    write(d / "static/app.js", "console.log(1)")
    write(d / "README.md", "# demo")
    if with_build:
        write(d / "composer.json", "{}")
        write(d / "pom.xml", "<project/>")
        write(d / "package.json", "{}")
    if with_deps:                       # 依赖目录必须被跳过
        write(d / "node_modules/lodash/index.js", "module.exports={}")
        write(d / "vendor/autoload.php", "<?php")
        for i in range(30):
            write(d / f"node_modules/lodash/f{i}.js", "x")
    write(d / ".git/config", "[core]")
    (d / "big").mkdir(parents=True, exist_ok=True)
    (d / "big/huge.php").write_bytes(b"a" * (I.MAX_FILE_BYTES + 10))
    return d


# ---------------------------------------------------------------- 扫描
def test_scan():
    print("\n=== 扫描：语言分布 / 跳过依赖 / 构建文件 / 超大文件 ===")
    repo = make_repo("proj1")
    s = I.scan_tree(repo)
    # 注意：假仓库里有 3 个 .php —— index.php、lib/Util.php，以及**超大的** big/huge.php
    check("识别出 PHP（含超大文件，识别不受索引上限影响）",
          s.by_lang.get("php") == 3, str(dict(s.by_lang)))
    check("识别出 Java / Python / JS",
          s.by_lang.get("java") == 1 and s.by_lang.get("python") == 1
          and s.by_lang.get("javascript") == 1, str(dict(s.by_lang)))
    check("跳过了 node_modules（30+ 个文件没进统计）",
          s.skipped_dirs.get("node_modules") == 1 and "javascript" and
          all("node_modules" not in f for f in s.files),
          f"skipped={dict(s.skipped_dirs)} js={s.by_lang.get('javascript')}")
    check("跳过了 vendor 与 .git",
          "vendor" in s.skipped_dirs and ".git" in s.skipped_dirs)
    check("构建/依赖清单被识别",
          set(s.build_files) == {"composer.json", "pom.xml", "package.json"},
          str(s.build_files))
    check("超大文件被标出（不进索引）",
          any("huge.php" in f for f in s.oversized), str(s.oversized[:2]))
    check("超大文件仍计入语言统计（只影响索引，不影响识别）",
          any(f.endswith("huge.php") for f in s.oversized)
          and s.by_lang.get("php") == 3, str(dict(s.by_lang)))
    check("来源不是目录时抛 IngestError",
          _raises(I.IngestError, lambda: I.scan_tree(repo / "nope")))


def _raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


# ---------------------------------------------------------------- 层级判定
def test_white_layer():
    print("\n=== white_layer 判定：自动最高只到 partial（§1.2 + 决策①）===")
    repo = make_repo("proj1")
    s = I.scan_tree(repo)
    lv, why = I.judge_white_layer(s)
    check("有源码 + 构建文件 → partial（**不是 full**）", lv == "partial", f"{lv}：{why[:40]}")
    check("理由里写明「本机未验证可编译运行」", "未验证" in why or "验证" in why, why[:60])

    nb = make_repo("proj_nobuild", with_build=False, with_deps=False)
    lv2, why2 = I.judge_white_layer(I.scan_tree(nb))
    check("有源码但无构建清单 → partial 且理由不同", lv2 == "partial" and why2 != why,
          f"{lv2}：{why2[:40]}")

    bo = make_repo("proj_bin", binary_only=True)
    lv3, why3 = I.judge_white_layer(I.scan_tree(bo))
    check("只有字节码产物 → gray", lv3 == "gray", f"{lv3}：{why3[:50]}")

    empty = TMP / "empty_dir"
    empty.mkdir(exist_ok=True)
    write(empty / "notes.txt", "只有文档")
    lv4, why4 = I.judge_white_layer(I.scan_tree(empty))
    check("无源码 → gray", lv4 == "gray", f"{lv4}：{why4[:40]}")

    check("人工标注 full + 理由 → 通过",
          I.judge_white_layer(s, "full", "我本地构建并跑通了")[0] == "full")
    check("标 full 但**不给理由** → 拒绝（不让人凭感觉抬结论上限）",
          _raises(I.IngestError, lambda: I.judge_white_layer(s, "full")))
    check("非法层级值 → 拒绝",
          _raises(I.IngestError, lambda: I.judge_white_layer(s, "半白")))


# ---------------------------------------------------------------- id
def test_id():
    print("\n=== codebase_id：稳定且重名不互相覆盖 ===")
    a1 = I.make_codebase_id("/x/proj", "opensource")
    a2 = I.make_codebase_id("/x/proj", "opensource")
    b = I.make_codebase_id("/y/other/proj", "opensource")
    check("同一来源 → 同一 id（可重复）", a1 == a2, a1)
    check("重名不同来源 → 不同 id（带哈希）", a1 != b, f"{a1} vs {b}")
    check("id 是文件名安全的形式", all(c.isalnum() or c in "-_." for c in a1), a1)


# ---------------------------------------------------------------- 入库（真跑）
def test_ingest():
    print("\n=== 入库：复制进受控根 + 写授权记录 ===")
    store = TMP / "store"
    rec = TMP / "codebases.json"
    repo = make_repo("proj1")
    with mock.patch.object(I, "CODEBASE_STORE", store), \
         mock.patch.object(P, "CODEBASES_FILE", rec):
        # dry_run：不落盘、不写记录
        d = I.ingest(repo, dry_run=True)
        check("dry_run 返回元数据", d.file_count > 0 and d.white_layer == "partial")
        check("dry_run **不复制**（store 目录未创建）", not store.exists())
        check("dry_run **不写记录**", not rec.exists())

        r = I.ingest(repo, note="测试用")
        # ⚠️ 必须比 `store.resolve()`：tempfile 给的是 **8.3 短名**（形如 `USERNA~1`），
        # 而 `ingest` 对受控根调了 `.resolve()`，短名会被展开成长名（完整用户名的形式）
        # —— 直接比字符串会因为"同一位置的两种写法"而误判。
        # 这也顺带说明 `paths.resolve_in_root` 为什么两边都先 resolve：短名/长名、
        # 大小写、`..`、重解析点，全靠这一步统一。
        check("真入库：受控根在 store 下",
              str(store.resolve()) in str(r.root), str(r.root))
        check("真入库：源码已复制过去", (r.root / "index.php").exists())
        check("真入库：依赖目录未被复制", not (r.root / "node_modules").exists())
        check("真入库：记录已写入", rec.exists())
        items = P.load_codebases()
        check("记录里能查到该 codebase",
              any(c.codebase_id == r.codebase_id for c in items),
              str([c.codebase_id for c in items]))
        got = P.get_codebase(r.codebase_id)
        check("记录带 white_layer 与来源", got.white_layer == "partial"
              and got.source == "opensource", f"{got.white_layer}/{got.source}")
        check("记录里存了文件数与语言分布（审计记录）",
              got.extra.get("file_count") == r.file_count, str(got.extra.get("file_count")))
        # ★ 关键：入库后 guard 能读，且仍拦得住越界
        check("guard 能读到根内文件",
              P.guard(r.codebase_id, "index.php").name == "index.php")
        check("guard 仍拦得住越界（受控根不是摆设）",
              _raises(P.PathEscapeError,
                      lambda: P.guard(r.codebase_id, "../../../config.yaml")))

        # 重复入库：清掉旧的再放新的（避免新旧混在一起让索引无法解释）
        write(repo / "index.php", "<?php // 改过了")
        r2 = I.ingest(repo)
        check("重复入库 id 不变", r2.codebase_id == r.codebase_id)
        check("重复入库后内容是新的",
              "改过了" in (r2.root / "index.php").read_text(encoding="utf-8"))
        check("记录没有重复条目",
              len([c for c in P.load_codebases() if c.codebase_id == r.codebase_id]) == 1)

        # register_only
        r3 = I.ingest(repo, register_only=True, codebase_id="inplace")
        check("register_only：受控根 = 来源目录本身",
              r3.root == repo.resolve(), str(r3.root))
        check("register_only：有明确警告（目录可能被外部改动）",
              any("外部改动" in w for w in r3.warnings), str(r3.warnings))
        check("register_only：没有复制出第二份",
              not (store / "inplace").exists())

        # 非法来源类型
        check("source 非法值 → 拒绝",
              _raises(I.IngestError, lambda: I.ingest(repo, source_kind="随便")))


# ---------------------------------------------------------------- 上限
def test_limits():
    print("\n=== 上限：被测代码可能有巨量文件（§9）===")
    repo = make_repo("proj1")
    with mock.patch.object(I, "MAX_FILES", 3):
        s = I.scan_tree(repo, max_files=3)
        check("达到文件数上限即停止并标记 truncated", s.truncated and len(s.files) == 3,
              f"{len(s.files)}/{s.truncated}")
    with mock.patch.object(I, "MAX_TOTAL_BYTES", 10):
        store = TMP / "store2"
        with mock.patch.object(I, "CODEBASE_STORE", store):
            check("总量超限且要复制 → 拒绝（并提示 register_only）",
                  _raises(I.IngestError, lambda: I.ingest(repo)))
            r = I.ingest(repo, register_only=True)
            check("register_only 时总量超限不拦（因为不复制）",
                  r.codebase_id and not store.exists())


def main() -> int:
    print("=" * 68)
    print("v059 代码入库（语言识别 / white_layer 判定 / 受控根落盘）")
    print("=" * 68)
    test_scan()
    test_white_layer()
    test_id()
    test_ingest()
    test_limits()
    shutil.rmtree(TMP, ignore_errors=True)
    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
