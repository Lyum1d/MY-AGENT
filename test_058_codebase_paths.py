# -*- coding: utf-8 -*-
"""v058 受控根校验的回归测试（实施规格 §9 的强制安全项）。

## 为什么这条测试值得写细

白盒工具里，**唯一一处做错就立刻泄露本机文件**的地方是「按模型给的路径读代码」。
模型控制路径参数，读到的东西会进上下文、可能发往云端 ——
一旦校验被绕过，`config.yaml`（FOFA 密钥）、`data/scope.json`（真实授权靶标）、
`.src_agent_llm.json`（API Key）都能被读出来。

所以这里对每一种**已知逃逸方式**都要有一个真跑的用例。

## 本机实测的两个前提（决定了用例怎么写）

1. **`os.symlink` 在本机不报错但没建成重解析点**（`islink=False`、`readlink` 报
   「不是重分析点」"）→ **符号链接用例无法真跑**，改为**验证测试前置条件**后跳过并说明；
2. **junction（`mklink /J`）可以建**，且 `resolve()` **确实跟随到外部**
   → 用 junction 做**真跑的目录逃逸用例**（这也是更危险的那种：能读整个外部目录）。

    python test_058_codebase_paths.py
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.codebase import paths as P                          # noqa: E402

ok, fail, skipped = [], [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def skip(name, why):
    skipped.append(name)
    print(f"  [SKIP] {name} —— {why}")


TMP = pathlib.Path(tempfile.mkdtemp(prefix="v058_cb_"))
CB_ROOT = TMP / "codebase"          # 模拟一个已入库的代码根
OUTSIDE = TMP / "outside"           # 根外（放「机密」）


def setup():
    CB_ROOT.mkdir(parents=True, exist_ok=True)
    (CB_ROOT / "src").mkdir(exist_ok=True)
    (CB_ROOT / "src" / "main.py").write_text("print('inside')\n", encoding="utf-8")
    OUTSIDE.mkdir(parents=True, exist_ok=True)
    (OUTSIDE / "config.yaml").write_text("fofaKey: SECRET-OUTSIDE\n", encoding="utf-8")


# ---------------------------------------------------------------- 正向
def test_allow():
    print("\n=== 正向：根内的路径必须放行 ===")
    check("根内相对路径", P.resolve_in_root(CB_ROOT, "src/main.py").name == "main.py")
    check("根内相对路径（带 ./）",
          P.resolve_in_root(CB_ROOT, "./src/main.py").name == "main.py")
    check("根内绝对路径（也允许，只要解析后仍在根内）",
          P.resolve_in_root(CB_ROOT, str(CB_ROOT / "src" / "main.py")).name == "main.py")
    check("根内目录", P.resolve_in_root(CB_ROOT, "src").is_dir())
    check("根自身（等于根不算越界）",
          P.resolve_in_root(CB_ROOT, ".") == CB_ROOT.resolve())
    check("根内不存在的文件也放行（交给上层报 not found，不算安全事件）",
          P.resolve_in_root(CB_ROOT, "src/not-there.py").name == "not-there.py")


# ---------------------------------------------------------------- 反向：逃逸
def test_deny():
    print("\n=== 反向：每一种已知逃逸都必须拒绝 ===")
    cases = [
        ("`..` 单层逃逸", "../outside/config.yaml"),
        ("`..` 多层逃逸", "../../../outside/config.yaml"),
        ("`..` 混在中段", "src/../../outside/config.yaml"),
        ("绝对路径在根外", str(OUTSIDE / "config.yaml")),
        ("指向项目自身的敏感文件", str(ROOT / "data" / "scope.json") if
         (ROOT / "data" / "scope.json").exists() else str(ROOT / "README.md")),
        ("空路径", ""),
        ("只有空白", "   "),
        ("UNC 风格路径", r"\\localhost\C$\Windows\win.ini"),
    ]
    for label, cand in cases:
        try:
            got = P.resolve_in_root(CB_ROOT, cand)
            check(f"拒绝：{label}", False, f"竟然放行 → {got}")
        except P.PathEscapeError as e:
            check(f"拒绝：{label}", True, str(e).splitlines()[0][:56])
        except Exception as e:                                # noqa: BLE001
            check(f"拒绝：{label}", False, f"抛了非预期异常 {type(e).__name__}")

    # 根本身不可用
    for label, r in [("根不存在", TMP / "no-such-root"),
                     ("根是文件", CB_ROOT / "src" / "main.py")]:
        try:
            P.resolve_in_root(r, "x.py")
            check(f"拒绝：{label}", False, "竟然放行")
        except P.PathEscapeError as e:
            check(f"拒绝：{label}", True, str(e).splitlines()[0][:56])


# ---------------------------------------------------------------- 重解析点逃逸（真跑）
def test_reparse_escape():
    print("\n=== 重解析点逃逸（这是最危险的一种：能读整个外部目录）===")
    # 先验证测试前置条件：本机的 os.symlink 到底建没建成
    probe_link = CB_ROOT / "_probe_symlink"
    symlink_works = False
    try:
        os.symlink(str(OUTSIDE / "config.yaml"), str(probe_link))
        symlink_works = os.path.islink(probe_link) or probe_link.is_symlink()
    except OSError:
        symlink_works = False
    finally:
        try:
            probe_link.unlink()
        except OSError:
            pass
    if symlink_works:
        try:
            P.resolve_in_root(CB_ROOT, "_probe_symlink")
            check("拒绝：符号链接逃逸（指向根外）", False, "竟然放行")
        except P.PathEscapeError:
            check("拒绝：符号链接逃逸（指向根外）", True)
    else:
        skip("符号链接逃逸", "本机 os.symlink 未建成重解析点（islink=False）—— 用例前置不成立")

    # junction：不需要管理员，且本机实测 resolve() 会跟随到外部
    jdir = CB_ROOT / "_probe_junction"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(jdir), str(OUTSIDE)],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode == 0 and jdir.exists():
        # 护栏自检：先证明这个 junction **确实**指向外部（否则下面的「拒绝」毫无意义）
        check("前置自检：junction 的 resolve() 确实跟随到根外",
              jdir.resolve() == OUTSIDE.resolve(),
              f"{jdir.resolve()}")
        for label, cand in [("经 junction 读文件", "_probe_junction/config.yaml"),
                            ("junction 目录本身", "_probe_junction"),
                            ("经 junction 的深层路径", "_probe_junction/sub/deep.txt")]:
            try:
                got = P.resolve_in_root(CB_ROOT, cand)
                check(f"拒绝：{label}", False, f"竟然放行 → {got}")
            except P.PathEscapeError as e:
                check(f"拒绝：{label}", True, str(e).splitlines()[0][:50])
        try:
            jdir.rmdir()
        except OSError:
            pass
    else:
        skip("junction 逃逸", "无法创建 junction")


# ---------------------------------------------------------------- 授权记录
def test_codebases_record():
    print("\n=== codebase 授权记录（既是授权凭据，也是审计记录）===")
    f = TMP / "codebases.json"
    with mock.patch.object(P, "CODEBASES_FILE", f):
        check("文件不存在时返回空表（不抛异常 —— 这是正常初始状态）",
              P.load_codebases() == [])
        f.write_text("{ 坏 json", encoding="utf-8")
        check("坏 JSON 返回空表（不抛异常）", P.load_codebases() == [])

        f.write_text(json.dumps({"codebases": [
            {"codebase_id": "cb1", "root": str(CB_ROOT), "source": "opensource",
             "white_layer": "full", "note": "测试", "added_at": "2026-10-03"},
            {"codebase_id": "bad", "root": str(CB_ROOT), "source": "乱填",
             "white_layer": "乱填"},
            {"codebase_id": "missingroot"},
            "不是字典",
        ]}, ensure_ascii=False), encoding="utf-8")
        items = P.load_codebases()
        check("有效条目被读出", len(items) == 2, str([c.codebase_id for c in items]))
        bad = [c for c in items if c.codebase_id == "bad"][0]
        check("非法 source 回落为 opensource（不静默接受未知值）",
              bad.source == "opensource", bad.source)
        check("非法 white_layer 回落为 partial", bad.white_layer == "partial", bad.white_layer)
        check("缺 root 的条目被忽略（宁少不错）",
              all(c.codebase_id != "missingroot" for c in items))
        check("white_layer 有可读说明（层级决定结论上限）", bool(items[0].layer_help))

        # 入口 guard
        try:
            P.guard("cb1", "src/main.py")
            check("guard：已入库 + 根内 → 放行", True)
        except Exception as e:                                # noqa: BLE001
            check("guard：已入库 + 根内 → 放行", False, f"{type(e).__name__}: {e}")
        try:
            P.guard("cb1", "../outside/config.yaml")
            check("guard：已入库 + 越界 → 拒绝", False, "竟然放行")
        except P.PathEscapeError:
            check("guard：已入库 + 越界 → 拒绝", True)
        try:
            P.guard("nope", "src/main.py")
            check("guard：未入库的 codebase_id → 拒绝", False, "竟然放行")
        except P.CodebaseNotFound as e:
            check("guard：未入库的 codebase_id → 拒绝", True, str(e)[:60])
        try:
            P.guard("", "src/main.py")
            check("guard：空 codebase_id → 拒绝", False, "竟然放行")
        except P.CodebaseNotFound:
            check("guard：空 codebase_id → 拒绝", True)

        # 写回 round-trip（原子写，复用 config_io）
        with mock.patch.object(P, "CODEBASES_FILE", f):
            P.save_codebases(items)
            again = P.load_codebases()
            check("save → load round-trip 保真",
                  {c.codebase_id for c in again} == {c.codebase_id for c in items},
                  str([c.codebase_id for c in again]))


# ---------------------------------------------------------------- 归一化判据
def test_within_normcase():
    print("\n=== 包含性判据：Windows 大小写不敏感，不能出现两种判定 ===")
    check("大小写不同视为同一位置（Windows 语义）",
          P._within(pathlib.Path(r"C:\TBOX"), pathlib.Path(r"c:\tbox\src\a.py")))
    check("不同盘符不算在根内",
          not P._within(pathlib.Path(r"C:\tbox"), pathlib.Path(r"D:\tbox\a.py")))
    check("前缀相同但不是子目录（tbox2 vs tbox）不算在根内",
          not P._within(pathlib.Path(r"C:\tbox"), pathlib.Path(r"C:\tbox2\a.py")))
    check("自身算在根内", P._within(pathlib.Path(r"C:\tbox"), pathlib.Path(r"C:\tbox")))


def main() -> int:
    setup()
    print("=" * 68)
    print("v058 受控根校验（白盒 §9 强制安全项）")
    print(f"  测试根：{CB_ROOT}")
    print(f"  根外（放机密）：{OUTSIDE}")
    print("=" * 68)
    test_allow()
    test_deny()
    test_reparse_escape()
    test_codebases_record()
    test_within_normcase()
    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败 / {len(skipped)} 跳过")
    if skipped:
        print("跳过项：" + "、".join(skipped))
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
