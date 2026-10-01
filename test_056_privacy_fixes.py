# -*- coding: utf-8 -*-
"""v056 隐私修复回归：工具箱路径不再写死 + 防「本机路径重新入库」的护栏。

背景（核验发现，见 `outputs/056_项目核验报告.md`）：
三个已跟踪文件里残留作者的本机绝对路径与 Windows 用户名 ——
  · `app/config.py` 的 `TOOLBOX_ROOT` **默认值**写死一个 `E:\\<网盘目录>\\…`；
  · `data/wordlists/common-small.txt` 注释里一条完整本机路径；
  · `data/tool_overrides.json` 一条 `caveat`（**会进模型上下文**）里同一条路径。
三重影响：隐私（暴露本机目录结构）、可用性（那路径在别人机器上不存在却被当默认值）、
以及违反项目自身约定（"不要写死路径"）。

    python test_056_privacy_fixes.py
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config                                     # noqa: E402

GIT = r"D:\Git\cmd\git.exe"
ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


# ---------------------------------------------------------------- 路径三级解析
def test_resolution():
    print("\n=== 工具箱根目录：三级解析（环境变量 > config.yaml > 未配置）===")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="v056_cfg_"))
    with mock.patch.object(config, "APP_DIR", tmp):
        # ① 环境变量优先
        with mock.patch.dict(os.environ, {"TOOLBOX_ROOT": r"D:\from_env"}, clear=False):
            check("环境变量优先", config._toolbox_root_raw() == r"D:\from_env",
                  config._toolbox_root_raw())
        # ② 环境变量缺省时读本机 config.yaml
        (tmp / "config.yaml").write_text(
            "fofaKey: \"\"\ntoolboxRoot: \"D:\\\\from_yaml\\\\tbox\"\n", encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != "TOOLBOX_ROOT"}
        with mock.patch.dict(os.environ, env, clear=True):
            got = config._toolbox_root_raw()
            check("环境变量未设 → 读本机 config.yaml 的 toolboxRoot",
                  got == r"D:\from_yaml\tbox", repr(got))
        # ③ 都没有 → 空串（未配置）
        (tmp / "config.yaml").write_text("fofaKey: \"\"\n", encoding="utf-8")
        with mock.patch.dict(os.environ, env, clear=True):
            check("两者都没有 → 空串（未配置，不是回退到某个写死路径）",
                  config._toolbox_root_raw() == "", repr(config._toolbox_root_raw()))
        # ④ config.yaml 不存在也不能抛
        (tmp / "config.yaml").unlink()
        with mock.patch.dict(os.environ, env, clear=True):
            check("config.yaml 不存在 → 空串且不抛异常",
                  config._toolbox_root_raw() == "")


# ---------------------------------------------------------------- 未配置时的提示
def test_unset_message():
    print("\n=== 未配置时要说清「怎么配」，而不是含糊的「找不到工具清单」===")
    check("存在统一的提示文案常量", isinstance(getattr(config, "TOOLBOX_ROOT_HELP", None), str)
          and "TOOLBOX_ROOT" in config.TOOLBOX_ROOT_HELP)
    from app.registry import registry
    with mock.patch.object(config, "TOOLBOX_ROOT_SET", False), \
         mock.patch.object(config, "TOOLBOX_ROOT", pathlib.Path("")):
        registry.load()
        errs = " ".join(registry.errors)
        check("registry 报错里包含「未配置工具箱根目录」+ 配置方法",
              "未配置工具箱根目录" in errs and "TOOLBOX_ROOT" in errs, errs[:90])
        check("不再只说含糊的「找不到工具清单」", "找不到工具清单" not in errs, errs[:90])
    # ⚠️ 复原必须在 mock 退出**之后**做：在 mock 内部 reload 时 TOOLBOX_ROOT 仍是
    # 未配置态，会把注册表载成 0 个工具并**留在那里**污染后续套件（第一版就踩了这个）。
    registry.load()
    check("复原后注册表仍有工具（不污染后续套件）",
          len(registry.tools) > 100, str(len(registry.tools)))


# ---------------------------------------------------------------- health 字段诚实
def test_health_honest():
    print("\n=== /api/health 在未配置时不得说「工具箱存在」 ===")
    src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    check("health 用 TOOLBOX_ROOT_SET 参与判定（不是直接 .exists()）",
          "config.TOOLBOX_ROOT_SET and config.TOOLBOX_ROOT.exists()" in src)
    check("health 带 toolbox_configured 字段", '"toolbox_configured"' in src)
    check("未配置时 toolbox 不回显 '.'（空串）",
          'str(config.TOOLBOX_ROOT) if config.TOOLBOX_ROOT_SET else ""' in src)


# ---------------------------------------------------------------- 防回归护栏（最重要）
def test_no_local_paths_guard():
    print("\n=== 护栏：已跟踪文件里不得再出现真实本机路径/用户名 ===")
    out = subprocess.run([GIT, "ls-files", "-z"], cwd=str(ROOT), capture_output=True)
    files = [f.decode("utf-8", "replace") for f in out.stdout.split(b"\0") if f]
    check("取到已跟踪文件清单", len(files) > 100, str(len(files)))

    # 真实本机标识（刻意不含 `E:\你的路径` 这类占位符）
    pats = {
        "本机 Windows 用户名": re.compile(r"Lianaxber", re.I),
        "本机网盘下载目录": re.compile(r"BaiduNetdiskDownload", re.I),
        "本机时间戳工作区路径": re.compile(r"WorkBuddy\\+2026-\d\d-\d\d-\d\d-\d\d-\d\d"),
    }
    hits = {}
    for f in files:
        try:
            txt = (ROOT / f).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, rx in pats.items():
            if rx.search(txt):
                hits.setdefault(label, []).append(f)
    check("已跟踪文件无真实本机路径/用户名（**谁再写回去就会红**）",
          not hits, str(hits))

    # 反向对照：占位符写法必须仍然允许（别把好代码判红）
    guide = ROOT / "团队协作指南.md"
    if guide.exists():
        g = guide.read_text(encoding="utf-8", errors="ignore")
        check("文档里的占位符写法（E:\\你的路径\\…）不被误判",
              "你的路径" in g and not pats["本机 Windows 用户名"].search(g))


# ---------------------------------------------------------------- 已修复的三处
def test_three_leaks_gone():
    print("\n=== 核验报告里那 3 处泄漏已修复 ===")
    for f in ("app/config.py", "data/wordlists/common-small.txt",
              "data/tool_overrides.json"):
        txt = (ROOT / f).read_text(encoding="utf-8", errors="ignore")
        check(f"{f} 不再含本机用户名/下载目录",
              not re.search(r"Lianaxber|BaiduNetdiskDownload", txt, re.I))
    # 词表那行现在应是相对路径
    wl = (ROOT / "data/wordlists/common-small.txt").read_text(encoding="utf-8")
    check("词表示例改用相对路径", "data\\wordlists\\common-small.txt" in wl
          or "data/wordlists/common-small.txt" in wl)
    # caveat 仍是合法 JSON
    try:
        json.loads((ROOT / "data/tool_overrides.json").read_text(encoding="utf-8"))
        check("tool_overrides.json 仍是合法 JSON", True)
    except Exception as e:                                    # noqa: BLE001
        check("tool_overrides.json 仍是合法 JSON", False, str(e)[:70])


# ---------------------------------------------------------------- 抽取重构未破坏行为
def test_flat_yaml_extraction():
    print("\n=== 扁平 yaml 解析器抽取后：只有一份实现，且调用方行为不变 ===")
    from app.flat_config import parse_flat_yaml, read_flat_yaml
    from app.fofa import _parse_flat_yaml
    check("fofa 的 _parse_flat_yaml 就是中性模块里那一个（同一对象，非两份实现）",
          _parse_flat_yaml is parse_flat_yaml)
    check("解析基本形态正确",
          parse_flat_yaml("a: 1\nb: \"x\"\n# 注释\nc:\n") == {"a": 1, "b": "x", "c": ""},
          str(parse_flat_yaml("a: 1\nb: \"x\"\n# 注释\nc:\n")))
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="v056_flat_")) / "c.yaml"
    check("文件不存在 → {}（不抛）", read_flat_yaml(tmp) == {})
    tmp.write_text('toolboxRoot: "D:\\\\tbox"\n', encoding="utf-8")
    # 解析器**保持字面量语义**、不代替调用方解释 YAML 转义 ——
    # 归一化（把双反斜杠折成单个）放在 config 层，这样其他键（如 fofaKey 里
    # 可能含特殊字符）不会被 parser 乱改。上面那条 resolution 用例覆盖归一化。
    check("解析器保持字面量（转义解释是调用方的事）",
          read_flat_yaml(tmp).get("toolboxRoot") == "D:\\\\tbox",
          repr(read_flat_yaml(tmp).get("toolboxRoot")))
    check("console_api 仍按原样从 fofa 导入（既有测试依赖这行字符串）",
          "from .fofa import _parse_flat_yaml" in
          (ROOT / "app" / "console_api.py").read_text(encoding="utf-8"))


def main() -> int:
    print("=" * 68)
    print("v056 隐私修复回归（工具箱路径不写死 + 本机路径防回归护栏）")
    print("=" * 68)
    test_resolution()
    test_unset_message()
    test_health_honest()
    test_no_local_paths_guard()
    test_three_leaks_gone()
    test_flat_yaml_extraction()
    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
