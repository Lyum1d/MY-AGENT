# -*- coding: utf-8 -*-
"""扁平 `key: value` 配置解析（本机 config.yaml）。

## 为什么单独成一个模块

它有两个方向的调用者，而两者之间的依赖是**单向**的：

  · `app/fofa.py`、`app/console_api.py` 读 config.yaml 取 FOFA 密钥 / 控制台口令；
  · `app/config.py` 也**需要**读它 —— 取工具箱根目录 `toolboxRoot`（见 config.py 的说明）。

但 `fofa.py` 在模块级 `from . import config`，所以 `config.py` **不能**反向 `from .fofa import`，
那会循环导入。把这个解析器放到一个**不依赖 app 任何模块**的中性位置，两边都能用，
而且**只有一份实现**（本项目反复踩过"同一原理落两份实现、迟早漂移"的坑）。

## 原实现背景（保留）

config.yaml 此前只在装了 pyyaml 时才能读，而 requirements.txt 没声明该依赖，
导致 FOFA 永远提示「未配置」。这里补一个内置兜底，装不装 pyyaml 功能都可用。
**不追求通用 YAML 语义**（嵌套/列表/多行），够用即可；有 pyyaml 时优先走 pyyaml。
"""
from __future__ import annotations

import pathlib


def parse_flat_yaml(text: str) -> dict:
    """无 pyyaml 时的极简解析：只支持本项目 config.yaml 用到的扁平 key: value。"""
    out: dict[str, object] = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line or line.startswith("-"):
            continue
        key, val = line.split(":", 1)
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if not key:
            continue
        out[key] = int(val) if val.isdigit() else val
    return out


def read_flat_yaml(path) -> dict:
    """读一个扁平 yaml 文件，返回 dict。

    **不存在 / 读失败一律返回 `{}`，不抛异常** —— 本机配置缺失是常态
    （config.yaml 不入库，新 clone 的机器上根本没有），调用方不该为此写 try。
    """
    try:
        p = pathlib.Path(path)
        if not p.exists():
            return {}
        return parse_flat_yaml(p.read_text(encoding="utf-8", errors="replace")) or {}
    except Exception:                                        # noqa: BLE001
        return {}
