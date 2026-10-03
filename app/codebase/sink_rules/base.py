# -*- coding: utf-8 -*-
"""sink 规则的数据结构与构造器。

单独成文件是为了**避免循环导入**：`sink_rules/__init__.py` 要汇总各语言模块，
而各语言模块又需要 `SinkRule` 类型 —— 类型放这里，两边都只依赖它。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SinkRule:
    id: str                 # 规则标识（稳定，进报告用）
    lang: str               # php | java | python | javascript | *
    kind: str               # rce | sqli | ssrf | path_traversal | deserialization | …
    pattern: str            # 正则（在**单行**上匹配）
    why: str                # 为什么危险（帮模型判断影响面）
    hint: str = ""          # 要证明可利用还需看什么（可达性/净化）
    _rx: re.Pattern | None = field(default=None, compare=False, repr=False)

    def regex(self) -> re.Pattern:
        if self._rx is None:
            # 大小写**敏感**：`Exec` 与 `exec` 在多数语言里是不同的东西，不能一律放宽。
            # 需要忽略大小写的地方在 pattern 里显式写 `(?i)`。
            object.__setattr__(self, "_rx", re.compile(self.pattern))
        return self._rx


def rule(rid: str, lang: str, kind: str, pattern: str, why: str, hint: str = "") -> SinkRule:
    return SinkRule(rid, lang, kind, pattern, why, hint)
