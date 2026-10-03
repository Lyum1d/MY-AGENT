# -*- coding: utf-8 -*-
"""代码检索（实施规格 §4.1 检索层 / §5 的 P3「定位候选」）。

## 输出的是**候选**，不是漏洞

§1.4 说白盒头号陷阱是「误报被当成发现」，而静态匹配**天然判不了可达性与净化**。
所以每条命中都**带着规则的 `why`（为什么危险）与 `hint`（还要看什么）**一起返回 ——
让模型拿到的是「这里有个危险调用点，接下来该验证什么」，
而不是「这里有个漏洞」。

## 三条硬要求

1. **每条命中都带 `文件:行号` + 该行原文** —— §5 的 P3 明确要求行号必须来自工具输出，
   禁止模型凭记忆写；原文则让它能直接引用而不用再猜；
2. **读代码一律走 `paths.guard`** —— 这是 v058 那条受控根校验的唯一消费者，
   也是本能力里唯一「做错就泄露本机文件」的环节。**不允许任何绕过**；
3. **代码内容是不可信数据** —— §9：被测代码里可以写任何文字（包括「忽略之前的指令」）。
   这些内容会进上下文，因此**只当数据用，绝不作为指令执行**。

## 与 `index.py` 的分工

`index.py` 记录**定义**（函数/类/字符串在哪），`search.py` 找**用法**（在哪调用了危险函数）。
两者都确定性、都可回归；判定仍全部交给模型（§4.1 的分层意图）。
"""
from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass, field

from . import index as I
from . import ingest as G
from . import paths as P
from . import sink_rules as S

#: 检索返回条数上限（返回太多既稀释注意力、也吃上下文）
MAX_HITS = 300
#: 单次检索最多扫多少行（防止在大仓库上做无意义的全量扫描）
MAX_SCAN_LINES = 400_000


@dataclass
class Hit:
    file: str            # 相对受控根的 posix 路径
    line: int
    text: str            # 该行原文（**不可信数据**，见模块 docstring 第 3 条）
    lang: str
    kind: str            # 规则类别；正则检索时为 "regex"
    rule_id: str = ""
    why: str = ""
    hint: str = ""
    scope: str = ""      # 所在函数/类（`名字@文件:行号`）—— 判可达性的起点
    extractor: str = ""  # ast | lexical —— 这条命中的抽取精度

    @property
    def loc(self) -> str:
        return f"{self.file}:{self.line}"

    def render(self) -> str:
        """给模型看的单行摘要（紧凑，省上下文）。"""
        head = f"{self.loc}  [{self.kind}] {self.text.strip()[:160]}"
        if self.scope:
            head += f"\n    所在：{self.scope}"
        if self.why:
            head += f"\n    为什么危险：{self.why}"
        if self.hint:
            head += f"\n    还需确认：{self.hint}"
        return head


@dataclass
class _Target:
    root: pathlib.Path
    files: list[pathlib.Path] = field(default_factory=list)
    lang_of: dict[str, str] = field(default_factory=dict)


def _collect(codebase_id: str, langs: set[str] | None) -> _Target:
    """收集待检索的文件。**只读**，且路径全部来自受控根的遍历结果（不经模型输入）。"""
    cb = P.get_codebase(codebase_id)
    if cb is None:
        raise P.CodebaseNotFound(f"codebase「{codebase_id}」未入库 —— 请先 code_ingest。")
    root = pathlib.Path(cb.root)
    if not root.is_dir():
        raise P.CodebaseNotFound(f"受控根不存在：{root}")

    import os
    t = _Target(root=root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in G.SKIP_DIRS]
        for fn in sorted(filenames):
            lang = G.LANG_BY_EXT.get(pathlib.Path(fn).suffix.lower())
            if lang not in G.SUPPORTED_LANGS:
                continue
            if langs and lang not in langs:
                continue
            fp = pathlib.Path(dirpath) / fn
            try:
                if fp.stat().st_size > I.MAX_INDEX_FILE_BYTES:
                    continue
            except OSError:
                continue
            rel = fp.relative_to(root).as_posix()
            t.files.append(fp)
            t.lang_of[rel] = lang
    return t


def _enclosing(idx: I.Index | None, rel: str, line: int) -> str:
    """命中行所属的函数/类（取**行号 ≤ 命中行**里最大的那个符号）。

    这是「判可达性」的起点：模型拿到一个 sink，第一步就是找到它所在的函数、
    再看这个函数是谁调的。索引里已经有全部符号的行号，所以这一步是纯计算。
    """
    if idx is None:
        return ""
    cands = [s for s in idx.symbols if s.file == rel and s.line <= line]
    if not cands:
        return ""
    best = max(cands, key=lambda s: s.line)
    return f"{best.kind} {best.name} @ {best.loc}"


def _scan(codebase_id: str, matcher, *, langs=None, limit=MAX_HITS,
          want_scope: bool = True) -> list[Hit]:
    """共用扫描：按行喂给 `matcher(rel, lang, lineno, text, scope) -> Hit | None`。"""
    t = _collect(codebase_id, langs)
    idx = I.load(codebase_id) if want_scope else None
    hits: list[Hit] = []
    scanned = 0
    for fp in t.files:
        rel = fp.relative_to(t.root).as_posix()
        lang = t.lang_of[rel]
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            scanned += 1
            if scanned > MAX_SCAN_LINES:
                return hits
            h = matcher(rel, lang, lineno, line, idx)
            if h is not None:
                hits.append(h)
                if len(hits) >= limit:
                    return hits
    return hits


# ---------------------------------------------------------------- sink 检索

def search_sinks(codebase_id: str, *, kinds=None, langs=None,
                 limit: int = MAX_HITS) -> list[Hit]:
    """按危险 sink 规则库检索。`kinds`/`langs` 可缩小范围（如只看 rce）。"""
    want_kinds = {k.lower() for k in kinds} if kinds else None
    want_langs = {l.lower() for l in langs} if langs else None

    def matcher(rel, lang, lineno, line, idx):
        for r in S.rules_for(lang):
            if want_kinds and r.kind not in want_kinds:
                continue
            if not r.regex().search(line):
                continue
            return Hit(file=rel, line=lineno, text=line, lang=lang, kind=r.kind,
                       rule_id=r.id, why=r.why, hint=r.hint,
                       scope=_enclosing(idx, rel, lineno),
                       extractor="ast" if lang == "python" else "lexical")
        return None

    hits = _scan(codebase_id, matcher, langs=want_langs, limit=limit)
    # 稳定排序：可回归
    hits.sort(key=lambda h: (h.file, h.line, h.rule_id))
    return hits


# ---------------------------------------------------------------- 正则检索

def search_regex(codebase_id: str, pattern: str, *, langs=None,
                 ignore_case: bool = True, limit: int = MAX_HITS) -> list[Hit]:
    """按正则检索（用户/模型给的模式）。**非法正则退化为转义匹配**，不把工具打挂。"""
    try:
        rx = re.compile(pattern or "", re.I if ignore_case else 0)
        note = ""
    except re.error as e:
        rx = re.compile(re.escape(pattern or ""), re.I if ignore_case else 0)
        note = f"（模式非法正则，已按字面量匹配：{e}）"

    def matcher(rel, lang, lineno, line, idx):
        if not rx.search(line):
            return None
        return Hit(file=rel, line=lineno, text=line, lang=lang, kind="regex",
                   rule_id="", why=note, hint="",
                   scope=_enclosing(idx, rel, lineno),
                   extractor="ast" if lang == "python" else "lexical")

    hits = _scan(codebase_id, matcher, langs=langs, limit=limit)
    hits.sort(key=lambda h: (h.file, h.line))
    return hits


# ---------------------------------------------------------------- 读上下文（走 guard）

def read_context(codebase_id: str, rel: str, line: int,
                 before: int = 5, after: int = 5) -> dict:
    """取某处代码的上下文片段。

    ⚠️ **路径必经 `paths.guard`** —— 这是本能力里唯一「做错就泄露本机文件」的入口。
    `rel` 来自检索结果（相对受控根），但**不能因此信任**：它最终可能被模型改写，
    所以这里一律当外部输入处理。

    返回的 `text` 是**不可信数据**（§9）：只当数据看，绝不作为指令执行。
    """
    if before < 0 or after < 0 or before + after > 400:
        raise ValueError("上下文行数不合理（单个不超过 400 行）")
    if line < 1:
        raise ValueError("行号必须 ≥ 1")

    p = P.guard(codebase_id, rel)              # ← fail-closed，越界直接抛
    if not p.is_file():
        raise P.PathEscapeError(f"不是文件：{rel}")
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        raise P.PathEscapeError(f"读取失败：{e}") from e

    lo = max(1, line - before)
    hi = min(len(lines), line + after)
    numbered = [f"{i:>5} | {lines[i - 1]}" for i in range(lo, hi + 1)]
    idx = I.load(codebase_id)
    return {"file": rel, "line": line, "range": [lo, hi],
            "scope": _enclosing(idx, rel, line),
            "text": "\n".join(numbered),
            "untrusted": True}


def search_symbols(codebase_id: str, name: str = "", *, kind=None, lang=None,
                   limit: int = 200):
    """按名字查符号（委托索引 —— 它已经记了全部定义与行号）。"""
    idx = I.load(codebase_id)
    if idx is None:
        raise P.CodebaseNotFound(
            f"codebase「{codebase_id}」还没有索引 —— 请先跑 code_index。")
    return idx.find_symbols(name, kind=kind, lang=lang, limit=limit)


def search_strings(codebase_id: str, pattern: str, *, limit: int = 200):
    """按内容查字符串（委托索引；密钥类候选常从这里出）。"""
    idx = I.load(codebase_id)
    if idx is None:
        raise P.CodebaseNotFound(
            f"codebase「{codebase_id}」还没有索引 —— 请先跑 code_index。")
    return idx.find_strings(pattern, limit=limit)
