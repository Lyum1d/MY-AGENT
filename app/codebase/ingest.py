# -*- coding: utf-8 -*-
"""代码入库（实施规格 §4.1 接入层 / §5 的 P1）。

## 输入什么、输出什么

输入一份代码（本地目录），输出一个 **codebase**：
`codebase_id` + **受控根**（把源码复制进去，见下）+ 元数据（语言分布 / 构建方式 /
`white_layer` / 文件清单）+ 一条授权记录（写 `data/codebases.json`）。

## 两个刻意的设计决定

### 1. 入库 = **复制进受控根**，而不是「就地登记一个目录」

规格 §4.1 写的是「解压/落盘到受控根」，§9 要求入库数据**可清理**。
所以把源码复制到 `data/codebases/<codebase_id>/`：

- 受控根是**我们自己的目录**，`paths.py` 的「根内」判断才有确定含义；
- 要清理时删这一个目录即可，不会动到用户的原始仓库；
- 代价是占一份磁盘 —— 用上限（文件数/单文件大小）把它框住。

### 2. 自动判定的 `white_layer` **最高只到 `partial`**

§1.2 说层级**决定结论强度上限**，而「全白＝完整源码**且能编译运行**」这句话，
**不能由「看见了 `pom.xml`」推出来** —— 那需要真的构建过一次。
首期又明确不含 `code_run`（用户决策①），所以自动流程**没有能力**验证可运行性。

因此：自动判定只会给 `partial` / `gray`；**`full` 只能由人工标注**
（`layer_override` + 记入记录），这与 §4.3「`verified` 只能来自工具背书或人工确认」是同一条纪律。
**宁可保守，也不要让一个没验证过的「全白」把结论上限抬上去。**
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
from collections import Counter
from dataclasses import dataclass, field

from .. import config
from . import paths as P

# ---------------------------------------------------------------- 常量

#: 扩展名 → 语言。**识别**可以认识很多种；**支持**（能索引/分析）只限首批四种。
LANG_BY_EXT = {
    ".php": "php", ".phtml": "php", ".php5": "php",
    ".java": "java", ".jsp": "java", ".jspx": "java",
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rb": "ruby", ".cs": "csharp", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".rs": "rust", ".kt": "kotlin",
    ".scala": "scala", ".sh": "shell", ".ps1": "powershell",
    ".sql": "sql", ".vue": "vue", ".html": "html", ".htm": "html",
}

#: 首批支持分析的语言（用户决策②：PHP → Java → Python → JS）
SUPPORTED_LANGS = ("php", "java", "python", "javascript")

#: 构建/依赖清单文件 → 它所代表的语言
BUILD_FILES = {
    "composer.json": "php", "composer.lock": "php",
    "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java",
    "settings.gradle": "java", "build.xml": "java",
    "requirements.txt": "python", "pyproject.toml": "python",
    "setup.py": "python", "Pipfile": "python", "poetry.lock": "python",
    "package.json": "javascript", "yarn.lock": "javascript",
    "package-lock.json": "javascript", "pnpm-lock.yaml": "javascript",
    "go.mod": "go", "Gemfile": "ruby", "Cargo.toml": "rust",
}

#: 索引时跳过的目录（依赖与产物 —— 既大量又无审计价值；
#: 依赖问题走 `sbom.py` 的清单分析，不是逐文件读）
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "bower_components",
    "dist", "build", "target", "out", "bin", "obj", "__pycache__",
    ".venv", "venv", "env", ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
    "coverage", ".next", ".nuxt", "site-packages",
}

#: 「只有字节码/反编译产物」的特征（→ 灰盒）
BINARY_ARTIFACT_EXT = {".class", ".jar", ".war", ".ear", ".dll", ".so", ".dylib",
                       ".pyc", ".exe", ".o", ".a", ".nupkg"}
SOURCE_EXT = {e for e, lang in LANG_BY_EXT.items()}

#: 上限（§9：被测代码可能包含巨量文件，必须框住）
MAX_FILES = 20000
MAX_FILE_BYTES = 2 * 1024 * 1024          # 单文件超过就不进索引（但不影响语言统计）
MAX_TOTAL_BYTES = 512 * 1024 * 1024       # 复制入库的总量上限

#: 入库数据落在这里（**必须在 .gitignore 里** —— 它是被测代码，不是项目资产）
CODEBASE_STORE = config.DATA_DIR / "codebases"


class IngestError(ValueError):
    """入库失败（来源不可用 / 超限 / 记录写入失败）。"""


# ---------------------------------------------------------------- 数据结构

@dataclass
class Scan:
    root: pathlib.Path
    files: list[str] = field(default_factory=list)          # 相对根的 posix 路径
    by_lang: Counter = field(default_factory=Counter)
    build_files: list[str] = field(default_factory=list)
    total_bytes: int = 0
    skipped_dirs: Counter = field(default_factory=Counter)
    oversized: list[str] = field(default_factory=list)
    binary_only_hint: int = 0          # 只有二进制产物、没有对应源码的计数
    truncated: bool = False            # 是否因 MAX_FILES 提前停止


@dataclass
class IngestResult:
    codebase_id: str
    root: pathlib.Path
    white_layer: str
    white_layer_reason: str
    file_count: int
    by_lang: dict[str, int]
    build_files: list[str]
    total_bytes: int
    skipped_dirs: dict[str, int]
    oversized: list[str]
    supported: bool                  # 是否含首批支持分析的语言
    truncated: bool = False          # 是否因 MAX_FILES 提前停止（summary 里要显示）
    dry_run: bool = False
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        langs = "、".join(f"{k}×{v}" for k, v in
                          sorted(self.by_lang.items(), key=lambda kv: -kv[1])[:6])
        lines = [
            f"codebase_id : {self.codebase_id}",
            f"受控根      : {self.root}",
            f"white_layer : {self.white_layer} —— {self.white_layer_reason}",
            f"文件        : {self.file_count} 个 / {self.total_bytes/1024:.0f} KB",
            f"语言分布    : {langs or '（未识别到已知扩展名）'}",
            f"构建/依赖   : {', '.join(self.build_files) or '（未发现）'}",
            f"首批可分析  : {'是' if self.supported else '否（不在 PHP/Java/Python/JS 内）'}",
        ]
        if self.skipped_dirs:
            lines.append("跳过目录    : " + "、".join(
                f"{k}×{v}" for k, v in sorted(self.skipped_dirs.items())))
        if self.oversized:
            lines.append(f"超大文件    : {len(self.oversized)} 个不进索引（不影响语言统计）")
        if self.truncated:
            lines.append(f"⚠️ 文件数达到上限 {MAX_FILES}，扫描提前停止（该仓库不应全量读）")
        for w in self.warnings:
            lines.append(f"⚠️ {w}")
        return "\n".join(lines)


# ---------------------------------------------------------------- 扫描

def scan_tree(root, *, max_files: int = MAX_FILES) -> Scan:
    """遍历代码树，产出语言分布 / 构建文件 / 大小统计。**只读，不改任何东西。**"""
    root_p = pathlib.Path(root)
    if not root_p.is_dir():
        raise IngestError(f"来源不是目录：{root_p}")

    s = Scan(root=root_p)
    for dirpath, dirnames, filenames in os.walk(root_p):
        # 原地过滤，避免走进去（比 walk 完再筛快得多，也避免被 node_modules 拖死）
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS:
                s.skipped_dirs[d] += 1
            else:
                keep.append(d)
        dirnames[:] = keep

        for fn in filenames:
            p = pathlib.Path(dirpath) / fn
            rel = p.relative_to(root_p).as_posix()
            if len(s.files) >= max_files:
                s.truncated = True
                break
            try:
                size = p.stat().st_size
            except OSError:
                continue
            s.files.append(rel)
            s.total_bytes += size
            if size > MAX_FILE_BYTES:
                s.oversized.append(rel)

            ext = p.suffix.lower()
            lang = LANG_BY_EXT.get(ext)
            if lang:
                s.by_lang[lang] += 1
            if fn in BUILD_FILES:
                if fn not in s.build_files:
                    s.build_files.append(fn)
            if ext in BINARY_ARTIFACT_EXT:
                s.binary_only_hint += 1
        if s.truncated:
            break
    return s


# ---------------------------------------------------------------- white_layer 判定

def judge_white_layer(scan: Scan, override: str | None = None,
                      override_reason: str = "") -> tuple[str, str]:
    """判定白盒层级（§1.2）。返回 `(layer, reason)`。

    **自动判定最高只给 `partial`** —— 理由见模块 docstring：
    「能编译运行」这句话需要真的构建过，而首期不含 `code_run`。
    `full` 只能通过 `override`（人工标注）给出，且必须带上理由。
    """
    if override:
        lv = override.strip().lower()
        if lv not in P.WHITE_LAYERS:
            raise IngestError(f"white_layer 只能是 {P.WHITE_LAYERS}，收到：{override!r}")
        if lv == "full" and not override_reason.strip():
            # 提高结论上限必须有据可依，否则就是「凭感觉说全白」
            raise IngestError("标 full 必须给出理由（override_reason）—— "
                              "全白意味着结论上限最高，不能无据标注")
        return lv, (f"人工标注：{override_reason.strip()}" if override_reason.strip()
                    else "人工标注")

    has_source = bool(scan.by_lang)
    if not has_source:
        if scan.binary_only_hint:
            return "gray", (f"未识别到源码，但有 {scan.binary_only_hint} 个字节码/二进制产物"
                            "（反编译产物或发布包）→ 灰盒")
        return "gray", "未识别到任何源码文件（可能只是配置/文档/资源）"

    if scan.binary_only_hint and scan.binary_only_hint > sum(scan.by_lang.values()):
        return "gray", (f"二进制/字节码产物（{scan.binary_only_hint} 个）多于源码文件"
                        f"（{sum(scan.by_lang.values())} 个）→ 更像反编译产物，按灰盒处理")

    if scan.build_files:
        return "partial", ("有源码与构建/依赖清单，但**本机未验证可编译运行** → 只能算半白"
                           "（要升 full 需人工标注或后续动态验证）")
    return "partial", ("有源码但**未发现构建/依赖清单**，跑不起来的可能性较高 → 半白"
                       "（无法据此认为可运行）")


# ---------------------------------------------------------------- 入库

_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def make_codebase_id(source, extra: str = "") -> str:
    """由来源名生成稳定 id：`<slug>-<6 位哈希>`。

    带哈希是为了**同一个名字的不同来源不会互相覆盖**（重名仓库很常见）。
    """
    name = pathlib.Path(str(source).rstrip("/\\")).name or "codebase"
    slug = _SLUG_RE.sub("-", name).strip("-.").lower()[:40] or "codebase"
    h = hashlib.sha256((str(source) + "|" + extra).encode("utf-8")).hexdigest()[:6]
    return f"{slug}-{h}"


def _copy_tree(src: pathlib.Path, dst: pathlib.Path, skip: set[str]) -> int:
    """把源码复制进受控根（跳过依赖/产物目录与超大文件之外的一切照抄）。"""
    n = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in skip]
        rel = pathlib.Path(dirpath).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for fn in filenames:
            sp = pathlib.Path(dirpath) / fn
            try:
                shutil.copy2(sp, dst / rel / fn)
                n += 1
            except OSError:
                continue
    return n


def ingest(source, *, codebase_id: str | None = None, source_kind: str = "opensource",
           note: str = "", layer_override: str | None = None,
           override_reason: str = "", dry_run: bool = False,
           register_only: bool = False) -> IngestResult:
    """把一份代码入库。

    - 默认**复制**进受控根 `data/codebases/<id>/`（§4.1「落盘到受控根」）；
    - `register_only=True` 时不复制，只把**来源目录本身**登记为受控根
      —— 给「仓库太大/就在本机且不打算动它」的场景留一条路，但**要自己承担
      "这个目录可能被外部改动「的后果**，所以会在 warnings 里写明；
    - `dry_run=True` 只扫描并返回元数据，**不复制、不写记录**（先用它预览）。
    """
    src = pathlib.Path(source).expanduser()
    if not src.is_dir():
        raise IngestError(f"来源不是目录：{src}")

    kind = (source_kind or "opensource").strip().lower()
    if kind not in P.SOURCES:
        raise IngestError(f"source 只能是 {P.SOURCES}，收到：{source_kind!r}")

    scan = scan_tree(src)
    if not scan.files:
        raise IngestError(f"来源里没有可读文件：{src}")
    if scan.total_bytes > MAX_TOTAL_BYTES and not register_only:
        raise IngestError(
            f"来源总量 {scan.total_bytes/1024/1024:.0f} MB 超过上限 "
            f"{MAX_TOTAL_BYTES/1024/1024:.0f} MB —— 请先用 register_only 评估，"
            f"或先裁剪出要审计的子集")

    cid = (codebase_id or "").strip() or make_codebase_id(src, kind)
    layer, reason = judge_white_layer(scan, layer_override, override_reason)

    warnings: list[str] = []
    if register_only:
        root = src.resolve()
        warnings.append(
            "register_only：受控根就是来源目录本身，白盒只读它；"
            "若该目录会被外部改动（重新编译、切分支），读到的内容可能与入库时不一致。")
    else:
        root = (CODEBASE_STORE / cid).resolve()

    supported = any(l in SUPPORTED_LANGS for l in scan.by_lang)

    res = IngestResult(
        codebase_id=cid, root=root, white_layer=layer, white_layer_reason=reason,
        file_count=len(scan.files), by_lang=dict(scan.by_lang),
        build_files=list(scan.build_files), total_bytes=scan.total_bytes,
        skipped_dirs=dict(scan.skipped_dirs), oversized=scan.oversized[:20],
        supported=supported, truncated=scan.truncated,
        dry_run=dry_run, warnings=warnings)

    if dry_run:
        return res

    # ---- 落盘 ----
    if not register_only:
        dst = CODEBASE_STORE / cid
        if dst.exists():
            # 同一 id 重复入库：先清掉旧的，避免新旧文件混在一起（那会让索引结果无法解释）
            shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir(parents=True, exist_ok=True)
        copied = _copy_tree(src, dst, SKIP_DIRS)
        if copied == 0:
            raise IngestError(f"复制失败：{src} → {dst}（0 个文件）")
        root = dst.resolve()

    # ---- 写授权记录 ----
    items = P.load_codebases()
    items = [c for c in items if c.codebase_id != cid]
    items.append(P.Codebase(
        codebase_id=cid, root=root, source=kind, white_layer=layer,
        note=(note.strip() or "") + (f"｜{override_reason.strip()}" if override_reason else ""),
        added_at=_now(), extra={"file_count": res.file_count,
                                "by_lang": res.by_lang,
                                "build_files": res.build_files}))
    P.save_codebases(items)
    return res


def _now() -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S")
