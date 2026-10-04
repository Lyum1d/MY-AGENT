# -*- coding: utf-8 -*-
"""批量基准：**真实仓库 + 官方标注**，算「按类别的真实召回 / 精确性」。

## 为什么单独一个模块（与 `recall.py` 的分工）

`recall.py` 的 `Case` 是**单点模型**：一条用例 = 「在某个 `文件:行号` 命中某条规则」。
它对**手工写的小样本**很合适（内置语料、DVWA 的几个已知点），但表达不了评测集的语言：

> 「这个仓库里 272 个 SQL 注入用例，你打中了几个？」

那是**批量**的：用例 = **一个测试文件**，标注 = **官方给的（真漏洞 / 安全 + CWE）**。
两者粒度不同，硬塞进 `Case` 只会两边都别扭 —— 所以这里另起一条路径，
`recall.py` 的单点路径**原样保留**（内置语料仍靠它卡硬阈值）。

## ⚠️ 为什么必须这么做：DVWA 的 100% 是假的

v066/v067 用 DVWA 跑出 100% 召回。**那个数字不能信**：DVWA 是我们**手工挑的点**，
而且规则就是**照着那个形态调的**（拼接与 sink 同行）。真实项目里形态完全不同：

- **跨行污染**：`String sql = "... " + param;` 在上一行、`prepareStatement(sql)` 在下一行
  → **单行正则在结构上必然漏**（v069 已用 `call_pattern` + 污点分析补上，见 `taint.py`）；
- **全限定名**：`new java.io.FileInputStream(` —— 规则若只写短名，**522 处漏 500 处**；
- **跨行参数区**：`prepareStatement(\n    sql, ...)` —— 调用名与参数不同行。

**要回答「规则在真实项目上到底行不行」，只有一条路：拿带官方标注的评测集跑。**
本模块就是跑它的机器。首个接入的是 **OWASP BenchmarkJava v1.2**：
`expectedresults-1.2.csv` 有 **2740 条**逐用例标注，是**唯一可信的标尺**。

## 三条纪律（沿用 `recall.py` 的同族约定）

1. **读不到就返回空、绝不抛异常** —— 没配评测集是**正常状态**，不该让基准报错；
2. **不做环境相关的硬卡点** —— 有没有那份检出取决于本机，**只报数，不卡阈值**
   （能卡阈值的只有 `recall.py` 的内置语料）；
3. **「没测」不是「0 分」** —— 精确性在无负样本时返回 `None` 而不是 `0.0`
   （这条在 v067 踩过：真实用例全是正样本时报告显示「精确性 0%」，
   看的人会以为规则在疯狂误报，而事实是**根本没测**）。

## 归属模型：命中 → 用例

评测集按**文件**组织（`BenchmarkTest00001.java`）。一条 sink 命中落在哪个用例里，
就看它的 `file` 路径的 stem —— 与官方 CSV 的**第一列**同名即算这个用例被打了。
（所以这里**不是**「命中行号对不对」，而是「这个漏洞用例你有没有碰到」——
碰不到 = 漏报，这本来就是召回率的定义。）
"""
from __future__ import annotations

import csv
import io
import json
import pathlib
import tempfile
from dataclasses import dataclass, field

from .. import config

#: 本机评测集配置（**不入库**：含本机检出目录的绝对路径，带用户名）。
#: 与 `data/scope.json` / `data/codebases.json` / `data/recall_real.json` 同一套约定：
#: **机制入库（本模块 + `*.example` 模板），本机路径写在被 gitignore 的 json 里。**
BATCH_FILE = config.DATA_DIR / "recall_batch.json"


@dataclass
class Category:
    """一个类别在官方标注下的统计 + 本 Agent 的命中结果。"""
    name: str                       # 官方类别名（如 sqli / pathtraver）
    kind: str = ""                  # 本 Agent 的规则 kind（空 = 能力外）
    vuln_total: int = 0             # 官方标注「真漏洞」的用例数
    safe_total: int = 0             # 官方标注「安全」的用例数
    vuln_hit: int = 0               # 真漏洞用例里被命中的
    safe_hit: int = 0               # 安全用例里被命中的（= 误报）

    @property
    def recall(self) -> float:
        return (self.vuln_hit / self.vuln_total) if self.vuln_total else 0.0

    @property
    def precision(self) -> float | None:
        """打中的里面有多少是真漏洞。**一次都没打中时返回 None（未测）**。

        注意与 `recall.py` 的 `precision_of()`（负样本通过率）**口径不同**：
        那里是「安全样本没被误报的比例」，这里是「命中的判为正的比例」。
        两者数值上互补但基准不同，报告里分别标注，不要混用。
        """
        seen = self.vuln_hit + self.safe_hit
        return (self.vuln_hit / seen) if seen else None

    def render(self, width: int = 14) -> str:
        p = self.precision
        return (f"  {self.name:<{width}} 召回 {self.vuln_hit:4d}/{self.vuln_total:4d} "
                f"= {self.recall:5.1%}   误报 {self.safe_hit:4d}/{self.safe_total:4d}   "
                f"精确性 " + ("（未测）" if p is None else f"{p:.1%}"))


@dataclass
class BatchReport:
    """跑一批评测集的结果。"""
    name: str = ""
    root: str = ""
    csv: str = ""                    # 实际读的标注文件（出问题时要能指出读了哪个）
    codebase_id: str = ""
    file_count: int = 0
    hits_total: int = 0
    cases_total: int = 0             # 官方标注条数
    cases_hit: int = 0               # 被命中的用例文件数（含安全样本的误报）
    categories: list[Category] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ---- 汇总：只算「本 Agent 有能力」的类别 ----
    @property
    def covered(self) -> list[Category]:
        return [c for c in self.categories if c.kind]

    @property
    def uncovered(self) -> list[Category]:
        return [c for c in self.categories if not c.kind]

    def total(self, cats: list[Category]) -> dict[str, int | float | None]:
        """把一组类别合并成一个总数。

        ⚠️ 这个聚合**只能**这么算：分子分母都是**用例数**。
        不要用「命中总数」当指标 —— 一次误报能贡献几十条命中，
        把「命中数」拿来比大小会被单条宽口径规则带偏（v069 实测：删掉一条
        宽口径 `.load(` 后 deserialization 命中从 45 掉到 0，**数字变难看但更真**）。
        """
        v = sum(c.vuln_total for c in cats)
        s = sum(c.safe_total for c in cats)
        vh = sum(c.vuln_hit for c in cats)
        sh = sum(c.safe_hit for c in cats)
        seen = vh + sh
        return {"vuln_total": v, "safe_total": s, "vuln_hit": vh, "safe_hit": sh,
                "recall": (vh / v) if v else 0.0,
                "precision": (vh / seen) if seen else None}

    def render(self) -> str:
        lines = ["=" * 72]
        lines.append(f"批量基准：{self.name or '(未命名)'}")
        lines.append("=" * 72)
        if self.errors:
            for e in self.errors:
                lines.append(f"  ⚠️ {e}")
            return "\n".join(lines + ["=" * 72])
        lines.append(f"  仓库      = {self.root}")
        lines.append(f"  入库 id   = {self.codebase_id}"
                     f"（文件 {self.file_count} 个；sink 命中 {self.hits_total} 处）")
        lines.append(f"  官方标注  = {self.cases_total} 条；被命中的用例文件 "
                     f"{self.cases_hit} 个")
        lines.append("")
        lines.append("【本 Agent 有对应规则的类别】")
        t = self.total(self.covered)
        for c in self.covered:
            lines.append(c.render())
        lines.append("")
        lines.append("  小计（{n} 个类别）：召回 {vh}/{v} = {r:.1%}   误报 {sh}/{s}   "
                     "精确性 {p}".format(
                         n=len(self.covered), vh=t["vuln_hit"], v=t["vuln_total"],
                         r=t["recall"], sh=t["safe_hit"], s=t["safe_total"],
                         p="（未测）" if t["precision"] is None
                         else f"{t['precision']:.1%}"))
        if self.uncovered:
            lines.append("")
            lines.append("【能力外类别（无对应规则）】—— 低召回属预期，不是缺陷")
            for c in self.uncovered:
                lines.append(f"  {c.name:<14} 命中 {c.vuln_hit:4d}/{c.vuln_total:4d}")
        lines.append("")
        lines.append("  ⚠️ 这不是判决书，是**被测物的体检表**：")
        lines.append("     低召回 = 规则还没覆盖这个形态（多数是**跨行/跨函数**，检索层结构上做不到）；")
        lines.append("     精确性低 = 宽口径规则在裸奔。**两者都要看，只看召回会掩盖误报。**")
        lines.append("=" * 72)
        return "\n".join(lines)


CANONICAL_NAME = "expectedresults-1.2.csv"


def load_ground_truth(path: pathlib.Path) -> dict[str, tuple[str, bool, str]]:
    """解析评测集标注 CSV → `{用例名: (类别, 是否真漏洞, CWE)}`。

    约定（OWASP Benchmark 格式，一行一条）：
        BenchmarkTest00001,pathtraver,true,22
    以 `#` 开头的是注释行。**任何坏行跳过而不是报错** —— 标注文件格式漂了
    不该让整批跑不动（宁少不错）。
    """
    out: dict[str, tuple[str, bool, str]] = {}
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) < 3 or not parts[0]:
            continue
        name, cat = parts[0], parts[1]
        if not cat:
            continue
        is_vuln = parts[2].lower() == "true"
        cwe = parts[3] if len(parts) > 3 else ""
        out[name] = (cat, is_vuln, cwe)
    return out


def _csv_of(raw: dict) -> pathlib.Path:
    """定位标注文件：给了文件名就用，否则在仓库根下找 `expectedresults*.csv`。"""
    root = pathlib.Path(raw["dir"])
    name = str(raw.get("ground_truth") or "").strip()
    if name:
        return root / name
    cands = sorted(root.glob("expectedresults*.csv"))
    return cands[0] if cands else root / CANONICAL_NAME


def load_batches(path: pathlib.Path | None = None) -> list[dict]:
    """读本机评测集配置。文件不存在/解析失败一律返回**空表**（不抛异常）。

    返回空表是正常状态：没配评测集时，报告里那一段直接不出现 —— 不该因此报错。
    """
    p = pathlib.Path(path) if path else BATCH_FILE
    try:
        if not p.exists():
            return []
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:                                        # noqa: BLE001
        return []
    items = raw.get("batches") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict) or not it.get("dir"):
            continue                                        # 缺字段直接忽略（宁少不错）
        raw_dir = pathlib.Path(str(it["dir"]))
        if not raw_dir.is_dir():
            continue                                        # 目录不在（换机器了）→ 跳过
        item = dict(it)
        item["csv"] = str(_csv_of(item))                    # 解析好的标注文件路径
        out.append(item)
    return out


# ---------------------------------------------------------------- 跑分

def run_batch(raw: dict, workspace: pathlib.Path,
              *, register_only: bool = True) -> BatchReport:
    """跑一个评测集：入库 → 建索引 → sink 检索 → 按官方标注算数。

    **只读被测仓库**；入库/索引的落盘位置改到 workspace 下（不碰真实 store）。
    """
    from . import ingest as G
    from . import index as I
    from . import search as Q
    from .recall import _patched

    root = pathlib.Path(raw["dir"])
    rep = BatchReport(name=str(raw.get("name") or root.name), root=str(root))

    # `csv` 通常由 `load_batches()` 解析好；直接调用本函数时自己补（少一个必填字段，
    # 少一个「配置里漏写就崩」的坑）。
    csv_path = pathlib.Path(raw["csv"]) if raw.get("csv") else _csv_of(raw)
    rep.csv = str(csv_path)
    truth = load_ground_truth(csv_path)
    if not truth:
        rep.errors.append(f"读不到标注文件（{csv_path}）→ 该批跳过。"
                          f"OWASP Benchmark 的标注在仓库根下 expectedresults-1.2.csv。")
        return rep
    rep.cases_total = len(truth)

    # 类别 → 本 Agent 的 kind。写在配置里（各评测集用词不同，不该硬编码进代码）。
    cat_kind: dict[str, str] = {str(k): str(v)
                                for k, v in (raw.get("category_kind") or {}).items()}

    with _patched(workspace / "_store", workspace):
        r = G.ingest(str(root), codebase_id=f"batch-{rep.name}",
                     source_kind=str(raw.get("source_kind") or "opensource"),
                     register_only=register_only)
        I.build(r.codebase_id)
        hits = Q.search_sinks(r.codebase_id, limit=500_000)

        rep.codebase_id = r.codebase_id
        rep.file_count = r.file_count
        rep.hits_total = len(hits)

        # 命中 → 用例文件（按 stem 归属；官方 CSV 第一列就是这个名字）
        hit_cases = {pathlib.Path(h.file).stem for h in hits}
        rep.cases_hit = len(hit_cases & set(truth))

        by_cat: dict[str, Category] = {}
        for name, (cat, is_vuln, _cwe) in truth.items():
            c = by_cat.setdefault(cat, Category(name=cat, kind=cat_kind.get(cat, "")))
            if is_vuln:
                c.vuln_total += 1
                if name in hit_cases:
                    c.vuln_hit += 1
            else:
                c.safe_total += 1
                if name in hit_cases:
                    c.safe_hit += 1
        # 有规则的排前面（这才是可读的那部分），同类按名字稳定排序
        rep.categories = sorted(by_cat.values(), key=lambda c: (not c.kind, c.name))
    return rep


def evaluate_batches(batches: list[dict] | None = None,
                     workspace: pathlib.Path | None = None) -> list[BatchReport]:
    """跑全部评测集。默认读 `data/recall_batch.json`，没有就返回空表。"""
    if batches is None:
        batches = load_batches()
    tmp = pathlib.Path(workspace) if workspace else pathlib.Path(
        tempfile.mkdtemp(prefix="batch_"))
    tmp.mkdir(parents=True, exist_ok=True)
    out: list[BatchReport] = []
    for b in batches:
        try:
            out.append(run_batch(b, tmp))
        except Exception as e:                                # noqa: BLE001
            r = BatchReport(name=str(b.get("name") or ""), root=str(b.get("dir") or ""))
            r.errors.append(f"该批执行出错：{type(e).__name__}: {e}")
            out.append(r)
    return out


def render_all(reports: list[BatchReport]) -> str:
    if not reports:
        return ("（未配置批量基准 —— 见 data/recall_batch.json.example。"
                "这是**正常状态**：评测集取决于本机有没有检出那份代码。）")
    return "\n\n".join(r.render() for r in reports)
