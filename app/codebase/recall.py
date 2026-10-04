# -*- coding: utf-8 -*-
"""召回基准（实施规格 §7.3 / §8 的 A2·A8）。

## 它回答什么问题

**「这次改动让召回涨了还是跌了？」** —— 没有基准，改动就是盲改（本项目既有教训）。
所以这里做的是：一组**有已知答案**的代码样本 + 一个能算出数字的跑分器。

## 两类样本（缺一不可）

- **正样本**：含一个已知形态的漏洞，预期「在某个 `文件:行号` 命中某条规则」→ 计入**召回**；
- **负样本**：「看起来能命中、其实安全」的写法（参数化 SQL、列表传参的 subprocess、
  `yaml.safe_load`、`JSON.parse`、`secrets` 而非 `random`）→ 预期**不该**命中那些规则
  → 计入**精确性**。
  ⚠️ **只测召回不测误报，等于只测了一半** —— §1.4 说白盒头号陷阱就是误报被当发现。

## ⚠️ 这里内置的是「形态样本」，不是真实 CVE 的代码

规格 §7.3 建议"用已知有 CVE 的历史版本"做召回测试。本版内置的是**手工写的最小样本**，
它们**复现已知 CVE 的形态**（Log4Shell 的 JNDI lookup、反序列化、LFI、pickle 等），
但**不是那些项目的真实源码**。所以：

> **本基准测的是「规则能不能打中这个形态」，不是「在真实项目里的召回率」。**

这是**刻意的取舍**：内置样本**离线、秒级、确定**，能进日常回归；真实仓库要下载、慢、还会漂。
两者不冲突 —— `Case.dir` 就是给**真实仓库**留的口子：把某项目的已修复版本 checkout 到本地，
在 `REAL_CASES` 里加一条（`dir=` 指向它 + `expect` 写已知的修复点位置），
同一个跑分器就能算真实召回。**机制是本版交付物，语料可以持续长。**

## 已知误报（不藏起来）

有些用例是**已知会红**的（规则本身的精度问题）。它们不写进"必须通过"的断言里，
而是标 `known_fp` 单列出来 —— **既不掩盖问题，也不让它挡住别的回归**。
"""
from __future__ import annotations

import os
import pathlib
import tempfile
from dataclasses import dataclass, field

from . import index as I
from . import ingest as G
from . import paths as P
from . import search as Q


@dataclass
class Case:
    """一个基准样本。

    要么给 `lines`（内置的形态样本，会被物化成临时目录），
    要么给 `dir`（真实仓库/本地目录的路径）。
    """
    id: str
    kind: str                       # positive | negative
    lang: str
    file: str = ""                  # 相对路径（物化时用）
    lines: list[str] = field(default_factory=list)
    dir: str = ""                   # 真实目录（与 lines 二选一）
    # 正样本：期望命中的位置与规则（任一命中即算召回）
    expect_loc: list[str] = field(default_factory=list)
    expect_rules: list[str] = field(default_factory=list)
    # 负样本：**不该**命中的规则
    forbid_rules: list[str] = field(default_factory=list)
    # 已知误报：说明原因后单列，不参与"必须通过"
    known_fp: str = ""
    note: str = ""


#: 依赖的规则必须真的存在（防止规则改名后基准静默失效）
def _rule_exists(rid: str) -> bool:
    from . import sink_rules as S
    return S.by_id(rid) is not None


#: ------------------------------ 内置形态样本（10 正 + 6 负）------------------------------
CORPUS: list[Case] = [
    # ---------------- PHP ----------------
    Case("php_lfi", "positive", "php", "app.php", [
        "<?php",
        "// 形态：文件包含 + 未过滤输入（LFI，配合上传可 RCE）",
        "$page = $_GET['page'];",
        "include($page . '.php');",
        "?>",
    ], expect_loc=["app.php:4"], expect_rules=["php.rce.include"],
        note="最小 LFI 形态（真实案例：大量 PHP CMS 的 page/module 参数）"),
    Case("php_unserialize", "positive", "php", "app.php", [
        "<?php",
        "// 形态：反序列化用户可控数据（POP 链 → RCE）",
        "$data = base64_decode($_COOKIE['u']);",
        "$obj = unserialize($data);",
    ], expect_loc=["app.php:4"], expect_rules=["php.deser.unserialize"],
        note="cookie 反序列化（真实案例：多款 PHP 框架的 remember-me）"),
    Case("php_xss_reflected", "positive", "php", "xss_r.php", [
        "<?php",
        "// 形态取自 DVWA 反射型 XSS：**先拼进变量、之后才输出**",
        "if( array_key_exists( \"name\", $_GET ) && $_GET[ 'name' ] != NULL ) {",
        "    $html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';",
        "}",
    ], expect_loc=["xss_r.php:4"], expect_rules=["php.xss.superglobal_to_html"],
        note="DVWA 真实形态：sink 是「拼 HTML」，输出点可能在**另一个文件**（跨文件是判定层的活）"),
    Case("php_xss_echo", "positive", "php", "out.php", [
        "<?php",
        "// 形态：把数据库里存的用户内容直接输出（存储型 XSS 的输出端）",
        "$name = $row['name'];",
        "echo $name;",
    ], expect_loc=["out.php:4"], expect_rules=["php.xss.echo_var"],
        note="存储型 XSS 的输出端（DVWA xss_s 的 index.php 就是这个形态）"),

    # ---------------- Java ----------------
    Case("java_jndi", "positive", "java", "Lookup.java", [
        "import javax.naming.InitialContext;",
        "public class Lookup {",
        "    public Object resolve(InitialContext ctx, String url) throws Exception {",
        "        return ctx.lookup(url);",
        "    }",
        "}",
    ], expect_loc=["Lookup.java:4"], expect_rules=["java.jndi.lookup"],
        note="JNDI 注入形态（Log4Shell 同源）"),
    Case("java_deser", "positive", "java", "Session.java", [
        "import java.io.ObjectInputStream;",
        "public class Session {",
        "    public Object restore(ObjectInputStream in) throws Exception {",
        "        return in.readObject();",
        "    }",
        "}",
    ], expect_loc=["Session.java:4"], expect_rules=["java.deser.objectinput"],
        note="原生反序列化形态（真实案例：Java 生态最常见的高危类）"),

    # ---------------- Python ----------------
    Case("py_pickle", "positive", "python", "app.py", [
        "import base64",
        "import pickle",
        "",
        "def load_session(cookie):",
        "    raw = base64.b64decode(cookie)",
        "    return pickle.loads(raw)",
    ], expect_loc=["app.py:6"], expect_rules=["py.rce.pickle"],
        note="pickle 反序列化形态（真实案例：Flask session 伪造）"),
    Case("py_shell", "positive", "python", "tool.py", [
        "import subprocess",
        "",
        "def run(user_cmd):",
        "    subprocess.run(user_cmd, shell=True)",
    ], expect_loc=["tool.py:4"], expect_rules=["py.rce.subprocess_shell"],
        note="shell=True 形态（真实案例：无数后台工具的命令注入）"),
    Case("py_sqli_fstring", "positive", "python", "search.py", [
        "def find(cur, name):",
        "    cur.execute(f\"select * from users where name = '{name}'\")",
    ], expect_loc=["search.py:2"], expect_rules=["py.sqli.fstring"],
        note="f-string 拼 SQL 形态"),
    Case("py_hardcoded_secret", "positive", "python", "config.py", [
        "DB_PASSWORD = \"S3cr3t-P@ssw0rd-2026\"",
        "TIMEOUT = 30",
    ], expect_loc=["config.py:1"], expect_rules=["secret.assignment"],
        note="硬编码口令形态（顺带验证：普通配置项不应误报）"),

    # ---------------- JavaScript ----------------
    Case("js_eval", "positive", "javascript", "render.js", [
        "function render(tpl) {",
        "    return eval(tpl);",
        "}",
    ], expect_loc=["render.js:2"], expect_rules=["js.rce.eval"],
        note="eval 动态执行形态"),
    Case("js_exec", "positive", "javascript", "run.js", [
        "const cp = require(\"child_process\");",
        "",
        "function run(cmd) {",
        "    return cp.exec(cmd);",
        "}",
    ], expect_loc=["run.js:4"], expect_rules=["js.rce.child_process"],
        note="Node 命令执行形态"),

    # ---------------- 负样本（测精确性）----------------
    Case("neg_py_param_sql", "negative", "python", "db.py", [
        "def find(cur, name):",
        "    cur.execute(\"select * from users where name = ?\", (name,))",
    ], forbid_rules=["py.sqli.fstring", "py.sqli.concat"],
        note="参数化 SQL **不该**被判成注入 —— 只看「有没有拼」，不看「参数化没」就是误报"),
    Case("neg_py_subprocess_list", "negative", "python", "tool.py", [
        "import subprocess",
        "",
        "def ls(path):",
        "    subprocess.run([\"ls\", \"-l\", path], capture_output=True)",
    ], forbid_rules=["py.rce.subprocess_shell"],
        note="列表传参（无 shell）**不该**直接判命令注入"),
    Case("neg_py_yaml_safe", "negative", "python", "cfg.py", [
        "import yaml",
        "",
        "def load(text):",
        "    return yaml.safe_load(text)",
    ], forbid_rules=["py.deser.yaml_load"],
        note="`safe_load` 与 `load` 差一个字，**必须区分**"),
    Case("neg_js_json", "negative", "javascript", "parse.js", [
        "function parse(body) {",
        "    return JSON.parse(body);",
        "}",
    ], forbid_rules=["js.rce.eval"],
        note="`JSON.parse` 是纯数据解析，**不该**被当代码执行"),
    Case("neg_py_secrets", "negative", "python", "token.py", [
        "import secrets",
        "",
        "def make():",
        "    return secrets.token_urlsafe(32)",
    ], forbid_rules=["py.random.insecure"],
        note="`secrets` 是密码学安全随机，与 `random` **必须区分**"),
    Case("neg_php_prepared", "negative", "php", "db.php", [
        "<?php",
        "$stmt = $pdo->prepare('select * from users where name = ?');",
        "$stmt->execute([$name]);",
    ], forbid_rules=["php.sqli.concat"],
        note="参数化预处理 **不该**被判成注入。"
             "⚠️ 本条**曾经是已知误报**：规则匹配「括号内有 $」，把 `execute([$name])`"
             "（参数化绑定）也算进去了 —— 是本基准第一次跑就抓出来的，"
             "已用 `(?<!\\[)` 排除「$ 紧跟 `[`」这种绑定数组形态。留在这里当回归钉。"),
    Case("neg_php_escaped_echo", "negative", "php", "safe_out.php", [
        "<?php",
        "// 已转义的输出 —— XSS 规则**不该**报它（这是这类规则最容易犯的误报）",
        "echo htmlspecialchars( $name, ENT_QUOTES, 'UTF-8' );",
        "echo '<h1>Hello</h1>';",
    ], forbid_rules=["php.xss.echo_var", "php.xss.superglobal_to_html"],
        note="转义过 / 纯静态的 echo **不该**被判 XSS"),
    Case("neg_php_concat_escaped", "negative", "php", "safe_concat.php", [
        "<?php",
        "// 拼了 HTML 也拼了请求变量，但**经过转义** —— 不该报",
        "$html .= '<pre>' . htmlspecialchars( $_GET['name'] ) . '</pre>';",
    ], forbid_rules=["php.xss.superglobal_to_html"],
        note="同行有转义函数时不该报 —— 行内黑名单就是为它准备的"),
]


# ---------------------------------------------------------------- 跑分

@dataclass
class CaseResult:
    case: Case
    ok: bool
    detail: str
    hits: list[str] = field(default_factory=list)


@dataclass
class Report:
    results: list[CaseResult] = field(default_factory=list)
    known_fp_triggered: list[str] = field(default_factory=list)

    @property
    def positives(self) -> list[CaseResult]:
        return [r for r in self.results if r.case.kind == "positive"]

    @property
    def negatives(self) -> list[CaseResult]:
        return [r for r in self.results if r.case.kind == "negative"]

    def recall(self) -> float:
        p = self.positives
        return (sum(1 for r in p if r.ok) / len(p)) if p else 0.0

    def precision(self) -> float:
        """负样本通过率 —— 只认「没被已知误报豁免」的那些。"""
        n = [r for r in self.negatives if not r.case.known_fp]
        return (sum(1 for r in n if r.ok) / len(n)) if n else 0.0

    def failed(self) -> list[CaseResult]:
        return [r for r in self.results if not r.ok and not r.case.known_fp]

    def render(self) -> str:
        lines = ["=" * 68,
                 "白盒召回基准",
                 "=" * 68,
                 f"  正样本 {len(self.positives)} 个；负样本 {len(self.negatives)} 个"
                 f"（其中 {len([r for r in self.negatives if r.case.known_fp])} 个为已知误报）",
                 f"  召回率   = {self.recall():.0%}",
                 f"  精确性   = {self.precision():.0%}（负样本通过率）"]
        for r in self.results:
            mark = "PASS" if r.ok else ("KNOWN-FP" if r.case.known_fp else "FAIL")
            lines.append(f"  [{mark:>8}] {r.case.id:<24} {r.detail}")
        if self.known_fp_triggered:
            lines.append("")
            lines.append("  ⚠️ 已知误报被触发（**不掩盖、不阻塞**，但要知道它还在）：")
            for cid in self.known_fp_triggered:
                c = next(x for x in self.results if x.case.id == cid).case
                lines.append(f"    · {cid}：{c.known_fp}")
        lines.append("=" * 68)
        return "\n".join(lines)


def _materialize(case: Case, workspace: pathlib.Path) -> pathlib.Path:
    """把内置样本物化成真实文件（工具要的是**目录**）。"""
    d = workspace / case.id
    f = d / case.file
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(case.lines) + "\n", encoding="utf-8")
    return d


def run_case(case: Case, workspace: pathlib.Path) -> CaseResult:
    """跑单个样本。**依赖仓库/受控根/索引目录都落在 workspace 下**（不碰真实数据）。"""
    src = pathlib.Path(case.dir) if case.dir else _materialize(case, workspace)
    store = workspace / "_store"
    with _patched(store, workspace):
        r = G.ingest(src, codebase_id=f"bench-{case.id}")
        I.build(r.codebase_id)
        hits = Q.search_sinks(r.codebase_id, limit=1000)
        got_rules = {h.rule_id for h in hits}
        got_locs = {h.loc for h in hits}
        shown = sorted(got_locs)[:4]

        if case.kind == "positive":
            hit_loc = [l for l in case.expect_loc if l in got_locs]
            hit_rule = [x for x in case.expect_rules if x in got_rules]
            ok = bool(hit_loc or hit_rule)
            detail = (f"命中 {hit_loc or '—'} / {hit_rule or '—'}"
                      if ok else f"**没打到**（期望 {case.expect_loc or case.expect_rules}；"
                                 f"实际命中 {shown}）")
            return CaseResult(case, ok, detail, shown)

        # 负样本：不该命中 forbidden 规则
        bad = sorted(set(case.forbid_rules) & got_rules)
        ok = not bad
        detail = ("未误报 ✓" if ok else f"**误报**：{bad} @ {shown}")
        return CaseResult(case, ok, detail, shown)


class _patched:
    """把 ingest/index 的落盘位置临时改到 workspace 下（**不碰真实 store**）。"""

    def __init__(self, store: pathlib.Path, idx: pathlib.Path):
        self.store, self.idx = store, idx / "_index"
        self._stack = []

    def __enter__(self):
        from unittest import mock
        from . import ingest, index, paths
        self._stack = [
            mock.patch.object(ingest, "CODEBASE_STORE", self.store),
            mock.patch.object(paths, "CODEBASES_FILE", self.store / "codebases.json"),
            mock.patch.object(index, "INDEX_DIR", self.idx),
        ]
        for p in self._stack:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._stack):
            p.stop()
        return False


def evaluate(cases: list[Case] | None = None, workspace: pathlib.Path | None = None) -> Report:
    """跑一遍全部样本，返回报告。"""
    cases = CORPUS if cases is None else cases
    tmp = pathlib.Path(workspace) if workspace else pathlib.Path(
        tempfile.mkdtemp(prefix="recall_"))
    tmp.mkdir(parents=True, exist_ok=True)
    rep = Report()
    for c in cases:
        try:
            rep.results.append(run_case(c, tmp))
        except Exception as e:                                # noqa: BLE001
            rep.results.append(CaseResult(c, False, f"用例执行出错：{type(e).__name__}: {e}"))
    rep.known_fp_triggered = [r.case.id for r in rep.results
                              if r.case.known_fp and not r.ok]
    return rep


def corpus_health() -> list[str]:
    """语料自身的体检：引用的规则是否存在、样本是否自相矛盾。"""
    problems: list[str] = []
    seen: set[str] = set()
    for c in CORPUS:
        if c.id in seen:
            problems.append(f"{c.id}：id 重复")
        seen.add(c.id)
        if c.kind not in ("positive", "negative"):
            problems.append(f"{c.id}：kind 非法（{c.kind}）")
        if not c.lines and not c.dir:
            problems.append(f"{c.id}：既没有内置样本也没有目录")
        if c.lines and not c.file:
            problems.append(f"{c.id}：有内置样本但没写 file（无法物化）")
        for rid in list(c.expect_rules) + list(c.forbid_rules):
            if not _rule_exists(rid):
                problems.append(f"{c.id}：引用了不存在的规则 {rid}（规则改名后会静默失效）")
        if c.kind == "positive" and not (c.expect_loc or c.expect_rules):
            problems.append(f"{c.id}：正样本没有期望答案")
        if c.kind == "negative" and not c.forbid_rules:
            problems.append(f"{c.id}：负样本没有要禁的规则")
    return problems
