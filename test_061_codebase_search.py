# -*- coding: utf-8 -*-
"""v061 代码检索（`app/codebase/search.py` + sink 规则库）的回归测试。

覆盖：sink 命中与规则元数据、过滤、正则检索、**读上下文必经受控根校验**、
委托索引查询、确定性。

    python test_061_codebase_search.py
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.codebase import index as I                        # noqa: E402
from app.codebase import ingest as G                        # noqa: E402
from app.codebase import paths as P                          # noqa: E402
from app.codebase import search as Q                        # noqa: E402
from app.codebase import sink_rules as S                    # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


TMP = pathlib.Path(tempfile.mkdtemp(prefix="v061_search_"))


def write(p: pathlib.Path, lines: list[str]):
    """用行列表写夹具 —— **不经 shell 转义**（上一版被 `\\n` 变 `/n` 坑过）。"""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_repo() -> pathlib.Path:
    d = TMP / "proj"
    write(d / "a.php", [
        "<?php",
        "function handle($u) {",
        "    system($u);",
        "}",
        "$x = unserialize($_GET['d']);",
        "$r = mysql_query('select * from t where a=' . $_GET['a']);",
        "include($_GET['page']);",
        "header('Location: ' . $_GET['next']);",
    ])
    write(d / "B.java", [
        "public class B {",
        "    public void run(String cmd) throws Exception {",
        "        Runtime.getRuntime().exec(cmd);",
        "        ObjectInputStream in = new ObjectInputStream(null);",
        "        in.readObject();",
        "    }",
        "}",
    ])
    write(d / "c.py", [
        "import pickle",
        "import subprocess",
        "",
        "def load(data):",
        "    return pickle.loads(data)",
        "",
        "def run(cmd):",
        "    subprocess.run(cmd, shell=True)",
        "",
        "def q(cur, name):",
        "    cur.execute(f'select * from t where n={name}')",
    ])
    write(d / "d.js", [
        'const cp = require("child_process");',
        "function go(x) {",
        "    eval(x);",
        "    cp.exec(x);",
        "    document.getElementById('a').innerHTML = x;",
        "}",
    ])
    return d


def main() -> int:
    print("=" * 68)
    print("v061 代码检索（sink 规则库 / 正则 / 受控根读上下文）")
    print("=" * 68)
    print(f"  规则库：{S.stats()}")

    repo = make_repo()
    with mock.patch.object(G, "CODEBASE_STORE", TMP / "store"), \
         mock.patch.object(P, "CODEBASES_FILE", TMP / "cb.json"), \
         mock.patch.object(I, "INDEX_DIR", TMP / "idx"):
        r = G.ingest(repo)
        I.build(r.codebase_id)
        cid = r.codebase_id

        print("\n=== ① sink 检索：四种语言都能命中 ===")
        hits = Q.search_sinks(cid)
        by_file = {}
        for h in hits:
            by_file.setdefault(h.file, []).append(h)
        check("PHP 命中（system / unserialize / SQL 拼接 / include / Location 重定向）",
              {h.rule_id for h in by_file.get("a.php", [])} >=
              {"php.rce.shell", "php.deser.unserialize", "php.rce.include", "php.redirect"},
              str(sorted({h.rule_id for h in by_file.get("a.php", [])})))
        check("Java 命中（Runtime.exec / 反序列化）",
              {"java.rce.runtime_exec", "java.deser.objectinput"} <=
              {h.rule_id for h in by_file.get("B.java", [])},
              str(sorted({h.rule_id for h in by_file.get("B.java", [])})))
        check("Python 命中（pickle / subprocess shell=True / SQL f-string）",
              {"py.rce.pickle", "py.rce.subprocess_shell", "py.sqli.fstring"} <=
              {h.rule_id for h in by_file.get("c.py", [])},
              str(sorted({h.rule_id for h in by_file.get("c.py", [])})))
        check("JS 命中（eval / child_process / innerHTML）",
              {"js.rce.eval", "js.rce.child_process", "js.xss.innerhtml"} <=
              {h.rule_id for h in by_file.get("d.js", [])},
              str(sorted({h.rule_id for h in by_file.get("d.js", [])})))

        print("\n=== ② 每条命中都必须能当证据用（§5 P3）===")
        check("都有 `文件:行号`", all(h.loc.count(":") == 1 and h.line > 0 for h in hits))
        check("都带该行原文（模型可直接引用）", all(h.text.strip() for h in hits))
        check("都带 `why`（为什么危险）", all(h.why for h in hits))
        check("都带 `hint`（还要确认什么，防误报）",
              all(h.hint for h in hits), str([h.rule_id for h in hits if not h.hint][:3]))
        check("挤进函数内的命中带 `scope`（判可达性的起点）",
              any("function" in h.scope or "method" in h.scope for h in hits),
              str([(h.loc, h.scope) for h in hits if h.scope][:3]))
        check("Python 命中标 ast、其余标 lexical（如实标注精度）",
              all((h.extractor == "ast") == (h.lang == "python") for h in hits))

        print("\n=== ③ 过滤 ===")
        only_rce = Q.search_sinks(cid, kinds=["rce"])
        check("按 kind 过滤（只要 rce）", all(h.kind == "rce" for h in only_rce) and only_rce)
        only_php = Q.search_sinks(cid, langs=["php"])
        check("按语言过滤（只要 php）", all(h.lang == "php" for h in only_php) and only_php)
        check("kind + lang 组合",
              all(h.kind == "deserialization" for h in
                  Q.search_sinks(cid, kinds=["deserialization"], langs=["python"])))
        check("上限生效", len(Q.search_sinks(cid, limit=3)) == 3)

        print("\n=== ④ 正则检索 ===")
        rx = Q.search_regex(cid, r"eval|exec")
        check("按正则命中", len(rx) > 0 and all(h.kind == "regex" for h in rx))
        bad = Q.search_regex(cid, "a[b")
        check("非法正则**退化为字面量匹配**（不把工具打挂）",
              isinstance(bad, list) and all("按字面量匹配" in h.why for h in bad),
              str([h.why[:40] for h in bad[:1]]))
        check("忽略大小写可关", isinstance(Q.search_regex(cid, "EVAL", ignore_case=False), list))

        print("\n=== ⑤ 读上下文：**路径必经受控根校验**（本能力的安全命门）===")
        ctx = Q.read_context(cid, "a.php", 3, before=2, after=1)
        check("根内路径能读，且带行号前缀", "3 | " in ctx["text"] and ctx["file"] == "a.php")
        check("标记为不可信数据（§9 提示注入）", ctx.get("untrusted") is True)
        check("带 scope", isinstance(ctx["scope"], str))
        for label, rel in [
            ("`..` 逃逸", "../../../config.yaml"),
            ("绝对路径在根外", str(pathlib.Path(ROOT) / "README.md")),
            ("项目敏感文件", str(ROOT / "data" / "scope.json")),
        ]:
            try:
                Q.read_context(cid, rel, 1)
                check(f"读上下文拒绝：{label}", False, "竟然放行")
            except P.PathEscapeError:
                check(f"读上下文拒绝：{label}", True)
        check("行号非法 → 拒绝",
              _raises(ValueError, lambda: Q.read_context(cid, "a.php", 0)))
        check("上下文行数超大 → 拒绝",
              _raises(ValueError, lambda: Q.read_context(cid, "a.php", 1, 300, 300)))

        print("\n=== ⑥ 委托索引的查询 ===")
        syms = Q.search_symbols(cid, "run")
        check("按名查符号", any(s.name == "run" for s in syms), str([s.name for s in syms]))
        check("按 kind 查", all(s.kind == "class" for s in Q.search_symbols(cid, "", kind="class")))
        check("按内容查字符串", isinstance(Q.search_strings(cid, "select"), list))
        with mock.patch.object(I, "INDEX_DIR", TMP / "no_index_dir"):
            check("无索引时明确提示先跑 code_index",
                  _raises(P.CodebaseNotFound, lambda: Q.search_symbols(cid, "x")))

        print("\n=== ⑦ 确定性与边界 ===")
        h1 = [(x.file, x.line, x.rule_id) for x in Q.search_sinks(cid)]
        h2 = [(x.file, x.line, x.rule_id) for x in Q.search_sinks(cid)]
        check("两次检索结果完全一致（可回归）", h1 == h2)
        check("未入库 codebase → 抛 CodebaseNotFound",
              _raises(P.CodebaseNotFound, lambda: Q.search_sinks("no-such")))
        check("命中按 (文件, 行号, 规则) 稳定排序", h1 == sorted(h1))

    print("\n=== ⑧ 规则库自身的完整性（规则会不断加，需要护栏）===")
    ids = [r.id for r in S.ALL]
    check("规则 id 唯一（重复会让报告无法定位是哪条）",
          len(ids) == len(set(ids)), str([i for i in set(ids) if ids.count(i) > 1]))
    bad_rx = []
    for r in S.ALL:
        try:
            r.regex()
        except Exception as e:                               # noqa: BLE001
            bad_rx.append((r.id, str(e)[:40]))
    check("每条规则的正则都能编译", not bad_rx, str(bad_rx))
    check("每条规则都有 `why`（否则命中无法解释为什么危险）",
          all(r.why.strip() for r in S.ALL))
    check("每条规则都有 `hint`（否则模型容易把命中当结论）",
          all(r.hint.strip() for r in S.ALL),
          str([r.id for r in S.ALL if not r.hint.strip()]))
    check("规则的语言标注合法（四种 + 通配）",
          all(r.lang in ("php", "java", "python", "javascript", "*") for r in S.ALL),
          str(sorted({r.lang for r in S.ALL})))
    check("四种语言都有规则（首批范围，决策②）",
          all(S.rules_for(l) for l in ("php", "java", "python", "javascript")))
    check("通配规则对每种语言都生效",
          all(any(r.lang == "*" for r in S.rules_for(l))
              for l in ("php", "java", "python", "javascript")))
    check("by_id 能取回规则", S.by_id(ids[0]) is not None and S.by_id("no-such") is None)
    check("规则库统计可用", S.stats()["total"] == len(S.ALL) > 40, str(S.stats()["total"]))

    shutil.rmtree(TMP, ignore_errors=True)
    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


def _raises(exc, fn) -> bool:
    try:
        fn()
        return False
    except exc:
        return True


if __name__ == "__main__":
    sys.exit(main())
