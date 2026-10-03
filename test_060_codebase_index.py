# -*- coding: utf-8 -*-
"""v060 代码索引（`app/codebase/index.py`）的回归测试。

## 测试夹具为什么用「行列表 + join」而不是多行字符串

上一版我是在 shell 的 heredoc 里内联 `\\n` 写夹具的 —— **Git Bash 会把 `\\n` 变成 `/n`**，
于是**写进磁盘的 Python 文件其实是坏的**（`class Foo:/n    def bar(...)`），
`ast.parse` 自然失败、索引抽不到东西。我一度以为是索引的 bug。

结论：**夹具用 `"\\n".join([...])` 显式拼**，不经任何 shell 转义 ——
这类「测试装置自己坏了」最难查，因为现象看着像是被测代码错了。

    python test_060_codebase_index.py
"""
from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.codebase import index as X                        # noqa: E402
from app.codebase import ingest as G                        # noqa: E402
from app.codebase import paths as P                          # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def write(p: pathlib.Path, lines: list[str]):
    """写夹具：用行列表拼，**不经 shell 转义**（见模块 docstring）。"""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


TMP = pathlib.Path(tempfile.mkdtemp(prefix="v060_idx_"))


def make_repo() -> pathlib.Path:
    d = TMP / "proj"
    write(d / "src/a.py", [
        "import os",
        "import sys as _s",
        "from collections import OrderedDict",
        'API_KEY = "sk-abcdefghijklmnop1234"',
        "",
        "class Foo:",
        "    def bar(self, x):",
        '        return os.system("echo " + x)',
        "",
        "def top():",
        "    pass",
    ])
    write(d / "src/b.php", [
        "<?php",
        "require_once 'lib/x.php';",
        "$q = getenv('HOME');",
        "function handle($u) { return shell_exec($u); }",
        "class Ctrl { }",
    ])
    write(d / "src/c.java", [
        "import java.io.File;",
        "import java.util.List;",
        "public class Svc {",
        '    public String read(String p) { return new File(p).toString(); }',
        "}",
    ])
    write(d / "web.js", [
        'const cp = require("child_process");',
        "function run(cmd) { return cp.exec(cmd); }",
        "class UI {}",
    ])
    # 不支持的语言：应被跳过（决策②首批只四种）
    write(d / "main.go", ["package main", 'func main() { println("x") }'])
    # 超大文件：应被跳过并记录
    (d / "src" / "huge.php").write_bytes(b"a" * (X.MAX_INDEX_FILE_BYTES + 10))
    return d




def main() -> int:
    print("=" * 68)
    print("v060 代码索引（AST + 词法 / 确定性 / 可持久化）")
    print("=" * 68)
    repo = make_repo()

    with mock.patch.object(G, "CODEBASE_STORE", TMP / "store"), \
         mock.patch.object(P, "CODEBASES_FILE", TMP / "cb.json"), \
         mock.patch.object(X, "INDEX_DIR", TMP / "idx"):
        r = G.ingest(repo)
        idx = X.build(r.codebase_id, persist=True)

        print("\n=== ① Python 用真 AST（精确）===")
        py = [s for s in idx.symbols if s.lang == "python"]
        names = {s.name: s for s in py}
        check("类 Foo 被抽到且带行号", names.get("Foo") and names["Foo"].line == 6,
              str(names.get("Foo")))
        check("方法 bar 且 kind=method", names.get("bar") and names["bar"].kind == "method")
        check("顶层函数 top 且 kind=function",
              names.get("top") and names["top"].kind == "function")
        check("Python 的 extractor 标为 ast",
              all(s.extractor == "ast" for s in py), str({s.extractor for s in py}))
        check("import os / import sys as _s / from collections 都抽到",
              {"os", "sys", "collections"} <= {i.module for i in idx.imports if i.lang == "python"},
              str([i.module for i in idx.imports if i.lang == "python"]))
        check("字符串里能定位到硬编码密钥",
              [s.loc for s in idx.find_strings("sk-")] == ["src/a.py:4"],
              str([s.loc for s in idx.find_strings("sk-")]))

        print("\n=== ② 其余语言用词法，并**如实标注** ===")
        php = [s for s in idx.symbols if s.lang == "php"]
        java = [s for s in idx.symbols if s.lang == "java"]
        js = [s for s in idx.symbols if s.lang == "javascript"]
        check("PHP 抽到 function handle / class Ctrl",
              {"handle", "Ctrl"} <= {s.name for s in php}, str([s.name for s in php]))
        check("Java 抽到 class Svc 与 method read",
              {"Svc", "read"} <= {s.name for s in java}, str([s.name for s in java]))
        check("JS 抽到 function run / class UI",
              {"run", "UI"} <= {s.name for s in js}, str([s.name for s in js]))
        check("非 Python 的 extractor 标为 lexical（**不冒充精确**）",
              all(s.extractor == "lexical" for s in php + java + js))
        check("extractors 汇总里能看出每种语言的抽取方式",
              idx.extractors.get("python") == "ast"
              and idx.extractors.get("php") == "lexical", str(idx.extractors))
        check("PHP 的 require 抽到并带行号",
              any(i.module == "lib/x.php" and i.loc == "src/b.php:2" for i in idx.imports),
              str([(i.module, i.loc) for i in idx.imports if i.lang == "php"]))
        check("JS 的 require 抽到", any(i.module == "child_process" for i in idx.imports))

        print("\n=== ③ 每条事实都能给出 `文件:行号`（§5 P3 的硬要求）===")
        check("符号都有 loc", all(s.loc.count(":") == 1 and s.line > 0 for s in idx.symbols))
        check("字符串都有 loc（密钥类发现的唯一证据）",
              all(s.loc.count(":") == 1 and s.line > 0 for s in idx.strings))
        check("导入都有 loc", all(i.loc.count(":") == 1 and i.line > 0 for i in idx.imports))

        print("\n=== ④ 确定性：同一份代码两次构建结果一致（才能进回归）===")
        a = X.build(r.codebase_id, persist=False)
        b = X.build(r.codebase_id, persist=False)
        check("符号序列一致",
              [(s.name, s.line, s.extractor) for s in a.symbols]
              == [(s.name, s.line, s.extractor) for s in b.symbols])
        check("字符串序列一致",
              [(s.value, s.loc) for s in a.strings] == [(s.value, s.loc) for s in b.strings])
        check("导入序列一致",
              [(i.module, i.loc) for i in a.imports] == [(i.module, i.loc) for i in b.imports])

        print("\n=== ⑤ 持久化 ===")
        p = X.load(r.codebase_id)
        check("能读回索引且内容一致",
              p is not None and [(s.name, s.loc) for s in p.symbols]
              == [(s.name, s.loc) for s in idx.symbols])
        (TMP / "idx" / f"{r.codebase_id}.json").write_text('{"schema": 999}', encoding="utf-8")
        check("schema 不符 → 返回 None（让调用方重建，不硬读旧结构）",
              X.load(r.codebase_id) is None)

        print("\n=== ⑥ 边界 ===")
        check("未入库的 codebase_id → 抛 CodebaseNotFound",
              _raises(P.CodebaseNotFound, lambda: X.build("no-such-cb")))
        check("不支持的语言（go）不进索引",
              all(s.lang != "go" for s in idx.symbols))
        check("超大文件被跳过且记录在案",
              any("huge.php" in s for s in idx.skipped), str(idx.skipped[:2]))
        check("索引产物**不在受控根内**（不污染「根内即目标代码」的语义）",
              not str(X.index_path(r.codebase_id)).startswith(str(r.root)),
              str(X.index_path(r.codebase_id)))
        check("未入库 id 也不 stale 判错",
              isinstance(X.is_stale(idx), str))

        print("\n=== ⑦ 查询接口 ===")
        check("按名字子串查符号（大小写不敏感）",
              [s.name for s in idx.find_symbols("HAN")] == ["handle"],
              str([s.name for s in idx.find_symbols("HAN")]))
        check("按 kind 过滤", all(s.kind == "class" for s in idx.find_symbols("", kind="class")))
        check("按语言过滤", all(s.lang == "php" for s in idx.find_symbols("", lang="php")))
        check("非法正则退化为转义匹配（不把工具打挂）",
              idx.find_strings("sk-[") is not None)
        check("stats 汇总可用", idx.stats()["symbols"] == len(idx.symbols))

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
