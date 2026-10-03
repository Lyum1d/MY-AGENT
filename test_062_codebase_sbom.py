# -*- coding: utf-8 -*-
"""v062 依赖清单解析（`app/codebase/sbom.py`）的回归测试。

覆盖四种生态（composer / maven / pip / npm）+ lock 文件的「实际版本」语义 +
线索判定 + **解析失败不静默**。

    python test_062_codebase_sbom.py
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.codebase import ingest as G                        # noqa: E402
from app.codebase import paths as P                          # noqa: E402
from app.codebase import sbom as B                           # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


TMP = pathlib.Path(tempfile.mkdtemp(prefix="v062_sbom_"))


def write(p: pathlib.Path, lines: list[str]):
    """行列表拼 —— **不经 shell 转义**（v060 那次 `\\n` 被改成 `/n` 的教训）。"""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_repo() -> pathlib.Path:
    d = TMP / "proj"
    write(d / "composer.json", [
        '{',
        '  "require": {',
        '    "php": ">=8.0",',
        '    "ext-json": "*",',
        '    "monolog/monolog": "^2.0",',
        '    "guzzlehttp/guzzle": "http://packages.example.test/guzzle.zip"',
        '  },',
        '  "require-dev": { "phpunit/phpunit": "^9.0" }',
        '}',
    ])
    write(d / "composer.lock", [
        '{',
        '  "packages": [ {"name": "monolog/monolog", "version": "2.9.1"} ],',
        '  "packages-dev": [ {"name": "phpunit/phpunit", "version": "9.6.0"} ]',
        '}',
    ])
    write(d / "pom.xml", [
        '<project>',
        '  <properties><spring.version>5.3.20</spring.version></properties>',
        '  <parent>',
        '    <groupId>org.springframework.boot</groupId>',
        '    <artifactId>spring-boot-starter-parent</artifactId>',
        '    <version>2.7.0</version>',
        '  </parent>',
        '  <dependencies>',
        '    <dependency>',
        '      <groupId>org.springframework</groupId>',
        '      <artifactId>spring-core</artifactId>',
        '      <version>${spring.version}</version>',
        '    </dependency>',
        '    <dependency>',
        '      <groupId>com.example</groupId>',
        '      <artifactId>unknown-lib</artifactId>',
        '      <version>${not.defined}</version>',
        '    </dependency>',
        '    <dependency>',
        '      <groupId>com.alibaba</groupId>',
        '      <artifactId>fastjson</artifactId>',
        '      <version>1.2.24</version>',
        '    </dependency>',
        '  </dependencies>',
        '</project>',
    ])
    write(d / "requirements.txt", [
        "# 注释",
        "requests==2.28.1",
        "urllib3>=1.26",
        "reqeusts==1.0.0",
        "-r other.txt",
        "--index-url https://pypi.example.test/simple",
        "",
    ])
    write(d / "package.json", [
        '{',
        '  "dependencies": { "express": "^4.18.0", "lodahs": "1.0.0" },',
        '  "devDependencies": { "jest": "latest", "someonlycli": "latest" }',
        '}',
    ])
    write(d / "package-lock.json", [
        '{',
        '  "packages": {',
        '    "": {"name": "app"},',
        '    "node_modules/express": {"version": "4.18.2"},',
        '    "node_modules/jest": {"version": "29.5.0", "dev": true}',
        '  }',
        '}',
    ])
    write(d / "pyproject.toml", [
        "[project]",
        'name = "demo"',
        'dependencies = ["flask>=3.0", "pyyaml==6.0.1"]',
        "",
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        'cryptography = "^41.0"',
    ])
    # 不支持的清单：必须被**显式记下**，不能当作「没有依赖」
    write(d / "yarn.lock", ["# yarn lockfile v1", 'express@^4.18.0:', '  version "4.18.2"'])
    # 坏 JSON：必须进 parse_errors
    write(d / "broken/package.json", ["{ 这不是 json"])
    return d


def main() -> int:
    print("=" * 68)
    print("v062 依赖清单解析（composer / maven / pip / npm）")
    print("=" * 68)

    repo = make_repo()
    with mock.patch.object(G, "CODEBASE_STORE", TMP / "store"), \
         mock.patch.object(P, "CODEBASES_FILE", TMP / "cb.json"):
        r = G.ingest(repo)
        sb = B.build(r.codebase_id)

        print("\n=== ① 四种生态都能解析 ===")
        eco = sb.by_ecosystem()
        check("composer 解析到依赖", eco.get("composer", 0) >= 3, str(eco))
        check("maven 解析到依赖", eco.get("maven", 0) >= 4, str(eco))
        check("pip 解析到依赖", eco.get("pip", 0) >= 5, str(eco))
        check("npm 解析到依赖", eco.get("npm", 0) >= 3, str(eco))
        check("清单文件都被记录", len(sb.files) >= 6, str(sb.files))

        print("\n=== ② 「约束」与「实际版本」必须分开（判断 CVE 影响只能用实际版本）===")
        lock = sb.find("monolog/monolog")[0]
        check("lock 里的条目标 resolved=True（实际装入版本）",
              lock.resolved and lock.version == "2.9.1", lock.render())
        json_dep = sb.find("guzzlehttp/guzzle")[0]
        check("composer.json 里的约束标 resolved=False",
              not json_dep.resolved and "^2.0" not in json_dep.version, json_dep.render())
        check("同一包 lock 与 json 都有时，**留 lock 那条**",
              sb.find("monolog/monolog")[0].version == "2.9.1")
        req = sb.find("requests")[0]
        check("pip 的 `==` 固定版本标 resolved=True",
              req.resolved and req.version == "==2.28.1", req.render())
        loose = sb.find("urllib3")[0]
        check("`>=` 这种宽约束标 resolved=False（不是实际版本）",
              not loose.resolved, loose.render())
        npm_lock = sb.find("express")[0]
        check("package-lock 里的版本标 resolved=True 且优先于 package.json 的 ^4.18.0",
              npm_lock.resolved and npm_lock.version == "4.18.2", npm_lock.render())

        print("\n=== ③ Maven：属性解析与未解析占位符 ===")
        spring = [d for d in sb.deps if "spring-core" in d.name][0]
        check("`${spring.version}` 被 properties 解析成实际值",
              spring.version == "5.3.20", spring.render())
        unknown = [d for d in sb.deps if "unknown-lib" in d.name][0]
        check("解析不出的占位符**保留原样并标出线索**（不当成版本号）",
              "${not.defined}" in unknown.version and unknown.clues,
              unknown.render())
        parent = [d for d in sb.deps if d.scope == "parent"]
        check("父 POM 也记一条（它决定继承来的版本）",
              parent and "spring-boot-starter-parent" in parent[0].name)
        check("平台约束（php / ext-*）不算依赖包",
              not any(d.name in ("php", "ext-json") for d in sb.deps))

        print("\n=== ④ 线索（**是线索不是结论**）===")
        clues = {d.name: d.clues for d in sb.clues()}
        check("明文 http 源被标记",
              any("明文 http" in " ".join(v) for v in clues.values()),
              str([k for k, v in clues.items() if any("http" in x for x in v)]))
        # ⚠️ jest 在 package.json 里是 `latest`，但 lock 里有实际版本 29.5.0
        # → 合并时优先留 lock 那条，所以**不该**再报「未声明版本约束」。
        # 这正是「约束 vs 实际版本」这条设计的自然结果，不是漏报。
        check("有 lock 覆盖时，`latest` 不再是线索（实际版本已知）",
              "jest" not in clues, str(clues.get("jest")))
        check("**没有** lock 覆盖时，`latest` 被标记为未声明版本约束",
              "未声明版本约束" in " ".join(clues.get("someonlycli", [])),
              str(clues.get("someonlycli")))
        check("仿冒名被标记（`lodahs` vs `lodash` / `reqeusts` vs `requests` —— **相邻调换**）",
              "lodahs" in clues and "reqeusts" in clues,
              str([k for k in clues if k in ("lodahs", "reqeusts")]))
        check("**正常包不被误标**（express / flask / monolog 不应有线索）",
              not any(k in clues for k in ("express", "flask", "monolog/monolog")),
              str([k for k in clues if k in ("express", "flask", "monolog/monolog")]))
        check("clues() 返回的是依赖对象而非字符串",
              all(isinstance(d, B.Dep) for d in sb.clues()))

        print("\n=== ⑤ 解析失败/未支持**不能静默跳过** ===")
        check("坏 JSON 进 parse_errors（不静默吞掉）",
              any("broken/package.json" in e for e in sb.parse_errors), str(sb.parse_errors))
        check("yarn.lock 被显式记为未解析（而不是当作没有依赖）",
              any("yarn.lock" in u for u in sb.unparsed), str(sb.unparsed))
        check("stats 里能看到未解析与错误数", sb.stats()["unparsed"] >= 1
              and sb.stats()["parse_errors"] >= 1, str(sb.stats()))

        print("\n=== ⑥ 其它 ===")
        check("按名查找", len(sb.find("fastjson")) == 1 and sb.find("fastjson")[0].version == "1.2.24")
        check("requirements.txt 的选项行（-r / --index-url）不被当成包",
              not any(d.name in ("-r", "--index-url") for d in sb.deps))
        check("requirements 行号可用（便于引用证据）",
              sb.find("requests")[0].line > 0, str(sb.find("requests")[0].line))
        a = [d.render() for d in B.build(r.codebase_id).deps]
        b = [d.render() for d in B.build(r.codebase_id).deps]
        check("两次构建结果一致（确定性）", a == b)
        check("未入库 codebase → 抛 CodebaseNotFound",
              _raises(P.CodebaseNotFound, lambda: B.build("no-such")))
        check("依赖按 (生态, 名字) 稳定排序",
              [(d.ecosystem, d.name.lower()) for d in sb.deps]
              == sorted((d.ecosystem, d.name.lower()) for d in sb.deps))

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
