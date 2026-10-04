# -*- coding: utf-8 -*-
"""函数内轻量污染分析（v069）。

## 为什么需要它

`sink_rules` 的正则只在**单行**上匹配。这在一种很常见（而且很自然）的写法上**结构必漏**：

    String sql = "{call " + param + "}";              // ← 拼接在这一行
    CallableStatement st = connection.prepareCall(sql);  // ← sink 在下一行，括号里只有变量名

规则要求「`prepareCall(...)` 括号内有 `+`」，而这里括号内只有 `sql` —— **不是规则写松了就能修的**：
把 `+` 去掉改成「括号里有变量名就算」，会让整个仓库疯狂误报。

实测证据（OWASP BenchmarkJava v1.2，官方 ground truth）：
`sqi` 类别 **272 个真漏洞命中 0**；`cmdi` 126 → 命中 8；`pathtraver` 133 → 命中 2。
三个类别**同一个根因**（先拼变量、再传变量）。

## 这一层做什么、不做什么

**做**：在**同一个函数体内**、**严格按源码顺序**，推出「哪些局部变量是污点」。

- 污点起点（**必须显式含外部输入**）：
  - 语言级超级全局：`$_GET`/`$_POST`/`$_REQUEST`/`req.getParameter`/`request.getHeader` …
  - 已知的「取值 API」形态：`getHeader(`/`getParameter(`/`getQueryString(`/`getCookies(` …
- 污点传播：`x = <表达式>` 且该表达式含 `+` 拼接、且含**污点变量或污点起点** → `x` 变污点。
  - **传递闭包按行向下**（第 N 行的赋值只影响 N 行之后），保证确定性、可回归。
- 污点清除：`x = <不含任何污点成分的表达式>` → `x` 从污点集合移除（**覆盖即净化**）。

**不做**（有意为之，写在这里防止后人误以为漏了）：

- **不做跨函数**：不追参数进入被调函数、不追返回值。那需要真正的 AST/调用图，
  且**跨文件链路本就是判定层（模型）的活**（与 §4.1 分工一致）。
- **不做净化识别**：`htmlspecialchars` / `prepareStatement("...?")` 这类**不在这里判**——
  正则判不准「净化是否用对」。这里只回答「**这个变量是否由外部输入拼成**」，
  **是否真的可利用仍然要靠模型读上下文**（与「sink 命中≠漏洞」同一条纪律）。
- **不做别名/数组/字段传播**：`a.b` / `arr[i]` 只按字面变量名跟踪。

## v071 追加：**命令执行器变量**（`runners`）

除了「污点」，本层还顺带跟踪**另一类正交的信息**：哪些变量持有**命令执行器**。

    Runtime r = Runtime.getRuntime();     // ← r 不是「污点」（不含用户输入）
    Process p = r.exec(cmd + bar);        // ← 但 r 是执行器，这行就是命令执行 sink

**为什么必须单独跟踪**：`sink_rules` 的 `_CMD_CALL` 只认字面量
`Runtime.getRuntime().exec(`。实测 OWASP Benchmark 的 cmdi 真漏洞里
**35 个中 27 个**写成「先存变量、再 `r.exec(...)`」—— 那 27 个**一个都打不中**。

**为什么不直接把正则放宽成 `.exec(`**：那会裸奔（`.exec(` 会吃到一切同名方法）。
v069 已用「删掉宽口径 `.load(`」证明过这条教训。正确做法是**在变量层面判类型**，
而不是在方法名层面放宽。

**与污点的关系**：两者**正交且互相独立**——
`r` 是执行器但不是污点；`param` 是污点但不是执行器。
所以它们是 `TaintResult` 上**两个独立的字段**，不是一个合并的集合。
合并会让「这个变量脏不脏」和「这个变量能不能执行命令」互相污染。

## 输出是**候选**，不是漏洞

本层只把「原来打不中的形态」提升为**可被规则命中的候选**。命中之后该验证什么，
仍然由规则的 `hint` 引导（与既有 sink 命中完全同一条链路）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: 语言级「外部输入起点」形态（**只要出现就视为外部输入**）
#
# ⚠️ 扩充依据来自 OWASP Benchmark 实测：真实项目里「取值」的写法很分散，
# 只认 `request.getParameter` 会漏掉 `cookie.getValue()` / 枚举器 `.nextElement()`
# 这类**间接取值**——实测 BenchmarkTest00002 就卡在
# `param = URLDecoder.decode(theCookie.getValue(), "UTF-8")` 上（param 没被判污点，
# 导致下游 `new FileOutputStream(fileName)` 一个都命中不了）。
#
# ⚠️ **刻意不收**（它们是元数据/框架对象，不是用户可控值，收了会大面积误报）：
# `getSession` / `getRequestURI` / `getRequestURL` / `getRequestDispatcher` / `getHeaderNames`。
SOURCE_PATTERNS: dict[str, str] = {
    "php": r"\$_+(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b",
    "java": (r"\b(?:request|req)\s*\.\s*get(?:Parameter|ParameterValues|ParameterMap"
             r"|Header|Headers|QueryString|Cookies|InputStream|Reader)\b"
             r"|\bget(?:Parameter|ParameterValues|Header|Headers|QueryString|Cookies)\s*\("
             r"|\b\w*[Cc]ookie\w*\s*\.\s*getValue\s*\("
             r"|\b\w*(?:headers|params|names|cookies)\w*\s*\.\s*next(?:Element|Token)\s*\("),
    "javascript": (r"\b(?:req|request)\s*\.\s*(?:query|body|params|cookies|headers)\b"
                   r"|\bprocess\s*\.\s*argv\b"),
    "python": (r"\brequest\s*\.\s*(?:args|form|values|json|data|cookies|headers|GET|POST)\b"
               r"|\b(?:input|raw_input)\s*\("),
}

#: 通用的「取值 API」形态（跨语言，独立于框架）
SOURCE_GENERIC = r"\b(?:getHeader|getHeaders|getParameter|getParameterValues|getQueryString|getCookies|nextElement)\s*\("

#: 变量名的**词法**：PHP 一律带 `$` 前缀（`$param`），Java/JS/Python 不带（`param`）。
#: ⚠️ v069 实测踩到：早期这里只写 `[A-Za-z_]\w*`，**不允许 `$`**，
#: 于是 `$x = $_GET["a"]` 的左值抠不出来 → **PHP 的污点链一条都没工作过**。
#: 两种形态都收，靠 `_STOPWORDS` 与「必须带 `$` 或必须是纯标识符」两条约束控制噪音。
_IDENT_BODY = r"\$?[A-Za-z_]\w*"

#: 赋值语句：`<左值> = <右值>;`。左值只取简单标识符/带类型声明（不做复杂解析）。
#: **两个捕获组**：① 左值 ② 右值。
_ASSIGN = re.compile(
    r"^\s*("
    r"\$?[A-Za-z_][\w.]*"                                     # 变量名（PHP 可带 `$`）
    r"|(?:var|let|const)\s+\$?[A-Za-z_]\w*"                    # var/let/const 声明
    r"|(?:final\s+)?[A-Za-z_][\w<>\[\],\s]*?\s+\$?[A-Za-z_]\w*"  # 带类型声明
    r")"
    r"\s*=\s*(?!=)(.+?);?\s*$"
)

#: 从赋值左值里抠出**变量名**
_LHS_NAME = re.compile(
    r"(?:^|\s)(\$?[A-Za-z_]\w*)\s*$|(\$?[A-Za-z_]\w*)\s*(?:\.\w+|\s*\[[^\]]*\])*\s*$"
)

#: 从右值里抠出**出现的标识符**（用于判断它是否含污点变量）。
#: 左侧用 `(?<![A-Za-z0-9_])` 而非 `\b` —— 因为 `$` 前缀会让 `\b` 在 `$param` 上失效
#: （`$` 非 word 字符，`\bparam` 能匹配到 `param`，但我们要连 `$` 一起抠出来统一处理）。
_IDENT = re.compile(rf"(?<![A-Za-z0-9_])(\$?[A-Za-z_]\w*)")

#: 「命令执行器」的右值形态（v071）—— 赋值给变量后，该变量可以 `.exec(...)`。
#:
#: ## 为什么需要单独跟踪这一类
#:
#: v069 的 `_CMD_CALL` 只认字面量 `Runtime.getRuntime().exec(`。但真实 Java 代码
#: 几乎一律先存变量。**实测 OWASP Benchmark：cmdi 真漏洞 35 个里 27 个是这种写法**
#: （`Runtime r = Runtime.getRuntime(); Process p = r.exec(...)`），
#: 那 27 个**一个都打不中** —— 这是比「跨行污染」更彻底的结构性漏报。
#:
#: ## 为什么不直接把规则放宽成 `.exec(`
#:
#: 因为那会**裸奔**：`.exec(` 会匹配到 `ProcessBuilder.exec` 之外的一切同名方法
#: （各类框架、测试库都有 `exec`）—— v069 已用「删除宽口径 `.load(`」证明过这条教训：
#: **宁可用精确的白名单形态，也不要一个看起来很能打的宽正则**。
#: 所以做法是：**在变量层面判类型**（这个变量是不是从 `Runtime.getRuntime()` 来的），
#: 而不是在方法名层面放宽。
#:
#: 收集范围（刻意保守，只收真的能执行命令的）：
#:   - `Runtime.getRuntime()`
#:   - `new ProcessBuilder(...)` / `ProcessBuilder` 的静态工厂
#: 不收 `ProcessBuilder` 实例**经 `.command()` 后**的形态 —— 那属于容器间接污染，
#: 是有意留到后续版本、且需要突破「不做数组/字段传播」边界的独立议题。
_RUNNER_RHS = re.compile(
    r"(?:\bRuntime\s*\.\s*getRuntime\s*\(\s*\))"
    r"|(?:\bnew\s+(?:[\w.]+\.)?ProcessBuilder\s*\()"
)


def _norm(name: str) -> str:
    """变量名归一：**去掉 PHP 的 `$` 前缀**。

    `$param` / `param` 在集合比较时必须是同一个键，否则
    「左值抠出 `param`、右值抠出 `$param`」会永远对不上，污点传不下去。
    """
    return name.lstrip("$")

#: 常见的类型/关键字，避免被当成变量名（减少噪音）
_STOPWORDS = frozenset({
    "new", "return", "true", "false", "null", "None", "this", "super", "String",
    "int", "long", "byte", "char", "boolean", "double", "float", "void", "var",
    "let", "const", "final", "public", "private", "protected", "static",
})


@dataclass
class TaintResult:
    """一次函数级分析的结果。"""
    tainted: dict[int, set[str]] = field(default_factory=dict)
    """行号 → 该行**之后**处于污点状态的变量集合（含该行赋值产生的）。"""

    runners: dict[int, set[str]] = field(default_factory=dict)
    """行号 → 该行之后持有**命令执行器**的变量集合（v071）。

    `Runtime r = Runtime.getRuntime();` → 从这一行起 `r` 是执行器。
    用途见 `_RUNNER_RHS` 的说明：让 `.exec(` 的**调用者变量**能判出来。
    """

    def at(self, line: int) -> set[str]:
        """取「第 line 行被处理完时」的污点集合（供 sink 匹配时查）。"""
        return self.tainted.get(line, set())

    def runners_at(self, line: int) -> set[str]:
        """取「第 line 行被处理完时」的命令执行器变量集合。"""
        return self.runners.get(line, set())


def _lhs_name(lhs: str) -> str:
    """从赋值左值里取变量名：`String sql` → `sql`，`argList` → `argList`，`$x` → `x`。"""
    s = lhs.strip()
    # 去掉修饰符与类型
    s = re.sub(r"^(?:final|var|let|const)\s+", "", s)
    m = re.match(r"^[A-Za-z_<>\[\],\s]*?(\$?[A-Za-z_]\w*(?:\s*\.\s*\w+|\s*\[[^\]]*\])*)\s*$", s)
    return _norm(m.group(1).replace(" ", "")) if m else ""


def _is_source(lang: str, expr: str) -> bool:
    """表达式里是否含**外部输入起点**。"""
    pat = SOURCE_PATTERNS.get(lang)
    if pat and re.search(pat, expr):
        return True
    return bool(re.search(SOURCE_GENERIC, expr))


def _names(expr: str) -> set[str]:
    """表达式里出现的标识符集合（去掉常见关键字，`$` 前缀归一掉）。"""
    return {_norm(n) for n in _IDENT.findall(expr)
            if n not in _STOPWORDS and _norm(n) not in _STOPWORDS}


def analyze(lines: list[str], lang: str) -> TaintResult:
    """按**源码顺序**做函数外层的污点传播（调用方自己切分函数边界）。

    ⚠️ 这里刻意**不解析函数边界** —— 由调用方按 `scope` 切好再喂进来。
    传入的应当是**单个函数体的行**（或整个文件，此时污染可能跨函数泄漏，
    但因为要求显式含外部输入、且赋值覆盖即清除，实际影响很小）。
    """
    res = TaintResult()
    cur: set[str] = set()
    runners: set[str] = set()
    for i, line in enumerate(lines, 1):
        m = _ASSIGN.match(line)
        if m:
            lhs_raw, rhs = m.group(1), m.group(2)
            name = _lhs_name(lhs_raw)
            if name:
                rhs_has_source = _is_source(lang, rhs)
                rhs_names = _names(rhs)
                rhs_has_taint = bool(rhs_names & cur)
                # ⚠️ 判据顺序是踩出来的：
                # ① 右值含外部输入起点 → 污点（`param = request.getHeader(...)`）；
                # ② 右值含**已有污点变量** → 污点，**不论有没有 `+`** ——
                #    因为 `param = URLDecoder.decode(param, "UTF-8")` 这类是**传递**不是净化
                #    （早先写成「必须有拼接才算」，结果这一行把 param 从污点集里清掉了，
                #    下游 sink 一个都命不中 —— 修 Benchmark 时当场抓到的）；
                # ③ 其余 → **覆盖即净化**。
                if rhs_has_source or rhs_has_taint:
                    cur = cur | {name}
                else:
                    # 不含任何污点成分 → **覆盖即净化**（`param = "safe"`；
                    # 纯常量拼接 `"a" + "b"` 也走这里，同样安全）
                    cur = cur - {name}

                # ---- 命令执行器变量（v071）：与污点是**正交**的两件事 ----
                # 同一条赋值同时更新两个集合：`Runtime r = Runtime.getRuntime();`
                # 里 `r` **不是污点**（它不含用户输入），但它是**执行器**。
                # ⚠️ 合并成一个集合会让「r 本身脏不脏」和「r 能不能执行命令」
                # 互相污染 —— 后者是类型信息，前者是数据流信息。
                if _RUNNER_RHS.search(rhs):
                    runners = runners | {name}
                else:
                    runners = runners - {name}                # 覆盖即失效（重赋值就不是执行器了）
        res.tainted[i] = set(cur)
        res.runners[i] = set(runners)
    return res


def tainted_names_at(res: TaintResult, line: int) -> set[str]:
    """便捷取数：第 line 行当时处于污点的变量集合。"""
    return res.at(line)


def runner_names_at(res: TaintResult, line: int) -> set[str]:
    """便捷取数：第 line 行当时持有**命令执行器**的变量集合。"""
    return res.runners_at(line)
