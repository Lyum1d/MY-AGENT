# -*- coding: utf-8 -*-
"""Java 的危险 sink（首批四种里与 PHP 并列的高产面：反序列化 / 表达式注入 / 框架）。

## v069 两条实测修正（OWASP BenchmarkJava 驱动，不是凭空加的）

### ① 全限定名盲区

早期所有 Java 规则都写成短名，如 `new\\s+(?:File|FileInputStream)\\s*\\(`。
但真实 Java 代码（尤其经 IDE 自动补全的）几乎一律写**全限定名**。
Benchmark 全库统计：

    new java.io.File*      522 处      ← 旧 pattern 全部漏掉
    new File*（短名）        18 处      ← 只有这些能打中
    new java.net.URL        95 处      ← `new\\s+URL` 同样全漏

即 `java.path.file` 的实际召回率只有 **3.3%**，`java.ssrf.url` 约 1%。
修法：`new\\s+(?:[\\w.]+\\.)?(?:File|…)` —— **可选包名前缀**。
⚠️ 但**不要**图省事写成 `new\\s+[\\w.]*\\s*\\(`（任意类名）：那会把
`new BufferedReader(`、`new ArrayList(` 全都收进来，误报爆炸。
**必须逐类显式枚举**。

### ② 跨行污染（`call_pattern`）

「先拼到局部变量、再传给 sink」的写法**结构上打不中**：

    String sql = "{call " + param + "}";       // ← 危险在这里
    CallableStatement st = conn.prepareCall(sql);  // ← 本行括号里只有变量名

实测 sqli 272 个真漏洞命中 0。补法是在**同一条规则**上加 `call_pattern`
（只描述调用名、不要求参数里有危险成分），由 `search.py` 配合 `taint.py` 判
「这次调用的括号内有没有污点变量」。

⚠️ **不要**另开一条「平行规则」去做这件事 —— v069 第一版就是这么写的，
结果是死代码 + 平行规则裸奔（详见 `base.py` 的 `call_pattern` 注释）。
"""
from __future__ import annotations

from .base import SinkRule, rule

#: 常见文件/流类的**可选全限定名前缀**（`java.io.` / `java.nio.file.` / 无前缀都能匹配）
#: 刻意**不**用「任意类名」，否则会把所有 `new XxxFileReader(` 类构造收进来。
_FS_CLASSES = r"(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter" \
              r"|RandomAccessFile|BufferedReader|BufferedWriter)"

#: 文件/流类的「调用名」pattern（跨行污染用：只认调用，不要求参数里有 `+`）
_FS_CALL = rf"\bnew\s+(?:[\w.]+\.)?{_FS_CLASSES}\s*\("
#: JDBC / JPA 语句执行类的**调用名**（不含开头括号 —— 行级 pattern 要在其后接参数要求）
_SQL_CALL_BARE = (r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|prepareCall"
                  r"|nativeSQL|createQuery|createNativeQuery)")
#: 同上 + 开头括号（跨行污染用：只认调用，不要求参数里有 `+`）
_SQL_CALL = _SQL_CALL_BARE + r"\s*\("
#: 命令执行的「调用名」pattern
_CMD_CALL = r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\("

RULES: list[SinkRule] = [
    # ---------- 命令执行 ----------
    rule("java.rce.runtime_exec", "java", "rce",
         _CMD_CALL,
         "执行系统命令；参数可控即可 RCE",
         "追参数拼接方式（数组传参比字符串拼接安全）；有无白名单",
         # 跨行形态：`argList.add("cat " + param);` → `new ProcessBuilder(argList)`
         call_pattern=_CMD_CALL),

    # ---------- 反序列化（Java 最典型的高危类） ----------
    rule("java.deser.objectinput", "java", "deserialization",
         r"\bObjectInputStream\b|\breadObject\s*\(\s*\)|\breadUnshared\s*\(\s*\)",
         "原生反序列化 —— 存在 gadget 链时可直接 RCE（ysoserial 类）",
         "输入是否来自网络/用户；类路径里有没有 commons-collections 等已知链"),
    rule("java.deser.xmldecoder", "java", "deserialization",
         r"\bXMLDecoder\b",
         "XMLDecoder 反序列化可直接触发方法调用 → RCE",
         "是否解析外部 XML；能否控制其内容"),
    rule("java.deser.snakeyaml", "java", "deserialization",
         # ⚠️ v069：这里原来还有一条裸分支 `|\.load\s*\(` —— 它匹配**任何** `.load(`，
         # 包括 `Session.load()` / `config.load()`。Benchmark 上它贡献的 45 处命中
         # **绝大多数是误报**（只是混在总数里、被 kind 分布掩盖了）。已删除：
         # 宁可用 `new Yaml()` 精确匹配，也不要一个「看起来很能打」的宽口径。
         r"\bnew\s+(?:[\w.]+\.)?Yaml\s*\(\s*\)|SnakeYaml|SafeConstructor",
         "YAML 反序列化可实例化任意类；未用 SafeConstructor 时风险高",
         "有没有用 SafeConstructor；输入是否可控"),

    # ---------- JNDI / 表达式注入 ----------
    rule("java.jndi.lookup", "java", "rce",
         r"\b(?:InitialContext|Context)\b[^;]{0,60}?\.lookup\s*\(|\blookup\s*\(\s*[a-zA-Z_]",
         "JNDI 注入（Log4Shell 同源）：lookup 的名字可控即可加载远程类 → RCE",
         "名字是否含用户输入；JDK 版本与 `com.sun.jndi.ldap.object.trustURLCodebase` 设置"),
    rule("java.expression.inject", "java", "rce",
         r"\bScriptEngine\b|\bSpelExpressionParser\b|\bOgnl\b|\bMVEL\b|\bGroovyShell\b"
         r"|\bExpressionParser\b|\bTemplateEngine\b",
         "表达式/脚本引擎执行 —— 表达式可控时等价于代码执行（Spring/OGNL/Groovy 都出过）",
         "表达式的**模板**是否可控（不是变量可控）；沙箱是否可绕"),

    # ---------- SQL ----------
    rule("java.sqli.concat", "java", "sqli",
         # `prepareCall` / `createNativeQuery` 是 v069 补的：Benchmark 的 sqli 大量走
         # `CallableStatement`（`{call ...}`）与 JPA native query，原来完全不在覆盖面内。
         _SQL_CALL_BARE + r"\s*\([^;]{0,120}?\+",
         "SQL 语句用字符串拼接 —— 经典注入",
         "是否用 `?` 占位符参数化；拼接的是值还是标识符（表名/排序字段参数化不了，另看白名单）",
         # 跨行形态：`sql = "{call " + param + "}";` → `conn.prepareCall(sql)`
         call_pattern=_SQL_CALL),

    # ---------- XXE ----------
    rule("java.xxe.factory", "java", "xxe",
         r"\b(?:DocumentBuilderFactory|SAXParserFactory|SAXReader|XMLInputFactory|"
         r"TransformerFactory|SchemaFactory)\b",
         "解析 XML —— 默认配置下可能允许外部实体（XXE/SSRF/文件读取）",
         "有没有关掉 DTD / 外部实体（`disallow-doctype-decl`、`XMLConstants.FEATURE_SECURE_PROCESSING`）"),

    # ---------- 文件与路径 ----------
    rule("java.path.file", "java", "path_traversal",
         _FS_CALL
         + r"|\bFiles\s*\.\s*(?:readAllBytes|write|newInputStream|copy|delete|readString)\s*\(",
         "文件路径若来自外部可穿越目录（读配置/写 Web 目录）",
         "有没有 `getCanonicalPath()` 后做前缀校验；能否 `..` 穿越",
         # 跨行形态：`fileName = DIR + param;` → `new FileInputStream(fileName)`
         call_pattern=_FS_CALL
         + r"|\bFiles\s*\.\s*(?:readAllBytes|write|newInputStream|copy|delete|readString)\s*\("),

    # ---------- SSRF ----------
    rule("java.ssrf.url", "java", "ssrf",
         # 同全限定名问题：`new java.net.URL(` 有 95 处、短名仅 1 处。
         r"\bnew\s+(?:[\w.]+\.)?URL\s*\(|\bHttpURLConnection\b|\bopenConnection\s*\(|\bHttpClient\b",
         "发起外部请求 —— URL 可控即可探测内网/云元数据",
         "URL 是否可控；有无网段/协议白名单",
         call_pattern=r"\bnew\s+(?:[\w.]+\.)?URL\s*\(|\bopenConnection\s*\("),

    # ---------- 弱加密 ----------
    rule("java.crypto.weak", "java", "weak_crypto",
         r"Cipher\s*\.\s*getInstance\s*\(\s*[\"'](?:DES|RC2|RC4|Blowfish|AES/ECB)",
         "弱加密算法或 ECB 模式",
         "用途是什么：口令存储（更该用 bcrypt/argon2）还是传输"),
    rule("java.hash.weak", "java", "weak_crypto",
         r"MessageDigest\s*\.\s*getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']",
         "MD5/SHA-1 已不适合做完整性/口令摘要",
         "是否用于口令（是则可爆破）；是否用于签名（可伪造）"),

    # ---------- 反射/可见性 ----------
    rule("java.reflect.accessible", "java", "rce",
         r"\.setAccessible\s*\(\s*true\s*\)|\bClass\s*\.\s*forName\s*\(",
         "反射可绕过访问控制 —— 常是 gadget 链的一环",
         "类名/方法名是否可控；是否在反序列化或表达式引擎的路径上"),
]
