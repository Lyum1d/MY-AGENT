# -*- coding: utf-8 -*-
"""Java 的危险 sink（首批四种里与 PHP 并列的高产面：反序列化 / 表达式注入 / 框架）。"""
from __future__ import annotations

from .base import SinkRule, rule

RULES: list[SinkRule] = [
    # ---------- 命令执行 ----------
    rule("java.rce.runtime_exec", "java", "rce",
         r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\(",
         "执行系统命令；参数可控即可 RCE",
         "追参数拼接方式（数组传参比字符串拼接安全）；有无白名单"),

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
         r"\bnew\s+Yaml\s*\(\s*\)|\.load\s*\(|SnakeYaml|SafeConstructor",
         "YAML 反序列化可实例化任意类；未用 SafeConstructor 时风险高",
         "有没有用 SafeConstructor；输入是否可控"),
    rule("java.jndi.lookup", "java", "rce",
         r"\b(?:InitialContext|Context)\b[^;]{0,60}?\.lookup\s*\(|\blookup\s*\(\s*[a-zA-Z_]",
         "JNDI 注入（Log4Shell 同源）：lookup 的名字可控即可加载远程类 → RCE",
         "名字是否含用户输入；JDK 版本与 `com.sun.jndi.ldap.object.trustURLCodebase` 设置"),

    # ---------- 表达式注入 ----------
    rule("java.expression.inject", "java", "rce",
         r"\bScriptEngine\b|\bSpelExpressionParser\b|\bOgnl\b|\bMVEL\b|\bGroovyShell\b"
         r"|\bExpressionParser\b|\bTemplateEngine\b",
         "表达式/脚本引擎执行 —— 表达式可控时等价于代码执行（Spring/OGNL/Groovy 都出过）",
         "表达式的**模板**是否可控（不是变量可控）；沙箱是否可绕"),

    # ---------- SQL ----------
    rule("java.sqli.concat", "java", "sqli",
         r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|nativeSQL|createQuery)"
         r"\s*\([^;]{0,120}?\+",
         "SQL 语句用字符串拼接 —— 经典注入",
         "是否用 `?` 占位符参数化；拼接的是值还是标识符（表名/排序字段参数化不了，另看白名单）"),

    # ---------- XXE ----------
    rule("java.xxe.factory", "java", "xxe",
         r"\b(?:DocumentBuilderFactory|SAXParserFactory|SAXReader|XMLInputFactory|"
         r"TransformerFactory|SchemaFactory)\b",
         "解析 XML —— 默认配置下可能允许外部实体（XXE/SSRF/文件读取）",
         "有没有关掉 DTD / 外部实体（`disallow-doctype-decl`、`XMLConstants.FEATURE_SECURE_PROCESSING`）"),

    # ---------- 文件与路径 ----------
    rule("java.path.file", "java", "path_traversal",
         r"\bnew\s+(?:File|FileInputStream|FileOutputStream|RandomAccessFile)\s*\("
         r"|\bFiles\s*\.\s*(?:readAllBytes|write|newInputStream|copy|delete)\s*\(",
         "文件路径若来自外部可穿越目录（读配置/写 Web 目录）",
         "有没有 `getCanonicalPath()` 后做前缀校验；能否 `..` 穿越"),

    # ---------- SSRF ----------
    rule("java.ssrf.url", "java", "ssrf",
         r"\bnew\s+URL\s*\(|\bHttpURLConnection\b|\bopenConnection\s*\(|\bHttpClient\b",
         "发起外部请求 —— URL 可控即可探测内网/云元数据",
         "URL 是否可控；有无网段/协议白名单"),

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
