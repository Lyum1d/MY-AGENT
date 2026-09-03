# -*- coding: utf-8 -*-
"""工具注册表。

职责：
1. 解析工具箱的 config/tools.json，作为唯一权威数据源
2. 区分「可编排」与「仅可启动」工具
3. 为每个可编排工具生成英文别名（中文名做 function name 不可靠）并双向映射
4. 加载风险分级，提供闸门判定
5. 生成 Ollama function calling 所需的 schema
"""
from __future__ import annotations

import difflib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import config


@dataclass
class Tool:
    name: str           # 工具箱中的原始名称（可能是中文）
    alias: str          # 英文别名，用于 function calling
    category: str
    type: str           # 命令行 / Python / JAVA8 / 批处理 ...
    rel_path: str       # 相对工具箱根目录的路径
    url: str = ""
    description: str = ""
    risk_level: str = "L2"
    risk_reason: str = ""
    scriptable: bool = False
    executable: str = ""
    workdir: str = ""
    disabled: bool = False          # 实测不可用，不进 Agent 工具清单
    disabled_reason: str = ""
    tool_timeout: int = 0           # 单工具时长覆写（秒，0=用全局）
    ignore_exit_code: bool = False  # 退出码不可信（有输出即算成功）
    caveat: str = ""                # 已知注意事项，会写进给模型的工具说明
    allowed_flags: list = field(default_factory=list)  # 合法旗标白名单（为空=不校验）
    value_flags: list = field(default_factory=list)    # 其中需要吞掉下一个 token 的取值旗标
    stdin_input: str = ""               # 启动时写入子进程 stdin 的内容（用于绕开交互式提问）

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "alias": self.alias,
            "category": self.category,
            "type": self.type,
            "path": self.rel_path,
            "url": self.url,
            "description": self.description,
            "risk_level": self.risk_level,
            "risk_reason": self.risk_reason,
            "scriptable": self.scriptable,
            "exists": bool(self.executable),
            "disabled": self.disabled,
            "disabled_reason": self.disabled_reason,
        }


# 可编排工具的显式别名。
# 原因：路径文件名常带版本号/平台后缀（tidefinger_windows_amd64_v）或纯中文（哥斯拉特战版），
# 自动推导会产生 v、main、tool_2 这类无意义名字，直接拉低模型选型准确率。
# 这里是固定集合，显式指定最可靠。
ALIAS_OVERRIDES: dict[str, str] = {
    # L0 只读 / 本地分析
    "ENScan": "enscan",
    "OneForALL": "oneforall",
    "APP信息收集工具探测工具": "app_info",
    "Httpx辅助工具": "httpx",
    "Ehole指纹识别工具魔改版": "ehole",
    "TideFinger指纹识别工具": "tidefinger",
    "P1finger指纹识别": "p1finger",
    "VEO指纹识别工具": "veo_finger",
    "GOlin等保核查工具": "golin_compliance",
    "Frp": "frp_tunnel",
    "heapdump解密工具": "heapdump_decrypt",
    "杂项加密解密小工具(MD5版)": "md5_tool",
    "DeepSeekSelfTools": "deepseek_tool",
    # L1 主动探测扫描
    "DirSearch目录探测工具": "dirsearch",
    "WebPack信息探测工具": "packerfuzzer",
    "Afrog可定制化漏洞扫描工具": "afrog",
    "nuclei漏洞扫描器": "nuclei",
    "Xscan": "xscan",
    "EZ扫描检测工具": "ez_scan",
    "DDDD漏扫工具": "dddd_scan",
    "Rscan": "rscan",
    "SpringBoot-Scan": "springboot_scan",
    "Serein": "serein",
    "SharpScan": "sharpscan",
    # L2 漏洞验证与利用
    "SQLMAP X Plus": "sqlmap",
    "SQLMAP-GUI": "sqlmap_gui",
    "Fastjson检测利用工具": "fastjson_exp",
    "WExploit漏洞利用工具": "wexploit",
    "XG拟态WEBSHELL免杀工具": "xg_webshell",
    "HeavenlyBypassAV": "bypass_av",
    # L3 权限 / 横向 / 接管
    "Fscan_V2.0": "fscan",
    "Kscan-1.85稳定版": "kscan",
    "goon扫描探测爆破工具集": "goon",
    "棱镜X单兵作战系统": "heartsk",
    "AK SK利用工具": "aksk_exploit",
    "CF利用工具": "aksk_post_exploit",
    "JNDI利用工具": "jndi_exploit",
    "Neo-reGeorg": "neo_regeorg",
    "IWannaGetAll": "iwannagetall",
    "Nacos综合利用工具": "nacos_exploit",
    "方程式工具包": "equation_kit",
    "冰蝎4": "behinder4",
    "哥斯拉": "godzilla",
    "哥斯拉特战版": "godzilla_special",
    "Linux一键维权探测工具": "linux_privesc",
    "Vcenter综合渗适利用工具包": "vcenter_kit",
    "Mimikatz": "mimikatz",
    "GoExec": "goexec",
    "AD域自动化评估工具": "ad_domain_assess",
    "CobaltStrike 4.7": "cobaltstrike",
}


def _make_alias(name: str, rel_path: str, used: set[str]) -> str:
    """从路径文件名生成稳定英文别名。

    优先用可执行文件的文件名（通常是英文，如 enscan.exe -> enscan）；
    纯中文名则退化为 tool_<序号>，保证 function calling 的 name 合法。
    """
    stem = ""
    if rel_path:
        stem = Path(rel_path.replace("/", "\\")).stem
    # 去掉版本号与常见后缀，如 nuclei-7.4.8 -> nuclei
    stem = re.sub(r"[-_.]?\d+(\.\d+){1,3}", "", stem)
    stem = re.sub(r"[-_.]?(windows|amd64|win64|win32|x64|gui|v\d+)$", "", stem, flags=re.I)
    base = re.sub(r"[^a-zA-Z0-9_]", "_", stem).strip("_").lower()

    if not base or base[0].isdigit():
        base = ""
    if not base:
        ascii_part = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_").lower()
        base = ascii_part if ascii_part and not ascii_part[0].isdigit() else ""

    alias = base or "tool"
    if alias in used:
        i = 2
        while f"{alias}_{i}" in used:
            i += 1
        alias = f"{alias}_{i}"
    used.add(alias)
    return alias


class ToolRegistry:
    def __init__(self) -> None:
        self.tools: list[Tool] = []
        self._by_alias: dict[str, Tool] = {}
        self._by_name: dict[str, Tool] = {}
        self.loaded = False
        self.errors: list[str] = []

    # ---------- 加载 ----------
    def load(self) -> "ToolRegistry":
        tools_json = config.TOOLBOX_ROOT / "config" / "tools.json"
        if not tools_json.exists():
            self.errors.append(f"找不到工具清单：{tools_json}")
            return self

        raw = json.loads(tools_json.read_text(encoding="utf-8"))
        grades = self._load_grades()
        overrides = self._load_overrides()
        used: set[str] = set()

        for item in raw:
            rel = item.get("path", "") or ""
            url = item.get("url", "") or ""
            ttype = item.get("type", "")
            scriptable = ttype in config.SCRIPTABLE_TYPES and not url

            tool = Tool(
                name=item.get("name", ""),
                alias="",
                category=item.get("category", ""),
                type=ttype,
                rel_path=rel,
                url=url,
                description=(item.get("description") or "").strip(),
                scriptable=scriptable,
            )

            tool.alias = ALIAS_OVERRIDES.get(tool.name) or _make_alias(tool.name, rel, used)
            if tool.alias in used:
                tool.alias = _make_alias(tool.name, rel, used)
            used.add(tool.alias)

            ov = overrides.get(tool.alias) or overrides.get(tool.name)
            if ov:
                tool.disabled = bool(ov.get("disabled"))
                tool.disabled_reason = ov.get("reason", "")
                tool.tool_timeout = int(ov.get("timeout") or 0)
                tool.ignore_exit_code = bool(ov.get("ignore_exit_code"))
                tool.caveat = ov.get("caveat", "") or ""
                tool.allowed_flags = list(ov.get("allowed_flags") or [])
                tool.value_flags = list(ov.get("value_flags") or [])
                tool.stdin_input = ov.get("stdin_input", "") or ""

            if scriptable:
                g = grades.get(tool.name)
                if g:
                    tool.risk_level = g.get("level", config.DEFAULT_RISK_LEVEL)
                    tool.risk_reason = g.get("reason", "")
                else:
                    tool.risk_level = config.DEFAULT_RISK_LEVEL
                    tool.risk_reason = "未在分级表中定义，按默认 L2 处理"
                self._resolve_executable(tool)
            else:
                # 图形界面 / 网页工具不进流水线，但仍要能在工具箱面板启动
                if rel and not url:
                    self._resolve_executable(tool)

            self.tools.append(tool)
            self._by_name[tool.name] = tool
            self._by_alias[tool.alias] = tool

        self._add_builtin_tools()
        self.loaded = True
        return self

    def _add_builtin_tools(self) -> None:
        """注册内置工具（不依赖工具箱子进程，由 app/replayer.py 托管执行）。"""
        nuclei_exe = config.DATA_DIR / "bin" / "nuclei.exe"
        specs = [
            {
                "name": "HTTP重放器",
                "alias": "httpreplay",
                "description": "对单个 URL 发起受控 HTTP 请求并回传完整响应（状态码/响应头/响应体）。"
                               "用于未授权访问验证、IDOR 探测、CORS 检查、403 绕过、单点参数测试。",
                "risk_level": "L2",
                "risk_reason": "直接向目标发送构造请求；仅允许 GET/HEAD/OPTIONS 只读方法，"
                               "写入方法硬禁用；域名白名单（data/scope.json）强制生效",
                "caveat": "target 填完整 URL（可含查询串）。args 支持：多个 -H \"头: 值\"、"
                          "-d 参数=值（追加查询串）、-X 方法（仅 GET/HEAD/OPTIONS）、"
                          "--timeout 秒（上限 20）。无凭据直接请求即可验证未授权访问。",
                "executable": "builtin://httpreplay",
                "exists": True,
            },
            {
                "name": "Nuclei漏洞扫描CLI",
                "alias": "nuclei_cli",
                "description": "官方 nuclei 引擎命令行版，基于模板批量验证已知漏洞（CVE/暴露面/默认凭据）。"
                               "首次运行会自动下载模板库。",
                "risk_level": "L2",
                "risk_reason": "模板包含真实 PoC 请求，属于主动漏洞验证行为",
                "caveat": "target 填完整 URL。args 传 nuclei 原生旗标，"
                          "如 -severity critical,high 先跑高危模板减少噪声。",
                "executable": str(nuclei_exe) if nuclei_exe.exists() else "",
                "exists": nuclei_exe.exists(),
            },
        ]
        used = {t.alias for t in self.tools}
        for s in specs:
            if s["alias"] in used:
                continue
            t = Tool(
                name=s["name"], alias=s["alias"], category="内置能力",
                type="内置", rel_path="", description=s["description"],
                risk_level=s["risk_level"], risk_reason=s["risk_reason"],
                scriptable=True, caveat=s["caveat"], executable=s["executable"],
            )
            self.tools.append(t)
            self._by_name[t.name] = t
            self._by_alias[t.alias] = t

    def _load_grades(self) -> dict[str, Any]:
        p = config.DATA_DIR / "risk_grades.json"
        if not p.exists():
            self.errors.append(f"找不到风险分级文件：{p}，全部工具将按 L2 处理")
            return {}
        return json.loads(p.read_text(encoding="utf-8"))

    def _load_overrides(self) -> dict[str, Any]:
        p = config.DATA_DIR / "tool_overrides.json"
        if not p.exists():
            return {}
        data = json.loads(p.read_text(encoding="utf-8"))
        return {k: v for k, v in data.items() if not k.startswith("_")}

    def usable_scriptable(self) -> list[Tool]:
        """Agent 实际可用的可编排工具：排除禁用项与文件缺失项。"""
        return [t for t in self.scriptable_tools() if not t.disabled and t.executable]

    def _resolve_executable(self, tool: Tool) -> None:
        """把相对路径解析为绝对路径，并记录工作目录。"""
        if not tool.rel_path:
            return
        abs_path = config.TOOLBOX_ROOT / tool.rel_path.lstrip("/").replace("/", "\\")
        if abs_path.exists():
            tool.executable = str(abs_path)
            tool.workdir = str(abs_path.parent)
        else:
            self.errors.append(f"工具文件缺失：{tool.name} -> {abs_path}")

    # ---------- 查询 ----------
    def get_by_alias(self, alias: str) -> Tool | None:
        """用模型返回的别名查工具。找不到返回 None（模型可能编造了工具名）。"""
        return self._by_alias.get(alias)

    @staticmethod
    def canonical(alias: str) -> str:
        """工具名归一化。

        小模型返回的工具名极不干净，实测出现过的脏写法：
        带空白 / 大小写混用 / 全角字符 / 零宽空格 / 带引号或括号 /
        带命名空间前缀（functions.xxx）/ 带 .exe 后缀。
        全部在这里收敛，避免「名字看着对却被拦」的假失败。
        """
        s = unicodedata.normalize("NFKC", alias or "")   # 全角 -> 半角
        s = "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")  # 去零宽等控制符
        s = s.strip().strip("\"'`()[]{}<>").strip()
        s = re.sub(r"^functions\.", "", s, flags=re.I)
        s = re.sub(r"\.(exe|py|jar|bat)$", "", s, flags=re.I)
        s = re.sub(r"[\s\-]+", "_", s)
        return s.lower()

    def resolve(self, alias: str) -> tuple[Tool | None, bool]:
        """解析模型给出的工具名，带模糊匹配。

        小模型经常拼错工具名（如 eohole / subfindr），直接拒绝会浪费整整一轮决策。
        返回 (工具, 是否为模糊匹配命中)。
        """
        key = self.canonical(alias)
        if not key:
            return None, False

        tool = self._by_alias.get(alias) or self._by_alias.get(key)
        if tool:
            return tool, False

        # 归一化后再精确匹配一遍（覆盖全角、前缀、大小写等）
        for t in self.usable_scriptable():
            if self.canonical(t.alias) == key:
                return t, True

        candidates = {t.alias: t for t in self.usable_scriptable()}
        near = difflib.get_close_matches(key, list(candidates), n=1, cutoff=0.75)
        if near:
            return candidates[near[0]], True

        # 子串兜底：模型有时输出 "run oneforall now" 这类带前后缀的串
        for t in self.usable_scriptable():
            if len(t.alias) >= 4 and t.alias in key:
                return t, True
        return None, False

    def scriptable_tools(self) -> list[Tool]:
        return [t for t in self.tools if t.scriptable]

    def launchable_tools(self) -> list[Tool]:
        """能在工具箱面板一键启动的本地工具（不含网页与内置工具）。"""
        return [t for t in self.tools if t.executable and t.type != "内置"]

    def web_tools(self) -> list[Tool]:
        return [t for t in self.tools if t.url]

    def stats(self) -> dict[str, int]:
        return {
            "total": len(self.tools),
            "scriptable": len(self.scriptable_tools()),
            "launchable": len(self.launchable_tools()),
            "web": len(self.web_tools()),
            "missing": sum(1 for t in self.scriptable_tools() if not t.executable),
        }

    # ---------- 风险闸门 ----------
    def risk_of(self, alias: str) -> dict[str, Any] | None:
        tool = self.get_by_alias(alias)
        if not tool:
            return None
        meta = config.RISK_LEVELS.get(tool.risk_level, config.RISK_LEVELS[config.DEFAULT_RISK_LEVEL])
        return {
            "level": tool.risk_level,
            "name": meta["name"],
            "auto": meta["auto"],
            "double_confirm": meta["double_confirm"],
            "reason": tool.risk_reason,
            "tool": tool.name,
        }

    # ---------- function calling schema ----------
    def build_schemas(self, max_tools: int = 40) -> list[dict[str, Any]]:
        """为可编排工具生成 function calling schema。

        max_tools 限制数量：工具太多会拖慢本地小模型的决策速度。
        按风险从低到高排序，优先保留低危工具。
        内置工具（重放器等核心能力）始终保留，不参与配额竞争。
        """
        order = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
        tools = sorted(self.usable_scriptable(), key=lambda t: order.get(t.risk_level, 2))
        builtins = [t for t in tools if t.type == "内置"]
        rest = [t for t in tools if t.type != "内置"][: max(0, max_tools - len(builtins))]
        tools = builtins + rest

        schemas = []
        for t in tools:
            desc = t.description or t.risk_reason or t.category
            full = f"{t.name}（{t.category}）：{desc}。风险等级 {t.risk_level}。"
            if t.caveat:
                full += f"注意：{t.caveat}"
            if t.allowed_flags:
                full += "合法参数（args 只允许使用这些旗标，其余会被自动丢弃）：" + ", ".join(sorted(set(t.allowed_flags))) + "。"
            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.alias,
                        "description": full,
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "目标，域名、IP 或企业名称",
                                },
                                "args": {
                                    "type": "string",
                                    "description": "附加命令行参数，不需要则留空字符串",
                                },
                            },
                            "required": ["target"],
                        },
                    },
                }
            )
        return schemas

    def alias_reference(self) -> str:
        """给系统提示词用的工具清单，帮助模型选对工具。"""
        lines = []
        for t in self.usable_scriptable():
            lines.append(f"- {t.alias} = {t.name} | {t.category} | {t.risk_level} | {t.description or t.risk_reason}")
        return "\n".join(lines)


registry = ToolRegistry()
