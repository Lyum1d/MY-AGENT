# -*- coding: utf-8 -*-
"""给 invocation_templates.json 追加「目标格式」字段。

背景：不同工具对 target 的格式要求不一样，实测差异明显：
  - ehole  finger -u www.jiaoyu.cn        -> exit 1，输出为空（静默失败）
  - ehole  finger -u https://www.jiaoyu.cn-> exit 0，正常出指纹
  - httpx  -u www.jiaoyu.cn               -> exit 0（自带补全，但吃 URL 也没问题）
  - oneforall --target www.jiaoyu.cn      -> 需要裸域名 jiaoyu.cn 才能收全子域

因此在模板里声明每个工具要哪种形式，由执行器统一归一化，
不把格式负担甩给小模型（小模型最容易在这里出错）。

形式定义：
  url    : 必须是完整 URL，缺 scheme 时补 https://
  host   : 只要主机名/端口，去掉 scheme 与路径，保留 www
  domain : 裸域名，去掉 scheme、路径，并去掉 www. 前缀
  raw    : 原样传入（本地分析类工具、纯 args 工具）
"""
import io
import json
from pathlib import Path

P = Path(__file__).parent / "data" / "invocation_templates.json"

# 按 flag 的兜底规则：模板里出现哪个 flag 就默认要哪种形式
DEFAULT_BY_FLAG = [
    ("--target", "domain"),
    (" -n ", "domain"),
    (" -u ", "url"),
    (" -t ", "host"),
    (" -h ", "host"),
]

# 显式指定，优先级高于兜底规则
EXPLICIT = {
    "httpx": "host",          # 存活探测吃裸主机即可，避免 URL 里的路径干扰
    "ehole": "url",
    "veo_finger": "url",
    "packerfuzzer": "url",
    "dirsearch": "url",
    "sqlmap": "url",
    "sqlmap_gui": "url",
    "springboot_scan": "url",
    "heartsk": "url",
    "fastjson_exp": "url",
    "nacos_exploit": "url",
    "iwannagetall": "url",
    "equation_kit": "url",
    "vcenter_kit": "url",
    "neo_regeorg": "url",
    "wexploit": "url",
    "afrog": "host",
    "fscan": "host",
    "kscan": "host",
    "dddd_scan": "host",
    "sharpscan": "host",
    "goon": "host",
    "oneforall": "domain",
    "enscan": "domain",
    # 本地分析 / 免杀 / 隧道 / 后门类：不接目标或目标含义特殊
    "heapdump_decrypt": "raw",
    "md5_tool": "raw",
    "app_info": "raw",
    "golin_compliance": "host",
    "ad_domain_assess": "host",
    "goexec": "raw",
    "linux_privesc": "raw",
    "deepseek_tool": "raw",
}


def guess(alias: str, cmd: str) -> str:
    if alias in EXPLICIT:
        return EXPLICIT[alias]
    if "{target}" not in cmd:
        return "raw"
    padded = f" {cmd} "
    for flag, form in DEFAULT_BY_FLAG:
        if flag in padded:
            return form
    return "raw"


def main():
    data = json.loads(P.read_text(encoding="utf-8"))
    out = {}
    for k, v in data.items():
        if k.startswith("_"):
            out[k] = v
            continue
        cmd = v["cmd"] if isinstance(v, dict) else v
        out[k] = {"cmd": cmd, "target": guess(k, cmd)}

    out["_说明"] = (
        "工具调用模板。{exe}=可执行文件绝对路径，{target}=目标，{args}=模型给出的附加参数。"
        "target 字段声明该工具需要的目标形式（url/host/domain/raw），执行器会自动归一化，"
        "未配置的工具默认使用 {exe} {args} {target} 且不做归一化。"
    )
    P.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    from collections import Counter
    c = Counter(v["target"] for k, v in out.items() if not k.startswith("_"))
    print("已写入", P)
    print("形式分布：", dict(c))
    for k in ("ehole", "httpx", "oneforall", "enscan", "fscan", "dirsearch"):
        print(f"  {k:12} -> {out[k]}")


if __name__ == "__main__":
    main()
