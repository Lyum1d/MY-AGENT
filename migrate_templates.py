# -*- coding: utf-8 -*-
"""把 invocation_templates.json 从「纯字符串」升级为「对象 + 目标格式」。

不同工具对目标格式的要求不同，实测差异：
  - ehole / sqlmap 等 -u 类：必须带 scheme，传裸域名会静默返回空（exit 1）
  - oneforall --target：要裸域名，带 www 或 scheme 会收集不全
  - fscan / kscan 等 -h/-t 扫描器：要 host 或 CIDR，带 scheme 会解析失败

target 取值：url | host | domain | raw
"""
import io
import json
from pathlib import Path

P = Path(__file__).parent / "data" / "invocation_templates.json"

# 别名 -> 目标格式。未列出的默认 raw（原样传入）。
FORM = {
    # 需要完整 URL（带 https://）
    "httpx": "url",
    "ehole": "url",
    "veo_finger": "url",
    "packerfuzzer": "url",
    "dirsearch": "url",
    "sqlmap": "url",
    "sqlmap_gui": "url",
    "afrog": "url",
    "dddd_scan": "url",
    "springboot_scan": "url",
    "heartsk": "url",
    "fastjson_exp": "url",
    "nacos_exploit": "url",
    "iwannagetall": "url",
    "equation_kit": "url",
    "vcenter_kit": "url",
    "neo_regeorg": "url",
    "wexploit": "url",

    # 需要 host / IP / CIDR，不能带 scheme
    "fscan": "host",
    "kscan": "host",
    "sharpscan": "host",
    "goon": "host",
    "golin_compliance": "host",
    "ad_domain_assess": "host",
    "goexec": "host",
    "linux_privesc": "host",

    # 需要裸域名（去 scheme、去 www）
    "oneforall": "domain",

    # 企业名称查询，原样
    "enscan": "raw",
}


def main():
    data = json.loads(P.read_text(encoding="utf-8"))
    out = {}
    for k, v in data.items():
        if k.startswith("_"):
            out[k] = v
            continue
        cmd = v["cmd"] if isinstance(v, dict) else v
        form = FORM.get(k, "raw")
        out[k] = {"cmd": cmd, "target": form}

    out["_说明"] = (
        "工具调用模板。{exe}=可执行文件绝对路径，{target}=目标，{args}=模型给出的附加参数。"
        "target 字段声明该工具期望的目标格式，执行前会自动归一化："
        "url=补全 https:// ；host=去掉 scheme 与路径 ；domain=去掉 scheme、www 与路径 ；raw=原样传入。"
        "未配置 target 的工具默认 raw。未配置模板的工具默认使用 {exe} {args} {target}。"
    )
    P.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已升级 {len([k for k in out if not k.startswith('_')])} 条模板")
    for k in ("ehole", "oneforall", "fscan", "httpx"):
        print(f"  {k}: {json.dumps(out[k], ensure_ascii=False)}")


if __name__ == "__main__":
    main()
