# -*- coding: utf-8 -*-
"""把 invocation_templates.json 从「字符串」升级为「对象」，并标注每个工具期望的目标格式。

目标格式（target form）：
  url    必须带 scheme，如 https://www.jiaoyu.cn（ehole 传裸域名会静默返回空）
  host   只要主机名/IP，去掉 scheme 与路径（fscan -h 192.168.1.1）
  domain 只要注册域名，去掉 scheme、路径与 www.（oneforall 子域名枚举）
  asis   原样透传，不转换（默认）
"""
import io
import json
from collections import OrderedDict
from pathlib import Path

P = Path(__file__).parent / "data" / "invocation_templates.json"

# 需要显式指定格式的工具有限，其余走 asis 默认（最保守，不改动现有行为）
FORM = {
    # 实测：ehole 传 www.jiaoyu.cn 返回空且 exit 1，带 https:// 才正常
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
    "httpx": "url",
    "afrog": "url",
    "dddd_scan": "url",
    "goon": "url",
    # 子域名枚举要裸域名，带 www. 会漏
    "oneforall": "domain",
    # 主机/IP 扫描类，不接受 scheme
    "fscan": "host",
    "sharpscan": "host",
    "kscan": "host",
}

META = {
    "_说明": "工具调用模板。{exe}=可执行文件绝对路径，{target}=目标（按 target_form 归一化后填入），{args}=模型给出的附加参数。未配置的工具默认使用 {exe} {args} {target}。",
    "_target_form": "url=必须带 scheme；host=去掉 scheme 与路径；domain=去掉 scheme/路径/www.；asis=原样透传。",
}


def main():
    old = json.loads(P.read_text(encoding="utf-8"))
    new = OrderedDict()
    new["_说明"] = META["_说明"]
    new["_target_form"] = META["_target_form"]
    n_url = n_host = n_domain = n_asis = 0

    for k, v in old.items():
        if k.startswith("_"):
            continue
        form = FORM.get(k, "asis")
        new[k] = {"cmd": v, "target_form": form}
        if form == "url":
            n_url += 1
        elif form == "host":
            n_host += 1
        elif form == "domain":
            n_domain += 1
        else:
            n_asis += 1

    # 备份
    bak = P.with_suffix(".json.bak")
    bak.write_text(json.dumps(old, ensure_ascii=False, indent=2), encoding="utf-8")

    P.write_text(json.dumps(new, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已升级 {len(new) - 2} 条模板 -> {P.name}")
    print(f"  url={n_url} host={n_host} domain={n_domain} asis={n_asis}")
    print(f"  原文件已备份为 {bak.name}")


if __name__ == "__main__":
    main()
