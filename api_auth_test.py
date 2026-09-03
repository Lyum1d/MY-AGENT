# -*- coding: utf-8 -*-
"""www.jiaoyu.cn API 未授权访问探测（只读、无参 GET、低速率）。

授权依据：补天公益 SRC，www.jiaoyu.cn 为授权测试资产。
方法学：
  1. 全部请求为无参数 GET，不触发任何写操作/短信发送/验证码消耗
  2. 0.4s 间隔限速，UA 标明安全测试用途
  3. 以 /api/__not_exist__ 为基线：区分「SPA fallback 假 200」与「真实 API 响应」
  4. 判定重点：Content-Type 为 JSON 且非基线形态 → 潜在未授权访问，记录证据
"""
import json
import time

import httpx

BASE = "https://www.jiaoyu.cn"
UA = "SRC-Agent-AuthTest/1.0 (authorized Butian SRC test; contact via Butian platform)"

APIS = [
    "/api/user/info", "/api/my/course", "/api/my/course/note", "/api/my/learn/log",
    "/api/user/phone", "/api/user/password", "/api/login/info", "/api/user/assessFile/uploads",
    "/api/course/course", "/api/course/teacher", "/api/course/category",
    "/api/course/comment", "/api/course/preview", "/api/course/yxtTop", "/api/course/log/add",
    "/api/cms/news", "/api/home/home", "/api/zznc/index", "/api/zznc/sat_score",
    "/api/login", "/api/logout", "/api/register", "/api/reset", "/api/captcha",
    "/api/sms/send", "/api/common/register/getcode", "/api/message/add",
    "/api/user/update", "/api/user/unbind", "/api/weixin/bind", "/api/zznc/sat_save",
]
BASELINE = "/api/__not_exist_baseline__"

results = []


def probe(c: httpx.Client, path: str) -> dict:
    try:
        r = c.get(BASE + path, headers={"User-Agent": UA}, timeout=15)
        body = r.text
        ctype = r.headers.get("content-type", "")
        is_json = "json" in ctype.lower()
        is_fallback = (not is_json) and "html" in ctype.lower() and len(body) == 1536
        snippet = body[:300].replace("\n", " ") if is_json else (
            "<SPA fallback 1536B>" if is_fallback else body[:200].replace("\n", " "))
        return {"path": path, "code": r.status_code, "ctype": ctype.split(";")[0],
                "len": len(body), "json": is_json, "fallback": is_fallback,
                "snippet": snippet}
    except Exception as e:
        return {"path": path, "code": -1, "ctype": "", "len": 0, "json": False,
                "fallback": False, "snippet": f"[异常] {e}"}


def main():
    with httpx.Client(trust_env=False, follow_redirects=False) as c:
        print("== 基线 ==")
        base = probe(c, BASELINE)
        print(f"  {BASELINE} -> {base['code']} {base['ctype']} len={base['len']} fallback={base['fallback']}")
        time.sleep(0.4)

        print("\n== 逐条探测（无参 GET）==")
        for p in APIS:
            r = probe(c, p)
            results.append(r)
            flag = ""
            if r["json"]:
                flag = "  <<< JSON 响应，值得关注"
            elif r["fallback"]:
                flag = "  (SPA fallback)"
            print(f"  {r['code']:<4} {r['ctype']:<16} len={r['len']:<6} {p}{flag}")
            if r["json"]:
                print(f"        └ {r['snippet']}")
            time.sleep(0.4)

    # 汇总
    interesting = [r for r in results if r["json"] and r["code"] == 200]
    print("\n" + "=" * 70)
    print(f"JSON 200 响应（潜在未授权访问候选）：{len(interesting)} 条")
    for r in interesting:
        print(f"  {r['path']}\n    └ {r['snippet'][:260]}")

    with open("api_auth_test_results.json", "w", encoding="utf-8") as f:
        json.dump({"baseline": base, "results": results}, f, ensure_ascii=False, indent=2)
    print("\n明细已保存 api_auth_test_results.json")


if __name__ == "__main__":
    main()
