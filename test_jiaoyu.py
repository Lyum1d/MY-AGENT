# -*- coding: utf-8 -*-
"""www.jiaoyu.cn 实靶测试：驱动 SRC Agent 跑一轮信息收集 + 指纹识别。

授权依据：补天公益 SRC，全部范围为测试资产。
策略：L1/L2 自动放行；L3 自动拒绝（用于验证降级路径与闸门是否生效）。
"""
import sys

import httpx

BASE = "http://127.0.0.1:8770"
TARGET = "www.jiaoyu.cn"

DEFAULT_TASK = (
    f"目标 {TARGET} 是已授权的公益 SRC 测试资产。"
    f"请对该目标做信息收集与指纹识别：1) 先做存活探测确认站点可达并识别 Web 服务；"
    f"2) 收集子域名；3) 对主站做指纹识别（CMS/框架/中间件）。"
    f"所有工具的 target 参数统一填 {TARGET}。完成后给出结论摘要。"
)

# 允许自定义任务：python test_jiaoyu.py "你的任务描述"
TASK = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TASK

AUTO_APPROVE = {"L1", "L2"}   # L3 自动拒绝
LOG = []


# 注意：环境里设了 HTTP_PROXY（WorkBuddy 自带代理 127.0.0.1:52617）。
# httpx 默认 trust_env=True 会走代理，代理把绝对 URI 原样转发给本机服务，
# 导致路径变成 http%3A//... 而路由 404。访问本地服务必须 trust_env=False。
def client(timeout=30, **kw):
    return httpx.Client(timeout=timeout, trust_env=False, **kw)


def line(s=""):
    print(s, flush=True)
    LOG.append(s)


def post_json(c, url, **kw):
    """POST 并回显异常响应，避免静默 KeyError。"""
    r = c.post(url, **kw)
    try:
        data = r.json()
    except Exception:
        raise RuntimeError(f"{url} -> HTTP {r.status_code}: {r.text[:300]}")
    if r.status_code >= 400:
        raise RuntimeError(f"{url} -> HTTP {r.status_code}: {data}")
    return data


def main():
    with client(30) as c:
        # 1. 建项目（已存在则复用）
        pid = None
        for p in c.get(f"{BASE}/api/projects").json()["items"]:
            if p.get("target") == TARGET:
                pid = p["id"]
                break
        if pid:
            line(f"[项目] 复用已有项目 id={pid}")
        else:
            proj = post_json(c, f"{BASE}/api/projects", json={
                "name": "补天公益SRC-www.jiaoyu.cn",
                "target": TARGET,
                "note": "补天平台公益 SRC，全部范围为测试资产。用途：验证 SRC Agent 实靶流程。",
            })
            pid = proj["id"]
            line(f"[项目] {proj['name']}  id={pid}")

        # 2. 建会话
        sid = post_json(c, f"{BASE}/api/sessions",
                        params={"project_id": pid})["session_id"]
        line(f"[会话] {sid}")

    # 3. 下发任务 + 开 SSE（先发任务再连流，避免流先超时）
    with client(30) as c:
        r = c.post(f"{BASE}/api/sessions/{sid}/run",
                   json={"message": TASK, "project_id": pid})
        line(f"[下发] {r.status_code} {r.text[:120]}")
    line(f"[任务] {TASK}")
    line("=" * 70)

    finished = False
    buf = b""
    with client(None) as c:
        with c.stream("GET", f"{BASE}/api/sessions/{sid}/stream") as sse:
            for raw in sse.iter_bytes():
                if finished:
                    break
                buf += raw
                if not buf.endswith(b"\n\n"):
                    continue
                text = buf.decode("utf-8", errors="replace").strip()
                buf = b""
                if not text.startswith("data: "):
                    continue
                try:
                    import json
                    ev = json.loads(text[6:])
                except Exception:
                    continue

                t = ev.get("type")
                if t == "target":
                    line(f"[目标锁定] {ev['data']}")
                elif t == "reasoning":
                    d = (ev.get("data") or "").strip()
                    if d:
                        line(f"[思考] {d[:400]}")
                elif t == "command":
                    line(f"  $ {ev['data']}")
                elif t == "output":
                    d = (ev.get("data") or "").rstrip()
                    if d:
                        line(f"    {d[:600]}")
                elif t == "exit":
                    line(f"  [exit] {ev.get('code')}")
                elif t == "need_confirm":
                    st = ev["step"]
                    lvl = ev.get("risk", {}).get("level", "?")
                    line(f"  [!] 风险闸门 {lvl}：{st['tool_name']} -> {st['target']}")
                    ok = lvl in AUTO_APPROVE
                    line(f"  [!] {'自动放行' if ok else '自动拒绝'} {lvl}")
                    with client(20) as cc:
                        cc.post(f"{BASE}/api/sessions/{sid}/confirm", json={"approved": ok})
                elif t == "step_denied":
                    line(f"  [x] 已拒绝：{ev['step']['tool_name']}")
                elif t == "answer":
                    line("=" * 70)
                    line(f"[结论] {ev['data']}")
                elif t == "error":
                    line(f"  [错误] {ev['data']}")
                elif t == "done":
                    finished = True
                    line("=" * 70)
                    line(f"[结束] state={ev.get('state')}")

    # 4. 拉取步骤汇总
    with client(30) as c:
        st = c.get(f"{BASE}/api/sessions/{sid}").json()
    line("\n" + "=" * 70)
    line("步骤汇总：")
    for i, s in enumerate(st["steps"], 1):
        line(f"  {i}. {s['tool_name']:<20} {s['status']:<8} "
             f"{s.get('risk', {}).get('level', '-')}  {s['target']}")

    with open("jiaoyu_test_log.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(LOG))
    line("\n日志已写入 jiaoyu_test_log.txt")
    line(f"项目 ID: {pid}   会话 ID: {sid}")


if __name__ == "__main__":
    sys.exit(main())
