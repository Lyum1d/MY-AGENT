# -*- coding: utf-8 -*-
"""授权实靶测试：驱动 SRC Agent 对**已授权目标**跑一轮信息收集 + 指纹识别。

授权依据：目标必须出现在 `data/scope.json` 里（该文件是本机授权目标的唯一真相源）。
策略：L1/L2 自动放行；L3 自动拒绝（用于验证降级路径与闸门是否生效）。

## 为什么不再写死域名（v046）

本仓库是 **public**，而本脚本原名把授权靶标名写进了**文件名与内容**。
项目把 `data/scope.json` 加进 `.gitignore` 的理由正是「含真实授权靶标，严禁入库」
—— 但泄露实际发生在这个测试脚本里，不在那个被严加看管的文件里。
现在改为**运行时从 `data/scope.json` 读取**，顺带让这个脚本对任何授权目标
（以及团队里任何成员）都能直接用 —— 不必为了换目标去改代码。

用法：
    python test_live_target.py                       # 用 scope.json 里的第一个授权域
    python test_live_target.py example.com           # 指定目标（须在 scope.json 内）
    python test_live_target.py example.com "任务描述"  # 自定义任务
"""
import json
import os
import sys

import httpx

BASE = "http://127.0.0.1:8770"
HERE = os.path.dirname(os.path.abspath(__file__))


def load_target(cli: str = "") -> str:
    """取本次实靶目标。显式给了就用给的，但**必须过同一份 scope 校验**。"""
    scope_file = os.path.join(HERE, "data", "scope.json")
    try:
        data = json.loads(open(scope_file, encoding="utf-8").read())
    except Exception as e:                       # noqa: BLE001
        raise SystemExit(f"读不到 data/scope.json（授权目标唯一真相源）：{e}")
    hosts = [d for d in (data.get("domains") or [])
             if isinstance(d, str) and "." in d]
    if not hosts:
        raise SystemExit("data/scope.json 里没有可用的授权域，请先填入已获授权的目标")

    if not cli:
        return hosts[0]
    # 复用 app/scope.py 的校验，而不是在这里另写一套匹配规则 ——
    # 两套规则一旦分叉，就会出现「测试脚本认为在范围内、Agent 认为不在」的静默缺口。
    try:
        sys.path.insert(0, HERE)
        from app import scope as scope_mod
        denied = scope_mod.check_scope(cli)
    except Exception:                            # noqa: BLE001
        denied = None if any(cli == h or cli.endswith("." + h)
                             for h in hosts) else "不在授权域内"
    if denied:
        raise SystemExit(f"指定目标不在授权范围：{denied}")
    return cli


TARGET = load_target(sys.argv[1] if len(sys.argv) > 1 else "")

DEFAULT_TASK = (
    f"目标 {TARGET} 是已授权的 SRC 测试资产。"
    f"请对该目标做信息收集与指纹识别：1) 先做存活探测确认站点可达并识别 Web 服务；"
    f"2) 收集子域名；3) 对主站做指纹识别（CMS/框架/中间件）。"
    f"所有工具的 target 参数统一填 {TARGET}。完成后给出结论摘要。"
)

TASK = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_TASK
LOG_NAME = "live_target_test_log.txt"     # 日志名不带目标标识，避免随交付物外流

AUTO_APPROVE = {"L1", "L2"}   # L3 自动拒绝
LOG = []


# 注意：环境里设了 HTTP_PROXY（WorkBuddy 自带代理）。
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
    line(f"[目标] {TARGET}（来自 data/scope.json）")
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
                "name": f"授权实靶回归-{TARGET}",
                "target": TARGET,
                "note": "公益 SRC 授权目标。用途：验证 SRC Agent 实靶流程。",
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
                        # 带上 step_id：后端只接受「正在等待确认的那一步」的回应
                        cc.post(f"{BASE}/api/sessions/{sid}/confirm",
                                json={"approved": ok, "step_id": st["id"]})
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

    # 日志含真实靶标与响应片段，属交战数据（已在 .gitignore 里排除）
    with open(LOG_NAME, "w", encoding="utf-8") as f:
        f.write("\n".join(LOG))
    line(f"\n日志已写入 {LOG_NAME}（含真实靶标，勿提交）")
    line(f"项目 ID: {pid}   会话 ID: {sid}")


if __name__ == "__main__":
    sys.exit(main())
