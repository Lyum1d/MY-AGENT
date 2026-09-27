# -*- coding: utf-8 -*-
"""v050 配置控制台回归测试（P1）。

覆盖三块：

  A. **口令闸门与 fail-closed** —— 这个界面能改授权白名单，未设口令时不许开放。
  B. **写入的两道服务端强制** —— 一次性确认票据 + 乐观锁。绕过前端也必须挡住。
  C. **写完真的生效** —— 端到端跑一遍 `scope.check_scope()`，而不是只看接口返回 200。

  D. 迁移器（`domains` + `_说明` → 结构化 `targets`），用占位域名做夹具。
  E. 红线自检：审计与备份两个新文件必须 gitignored；本版文件不含靶标词干。

## ⚠️ TestClient 必须带**回环 base_url**

应用有一道 `local_request_guard` 中间件（DNS 重绑定防护）：绑回环时强制 Host 必须是
回环名。TestClient 默认发 `Host: testserver`，会被它 403 掉 —— 现象是**所有**用例都红，
且理由与业务无关。所以统一用 `base_url=LOOPBACK`。

顺带记一笔（v050 侦察时的自我纠正）：我先前说「全站无鉴权」**并不准确**。
真实情况是**两条互补防线**：
  · 绑回环时：无鉴权，但有 Host 守卫（上面那道）；
  · 绑非回环（ALLOW_REMOTE=1）时：全站要求 `SRC_AGENT_TOKEN` Bearer 令牌，
    由 `remote_access_token_guard` 强制，且**未设令牌就拒绝所有请求**。
控制台口令补的是**回环场景下**的缺口，与这两条不重叠。

## ⚠️ 本测试**不碰真实的 data/scope.json**

用户的 `scope.json` 里有真实授权靶标，测试若写它会直接破坏白名单
（现象是「所有工具突然被拒」）。所有写入用例都通过临时目录重定向
`config.SCOPE_FILE` / `config_io.AUDIT_FILE` / `config_io.BACKUP_DIR` ——
这三个都是**调用时读的模块属性**，所以改属性即可全局重定向。

统计行格式必须是 `结果：N 通过 / M 失败`（run_all_tests.py 的正则要求）。
"""
from __future__ import annotations

import json
import re as _re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient                     # noqa: E402

from app import config, config_io, console_api, scope, scope_migrate  # noqa: E402
from app.main import app                                       # noqa: E402

# 回环 base_url（见文件头说明）：否则被 Host 守卫 403
LOOPBACK = "http://127.0.0.1:8770"

PASS, FAIL = 0, 0
REPO = Path(__file__).resolve().parent
PW = "test-console-pw-050"


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" —— {detail}" if detail else ""))


def read(rel: str) -> str:
    try:
        return (REPO / rel).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ---------------- 路径重定向（保护真实配置） ----------------
class Sandbox:
    """把控制台会写的东西**全部**重定向到临时目录。

    v051 起 P2 的写入面从 1 个（scope.json）扩到 6 个，其中四个是**仓库里的真实文件**：
      · data/risk_grades.json（入库）
      · data/tool_overrides.json（入库）
      · data/invocation_templates.json（入库）
      · data/rules/compliance-redlines.md（入库）
      · config.yaml（**含用户真实 FOFA 密钥，gitignored**）
    测试若碰它们，轻则污染仓库、重则把用户的密钥文件写坏。

    两条重定向路径，缺一不可：
      ① `config.DATA_DIR` → 临时目录。因为 `registry._load_grades()` /
         `_load_overrides()` 也是**调用时**读 `config.DATA_DIR` ——
         只有这样「控制台写」与「registry 重载读」才看到同一份临时文件，
         「写完重载真的生效」这条断言才有意义。
      ② `console_api._config_yaml_path` → 直接换成临时文件。
         `config.yaml` 走的是 `config.APP_DIR`，而 APP_DIR 被大量模块级常量依赖，
         **不能整体打补丁**；所以只换这一个函数（外科式）。
    """

    def __init__(self, seed: tuple[str, ...] = ()):
        # seed：需要复制进临时 data/ 的仓库文件（相对 data/ 的路径）
        self.seed = tuple(seed)

    def __enter__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="v050_"))
        data = self.tmp / "data"
        data.mkdir(parents=True, exist_ok=True)
        self.saved = (config.DATA_DIR, config.SCOPE_FILE, config_io.AUDIT_FILE,
                      config_io.BACKUP_DIR, config_io.OVERRIDES_FILE,
                      console_api._config_yaml_path)
        config.DATA_DIR = data
        for rel in self.seed:
            src = REPO / "data" / rel
            dst = data / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.exists():
                shutil.copy2(src, dst)
            else:
                dst.write_text("{}", encoding="utf-8")
        config.SCOPE_FILE = data / "scope.json"
        config_io.AUDIT_FILE = data / "console_audit.jsonl"
        config_io.BACKUP_DIR = data / "console_backups"
        config_io.OVERRIDES_FILE = data / "runtime_overrides.json"
        # config.yaml 单独换（见类注释 ②）
        yml = self.tmp / "config.yaml"
        src_yml = REPO / "config.yaml"
        yml.write_text(src_yml.read_text(encoding="utf-8", errors="ignore")
                       if src_yml.exists()
                       else 'fofaEmail: ""\nfofaKey: ""\n# 注释行应被保留\nceyeApi: ""\n',
                       encoding="utf-8")
        console_api._config_yaml_path = lambda: yml
        console_api._CONFIRMS.clear()
        config_io._ORIGINALS.clear()
        return self

    def __exit__(self, *a):
        (config.DATA_DIR, config.SCOPE_FILE, config_io.AUDIT_FILE,
         config_io.BACKUP_DIR, config_io.OVERRIDES_FILE,
         console_api._config_yaml_path) = self.saved
        console_api._CONFIRMS.clear()
        config_io._ORIGINALS.clear()


FIXTURE = {
    "_说明": (
        "【授权留痕】a.test 主域含子域：某某科技有限公司，补天公益 SRC 项目 cid=60001"
        "（用户 2026-09-01 明确给出 cid），仅只读轻量测试。"
        "b.test 主域含子域：北京示例科技有限公司（示例站官方站点），"
        "补天公益 SRC 项目 cid=60002（用户 2026-09-02 确认），仅只读轻量测试。"
        "c.test 主域含子域：补天公益 SRC 项目（用户 2026-09-03 确认属该项目、cid 待补），"
        "仅只读轻量测试。"),
    "domains": ["a.test", "b.test", "c.test", "d.test"],
}


def _write_fixture():
    config.SCOPE_FILE.write_text(json.dumps(FIXTURE, ensure_ascii=False, indent=2),
                                 encoding="utf-8")


# ============================================================ A 口令闸门
def test_a_gate():
    print("\n[A] 口令闸门（fail-closed）")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = ""
        with TestClient(app, base_url=LOOPBACK) as c:
            r = c.get("/api/console/overview")
            check("未设口令时 overview 被拒", r.status_code == 403, str(r.status_code))
            check("拒绝理由说清是「口令未设置」",
                  "口令未设置" in r.text and "fail-closed" in r.text, r.text[:120])
            check("拒绝理由给出配置方式",
                  "AGENT_CONSOLE_PASSWORD" in r.text and "consolePassword" in r.text)
            r = c.post("/api/console/login", json={"password": ""})
            check("未设口令时连登录都不给（不是空口令放行）",
                  r.status_code == 403, str(r.status_code))
            r = c.get("/api/console/scope")
            check("未设口令时 scope 读也被拒", r.status_code == 403)
            r = c.post("/api/console/scope/commit", json={"targets": []})
            check("未设口令时 commit 被拒（写路径同样 fail-closed）",
                  r.status_code == 403, str(r.status_code))
            r = c.get("/api/console/session")
            check("session 不需要鉴权（登录页要能问状态）", r.status_code == 200)
            check("session 如实报告口令未配置",
                  r.json().get("password_configured") is False)

        config.CONSOLE_PASSWORD = PW
        with TestClient(app, base_url=LOOPBACK) as c:
            r = c.get("/api/console/overview")
            check("设了口令但未登录 → 401（与 403 区分，要做的事不同）",
                  r.status_code == 401, str(r.status_code))
            r = c.get("/api/console/session")
            check("session 报告口令已配置、未登录",
                  r.json() == {"authenticated": False, "password_configured": True},
                  str(r.json()))
    finally:
        config.CONSOLE_PASSWORD = saved


# ============================================================ B 登录与票据
def test_b_login():
    print("\n[B] 登录与票据")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = PW
        with TestClient(app, base_url=LOOPBACK) as c:
            r = c.post("/api/console/login", json={"password": "wrong"})
            check("口令错 → 401", r.status_code == 401, str(r.status_code))
            check("口令错不签发 Cookie", "console_token" not in r.cookies)

            r = c.post("/api/console/login", json={"password": PW})
            check("口令对 → 200", r.status_code == 200, r.text[:80])
            check("签发 HttpOnly Cookie", "console_token" in r.cookies)
            check("Cookie 标记 HttpOnly", "httponly" in r.headers.get(
                "set-cookie", "").lower())
            check("Cookie 标记 SameSite=Strict", "samesite=strict" in r.headers.get(
                "set-cookie", "").lower())

            r = c.get("/api/console/session")
            check("登录后 session 为真", r.json().get("authenticated") is True)
            r = c.get("/api/console/scope")
            check("登录后可以读 scope", r.status_code == 200, str(r.status_code))

            # 伪造票据
            r = c.get("/api/console/scope",
                      cookies={"console_token": "9999999999.deadbeef"})
            check("伪造票据被拒", r.status_code == 401, str(r.status_code))
            r = c.get("/api/console/scope", cookies={"console_token": "1.x.y"})
            check("畸形票据被拒", r.status_code == 401)

            r = c.post("/api/console/logout")
            check("登出 → 200", r.status_code == 200)

        with TestClient(app, base_url=LOOPBACK) as c:
            c.cookies.clear()
            r = c.get("/api/console/scope")
            check("未带票据 → 401", r.status_code == 401)
    finally:
        config.CONSOLE_PASSWORD = saved


# ============================================================ C 读与干跑
def test_c_read_verify():
    print("\n[C] 白名单读取与干跑验证")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = PW
        with Sandbox() as _sb, TestClient(app, base_url=LOOPBACK) as c:
            _write_fixture()
            c.post("/api/console/login", json={"password": PW})

            r = c.get("/api/console/scope")
            d = r.json()["data"]
            check("读 scope 成功", r.status_code == 200)
            check("返回原始 domains", d["domains"] == FIXTURE["domains"], str(d["domains"]))
            check("尚未结构化时 targets 为 null", d["targets"] is None)
            check("旧写法下 consistent 为真", d["consistent"] is True)
            check("返回文件哈希供乐观锁用", bool(d["file"]["sha256_short"]))
            check("effective 里含端口/协议字段",
                  all({"host", "ports", "schemes"} <= set(x) for x in d["effective"]))

            # 干跑：这是本页最有价值的只读功能
            r = c.post("/api/console/scope/verify", json={"host": "a.test"})
            check("干跑已知授权域 → 放行",
                  r.status_code == 200 and r.json()["allowed"] is True, r.text[:100])
            r = c.post("/api/console/scope/verify", json={"host": "notyet.test"})
            check("干跑未授权域 → 拒绝",
                  r.status_code == 200 and r.json()["allowed"] is False)
            check("拒绝理由里带上白名单内容（便于排查）",
                  "白名单" in r.json()["reason"] or "不在授权" in r.json()["reason"])
            r = c.post("/api/console/scope/verify", json={"host": "mail.a.test"})
            check("干跑子域 → 放行（当前闸门一律含子域）",
                  r.json()["allowed"] is True)
            r = c.post("/api/console/scope/verify", json={"host": ""})
            check("干跑空 host → 400", r.status_code == 400)

            r = c.get("/api/console/overview")
            ov = r.json()
            check("overview 可读", r.status_code == 200)
            check("overview 含白名单条数", ov["scope"]["count"] == 4, str(ov["scope"]))
            check("overview 含工具统计", "scriptable" in ov["tools"])
            check("overview 含工具分级分布", bool(ov["tool_levels"]))
            check("overview 含超时口径与不变量",
                  "idle_below_total" in ov["timeouts"])
            check("overview 含编排参数", ov["orchestration"]["max_steps"] > 0)
            check("overview 报告口令已配置", ov["console"]["password_configured"] is True)
            check("overview 是无告警还是给了结构化告警",
                  isinstance(ov["warnings"], list))
            check("ENFORCE_SCOPE 关闭时会进告警列表",
                  config.ENFORCE_SCOPE or any("ENFORCE_SCOPE" in w["text"]
                                             for w in ov["warnings"]))
    finally:
        config.CONSOLE_PASSWORD = saved


# ============================================================ D preview 校验
def test_c2_structured_count():
    """[C2] 「结构化条目数」口径：数 raw targets，不能数合并视图的长度。

    实测踩到（2026-09-27 起服务跑端到端时）：总览把 7 个 host 显示成「结构化 14 条」——
    因为 `load_scope_targets()` 是 `domains` + `targets` 的**合并视图**，
    同一个 host 各出一条。数字本身不影响授权，但对运维界面是**误导**：
    看到「14 条」会以为有一批重复条目要清。
    """
    print("\n[C2] 总览「结构化条目数」口径")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = PW
        with Sandbox() as _sb, TestClient(app, base_url=LOOPBACK) as c:
            # 同一个 host 同时出现在 domains 与 targets → 合并视图会出 2 条
            config.SCOPE_FILE.write_text(json.dumps(
                {"domains": ["a.test"], "targets": [{"host": "a.test"}]},
                ensure_ascii=False), encoding="utf-8")
            c.post("/api/console/login", json={"password": PW})
            d = c.get("/api/console/overview").json()
            merged = len(scope.load_scope_targets())
            check("合并视图确实有 2 条（用例前提成立）", merged == 2, str(merged))
            check("总览报的结构化条数是 1（数 raw targets，不是合并视图）",
                  d["scope"]["structured"] == 1, str(d["scope"]))
            check("总览报的主机数是 1（合并视图已去重）",
                  d["scope"]["count"] == 1, str(d["scope"]))
    finally:
        config.CONSOLE_PASSWORD = saved


def test_d_preview_validation():
    print("\n[D] 提交前校验（不给「写了才发现坏」的机会）")
    saved = config.CONSOLE_PASSWORD
    ok = {"host": "new.test", "cid": "60010", "owner": "示例公司"}
    try:
        config.CONSOLE_PASSWORD = PW
        with Sandbox() as _sb, TestClient(app, base_url=LOOPBACK) as c:
            _write_fixture()
            c.post("/api/console/login", json={"password": PW})

            def pv(targets):
                return c.post("/api/console/scope/preview", json={"targets": targets})

            r = pv([ok])
            check("合法条目 → 200 且签发确认票据",
                  r.status_code == 200 and r.json()["confirm_token"], r.text[:120])
            check("合法条目风险等级为 high（有增删）", r.json()["level"] == "high")

            r = pv([])
            check("空白名单被拒（会导致所有工具被拒）", r.status_code == 400, r.text[:100])
            check("空白名单的拒绝理由说明了后果",
                  "白名单为空" in r.text or "都会被拒绝" in r.text, r.text[:140])

            r = pv([{"host": "http://x.test/"}, ])
            check("host 含协议/斜杠被拒", r.status_code == 400, r.text[:100])
            r = pv([{"host": "a.test"}, {"host": "A.TEST"}])
            check("host 重复（大小写归一后）被拒", r.status_code == 400, r.text[:100])
            r = pv([{"host": "x.test", "ports": [99999]}])
            check("端口越界被拒", r.status_code == 400, r.text[:100])
            r = pv([{"host": "x.test", "schemes": ["ftp"]}])
            check("协议非 http/https 被拒", r.status_code == 400, r.text[:100])
            r = pv([{"host": "x.test", "ports": []}])
            check("空的 ports 数组被拒（要么 null 要么非空）", r.status_code == 400, r.text[:100])

            # 「无增删」必须提交**与现状完全一致**的集合，否则 added/removed 非空、
            # 等级当然是 high。最初这条用例我提交了 [ok, a.test]，等于新增 new.test
            # 又删掉 b/c/d.test —— 那是三增一删，level=high 才是对的，是**用例写错了**。
            r = pv([{"host": h} for h in FIXTURE["domains"]])
            check("提交与现状一致的集合 → 无增删、风险等级为 low",
                  r.status_code == 200 and r.json()["level"] == "low"
                  and not r.json()["added"] and not r.json()["removed"], r.text[:160])
            r = pv([{"host": "a.test"}])
            check("移除条目时 diff 里列出被移除项",
                  r.status_code == 200 and "b.test" in r.json()["removed"],
                  r.text[:160])
    finally:
        config.CONSOLE_PASSWORD = saved


# ============================================================ E commit 强制
def test_e_commit_enforcement():
    print("\n[E] 写入的两道服务端强制（票据 + 乐观锁）")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = PW
        with Sandbox() as _sb, TestClient(app, base_url=LOOPBACK) as c:
            _write_fixture()
            c.post("/api/console/login", json={"password": PW})
            before_raw = config.SCOPE_FILE.read_text(encoding="utf-8")

            # ① 没有票据直接提交 → 必须被拒（否则「二次确认」只是前端装饰）
            r = c.post("/api/console/scope/commit",
                       json={"targets": [{"host": "evil.test"}], "expect_sha256": ""})
            check("无确认票据直接 commit → 400（绕过前端也挡得住）",
                  r.status_code == 400, f"{r.status_code} {r.text[:100]}")
            check("文件未被改动（拒绝是硬拒绝）",
                  config.SCOPE_FILE.read_text(encoding="utf-8") == before_raw)

            # ② 伪造票据
            r = c.post("/api/console/scope/commit",
                       json={"confirm_token": "made-up", "targets": [{"host": "evil.test"}]})
            check("伪造票据 → 400", r.status_code == 400, str(r.status_code))

            # ③ 正常走一遍：preview → commit
            new_targets = [{"host": "a.test", "cid": "60001", "owner": "某某科技有限公司"},
                           {"host": "b.test", "cid": "60002", "owner": "北京示例科技有限公司"},
                           {"host": "c.test"},
                           {"host": "d.test"},
                           {"host": "new.test", "cid": "60010", "owner": "示例公司"}]
            pv = c.post("/api/console/scope/preview", json={"targets": new_targets}).json()
            tok, sha = pv["confirm_token"], pv["expect_sha256"]

            # ④ 乐观锁：模拟「预览之后文件被手工改过」
            stale = "0" * len(sha)
            r = c.post("/api/console/scope/commit",
                       json={"confirm_token": tok, "expect_sha256": stale,
                             "targets": new_targets})
            check("哈希不匹配 → 409（防覆盖手工改动）", r.status_code == 409,
                  f"{r.status_code} {r.text[:100]}")
            check("409 理由说明是文件被改过后再写会覆盖",
                  "被改动过" in r.text or "覆盖" in r.text, r.text[:140])

            # ⑤ 票据是一次性的：上一步失败后票据已被消费，重放必须失败
            r = c.post("/api/console/scope/commit",
                       json={"confirm_token": tok, "expect_sha256": sha,
                             "targets": new_targets})
            check("票据一次性（消费后重放被拒）", r.status_code == 400, str(r.status_code))

            # ⑥ 重新预览并用正确哈希提交
            pv = c.post("/api/console/scope/preview", json={"targets": new_targets}).json()
            r = c.post("/api/console/scope/commit",
                       json={"confirm_token": pv["confirm_token"],
                             "expect_sha256": pv["expect_sha256"],
                             "targets": new_targets, "note_append": "控制台提交（测试）"})
            check("票据 + 哈希都正确 → 写入成功", r.status_code == 200, r.text[:140])
            body = r.json()
            check("返回备份文件名", bool(body.get("backup")), str(body.get("backup")))
            check("返回生效说明（reload 回显）",
                  bool(body["reload"]["actions"]), str(body["reload"]))

            # ⑦ 落盘结果
            disk = json.loads(config.SCOPE_FILE.read_text(encoding="utf-8"))
            check("targets 已落盘且数量正确", len(disk["targets"]) == 5)
            check("domains 兼容视图已同步",
                  sorted(disk["domains"]) == sorted(t["host"] for t in disk["targets"]),
                  str(disk["domains"]))
            check("_说明 原文保留未被改写",
                  disk["_说明"].startswith(FIXTURE["_说明"]))
            check("note_append 追加到了 _说明 末尾", "控制台提交（测试）" in disk["_说明"])

            # ⑧ 备份与审计真的落盘
            bks = list(config_io.BACKUP_DIR.glob("scope.*"))
            check("写前备份已生成", bool(bks), str(list(config_io.BACKUP_DIR.iterdir())))
            check("备份内容等于写前内容",
                  bks and bks[0].read_text(encoding="utf-8") == before_raw)
            check("审计文件已生成", config_io.AUDIT_FILE.exists())
            audit_txt = config_io.AUDIT_FILE.read_text(encoding="utf-8")
            check("审计记录含 scope/write 且等级为 high",
                  '"face": "scope"' in audit_txt and '"action": "write"' in audit_txt
                  and '"level": "high"' in audit_txt, audit_txt[:160])
            r = c.get("/api/console/audit")
            check("审计接口可读", r.status_code == 200 and r.json()["items"],
                  r.text[:100])
            r = c.get("/api/console/audit?face=scope")
            check("审计可按面过滤",
                  all(x["face"] == "scope" for x in r.json()["items"]))
            r = c.get("/api/console/audit/export")
            check("审计导出为 CSV", r.status_code == 200 and "text/csv" in
                  r.headers.get("content-type", ""), r.headers.get("content-type", ""))
            check("导出默认脱敏（不含完整域名）",
                  "new.test" not in r.text, r.text[:120])
            r = c.get("/api/console/audit/export?mask=0")
            check("mask=0 时导出全量", "new.test" in r.text, r.text[:120])
    finally:
        config.CONSOLE_PASSWORD = saved


# ============================================================ F 端到端生效
def test_f_end_to_end():
    print("\n[F] 端到端：写完真的生效（不只看接口返回 200）")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = PW
        with Sandbox() as _sb, TestClient(app, base_url=LOOPBACK) as c:
            _write_fixture()
            c.post("/api/console/login", json={"password": PW})

            check("写入前：new.test 未授权",
                  scope.check_scope("new.test") is not None)
            check("写入前：a.test 已授权",
                  scope.check_scope("a.test") is None)

            targets = [{"host": "a.test"}, {"host": "new.test"}]
            pv = c.post("/api/console/scope/preview", json={"targets": targets}).json()
            r = c.post("/api/console/scope/commit",
                       json={"confirm_token": pv["confirm_token"],
                             "expect_sha256": pv["expect_sha256"], "targets": targets})
            check("提交成功", r.status_code == 200, r.text[:120])

            # 关键：真实的授权闸门函数必须跟着变
            check("写入后：new.test 通过 check_scope（真的生效）",
                  scope.check_scope("new.test") is None,
                  str(scope.check_scope("new.test")))
            check("写入后：未在表内的 still.test 仍被拒",
                  scope.check_scope("still.test") is not None)
            check("写入后：被移除的 b.test 已被拒",
                  scope.check_scope("b.test") is not None)
            check("load_scope() 与 targets 一致",
                  sorted(scope.load_scope()) == ["a.test", "new.test"],
                  str(scope.load_scope()))
            check("结构化的 ports/schemes 仍被 check_scope 识别（未破坏 v012 P2-3）",
                  scope.check_scope("a.test") is None)
    finally:
        config.CONSOLE_PASSWORD = saved


# ============================================================ G 迁移器
def test_g_migrate():
    print("\n[G] 迁移器（domains + _说明 → 结构化 targets）")
    got = scope_migrate.parse_authorization_notes(
        FIXTURE["_说明"], ["a.test", "www.a.test", "b.test", "c.test", "d.test"])
    check("反解出 cid", got["a.test"]["cid"] == "60001", str(got["a.test"]))
    check("反解出授权主体", got["a.test"]["owner"] == "某某科技有限公司",
          str(got["a.test"]["owner"]))
    check("反解出授权日期", got["a.test"]["authorized_at"] == "2026-09-01")
    check("识别「主域含子域」", got["a.test"]["include_subdomains"] is True)
    check("反解出限制条件", "只读" in got["a.test"]["scope_note"],
          str(got["a.test"]["scope_note"]))
    check("子域写法能认到主域的留痕（www.a.test → a.test 那条）",
          got["www.a.test"]["cid"] == "60001")
    check("带括号的站点说明不影响主体解析",
          got["b.test"]["owner"] == "北京示例科技有限公司",
          str(got["b.test"]["owner"]))
    check("「cid 待补」不算有效 cid", got["c.test"]["cid"] == "")
    check("「cid 待补」被记进备注，不是静默丢弃",
          "待补" in got["c.test"]["scope_note"], str(got["c.test"]))
    check("没有留痕的域也返回一条并标待复核",
          got["d.test"]["needs_review"] is True and got["d.test"]["source_sentence"] == "")
    check("cid 与主体齐备的条目不标待复核", got["a.test"]["needs_review"] is False)
    check("缺主体的条目标待复核（cid 齐也不行）",
          got["a.test"]["needs_review"] is False)
    check("代词「补天…」不会被当主体名",
          got["c.test"]["owner"] == "", str(got["c.test"]["owner"]))

    new, rep = scope_migrate.plan(FIXTURE)
    check("plan 保留 _说明 原文", new["_说明"].startswith(FIXTURE["_说明"]))
    check("plan 追加了指向 targets 的说明段", "结构化条目" in new["_说明"])
    check("plan 同步 domains", new["domains"] == FIXTURE["domains"], str(new["domains"]))
    check("plan 报告统计正确",
          rep["hosts"] == 4 and rep["with_cid"] == 2 and rep["with_owner"] == 2,
          str(rep))
    check("plan 列出待复核清单",
          set(rep["needs_review"]) == {"c.test", "d.test"}, str(rep["needs_review"]))
    check("plan 结果通过结构校验", scope_migrate.validate(new) == [],
          str(scope_migrate.validate(new)))
    check("plan 幂等：对已结构化的结果再跑一次不丢字段",
          scope_migrate.plan(new)[0]["targets"][0]["cid"] == "60001")

    check("校验：host 含斜杠 → 报问题",
          any("非法字符" in p for p in
              scope_migrate.validate({"targets": [{"host": "a/b"}]})))
    check("校验：host 重复 → 报问题",
          any("重复" in p for p in
              scope_migrate.validate({"targets": [{"host": "a.test"}, {"host": "a.test"}]})))
    check("校验：缺 host → 报问题",
          any("缺 host" in p for p in scope_migrate.validate({"targets": [{}]})))
    check("校验：旧写法（只有 domains）合法",
          scope_migrate.validate({"domains": ["a.test"]}) == [])
    check("校验：schemes 非 http/https → 报问题",
          any("schemes" in p for p in scope_migrate.validate(
              {"targets": [{"host": "a.test", "schemes": ["ftp"]}]})))


# ============================================================ H 红线与接线
def test_h_wiring_and_redlines():
    print("\n[H] 接线、红线与防泄露")

    # ---- gitignore 必须盖住两个新文件（审计里有真实 host） ----
    gi = read(".gitignore")
    check("gitignore 含 console_audit.jsonl", "data/console_audit.jsonl" in gi)
    check("gitignore 含 console_backups/", "data/console_backups/" in gi)
    check("gitignore 含 runtime_overrides.json", "data/runtime_overrides.json" in gi)

    # ---- 真的被 git 忽略？（git check-ignore 是权威判据） ----
    import subprocess
    git = r"D:\Git\cmd\git.exe"
    for rel in ("data/console_audit.jsonl", "data/runtime_overrides.json"):
        try:
            r = subprocess.run([git, "check-ignore", "-q", rel], cwd=REPO,
                               capture_output=True, timeout=20)
            check(f"git 确认忽略 {rel}", r.returncode == 0, f"rc={r.returncode}")
        except Exception as e:                                 # noqa: BLE001
            check(f"git 确认忽略 {rel}", False, str(e))

    # ---- main.py 只加挂载，不动既有路由 ----
    mn = read("app/main.py")
    check("main.py 挂了 console router",
          'include_router(console_api.router, prefix="/api/console"' in mn)
    check("main.py 提供 /console 前端路由", '@app.get("/console")' in mn)
    check("main.py 挂载 console 静态目录",
          'app.mount("/console-assets"' in mn)
    check("既有 / 与 /static 未被改动",
          '@app.get("/")' in mn and 'app.mount("/static"' in mn)
    check("console 复用 main 的 MCP 健康检查（不另写一份导致漂移）",
          "from .main import _mcp_health" in read("app/console_api.py"))
    check("console 复用 fofa 的扁平 yaml 解析器（不另写一份）",
          "from .fofa import _parse_flat_yaml" in read("app/console_api.py"))

    # ---- 不新造确认通道 ----
    ca = read("app/console_api.py")
    # 判据要落在「有没有真的实现一个确认路由」，而不是「代码里出没出现 auth_ack 字样」——
    # 后者连注释里的解释性提及都会算违规（我第一版就是这么写的，假红一次）。
    check("console 未自行实现会话确认路由（确认双闸门必须走既有接口）",
          not _re.search(r'@router\.post\(\"[^\"]*confirm', ca))
    check("console 未自行实现 SSE 流（应透传既有接口）",
          not _re.search(r'@router\.get\(\"[^\"]*stream', ca))
    check("console 不发起目标流量（verify 只做本地匹配）",
          "httpx" not in ca and "safe_http_request" not in ca)

    # ---- 前端独立目录，零构建 ----
    for f in ("console/index.html", "console/console.css", "console/core.js",
              "console/views/overview.js", "console/views/scope.js",
              "console/views/audit.js", "console/views/_placeholder.js"):
        check(f"前端文件存在：{f}", (REPO / f).exists())
    check("前端不引 CDN / 第三方库",
          "http://" not in read("console/core.js")
          and "https://" not in read("console/core.js"))
    check("前端占位页说明了「现在该改哪个文件」（不是坏页面）",
          "当前请直接编辑" in read("console/views/_placeholder.js"))
    check("白名单页明确说明「不含子域」开关本版不提供",
          "假承诺" in read("console/views/scope.js"))

    # ---- 本版文件不含靶标词干 ----
    scope_file = REPO / "data" / "scope.json"
    if scope_file.exists():
        try:
            domains = json.loads(scope_file.read_text(encoding="utf-8")).get("domains") or []
        except Exception:                                      # noqa: BLE001
            domains = []
        stems = []
        for d in domains:
            if isinstance(d, str) and "." in d:
                s = d.split(".")[0].lower()
                if len(s) >= 4 and s != "discuz" and s not in stems:
                    stems.append(s)
        hits = []
        for rel in ("app/console_api.py", "app/config_io.py", "app/scope_migrate.py",
                    "console/index.html", "console/core.js",
                    "console/views/scope.js", "console/views/overview.js",
                    "console/views/audit.js", "console/views/_placeholder.js",
                    "migrate_scope.py", "test_console_api.py"):
            t = read(rel).lower()
            for s in stems:
                if s in t:
                    hits.append(f"{rel}⊃{s}")
        check(f"本版文件不含靶标词干（查了 {len(stems)} 个词干）", not hits, str(hits))
    else:
        check("scope.json 不存在 → 防泄露检查跳过", True)


def test_j_tools_edit():
    """[J] 工具与分级：白名单字段、必填理由、禁改闸门参数、双文件乐观锁。"""
    print("\n[J] 工具与分级（写入 risk_grades + tool_overrides 两个文件）")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = PW
        with Sandbox(seed=("risk_grades.json", "tool_overrides.json")) as _sb, \
                TestClient(app, base_url=LOOPBACK) as c:
            c.post("/api/console/login", json={"password": PW})
            r = c.get("/api/console/tools")
            d = r.json()
            check("工具清单可读", r.status_code == 200 and len(d["items"]) > 100,
                  str(len(d.get("items", []))))
            check("清单不重复（load 必须幂等 —— 每次提交都会重载它）",
                  len(d["items"]) == len({x["alias"] for x in d["items"]}),
                  f'{len(d["items"])} vs {len({x["alias"] for x in d["items"]})}')
            check("带两个文件的哈希（乐观锁用）",
                  bool(d["files"]["grades"]["sha256_short"])
                  and bool(d["files"]["overrides"]["sha256_short"]))
            check("返回可改字段白名单", "disabled" in d["editable_fields"])
            it = d["items"][0]
            check("每条带 in_model_list / scriptable / has_override",
                  {"in_model_list", "scriptable", "has_override"} <= set(it))

            # 找一个可编排工具做实验（非可编排的改分级应被拒）
            scr = [x for x in d["items"] if x["scriptable"]][0]
            ali = scr["alias"]
            name = scr["name"]

            # ---- 正例：只改分级 ----
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali, "grade": {"level": "L1", "reason": "测试预演"}})
            check("改分级可预览", r.status_code == 200, r.text[:120])
            tok = r.json().get("confirm_token", "")
            hashes = r.json().get("expect_sha256", {})
            check("返回两个文件的哈希", set(hashes) == {"grades", "overrides"}, str(hashes))

            # ---- 反例：不改理由 ----
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali, "grade": {"level": "L1"}})
            check("改分级不填理由被拒", r.status_code == 400 and "reason" in r.text,
                  r.text[:100])

            # ---- 反例：非法等级 ----
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali, "grade": {"level": "L9", "reason": "x"}})
            check("非法风险等级被拒", r.status_code == 400, r.text[:100])

            # ---- 反例：闸门参数不许从工具页改 ----
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali, "overrides": {"network_control": {"declared": True}}})
            check("不允许改 network_control（闸门参数）",
                  r.status_code == 400 and "闸门参数" in r.text, r.text[:130])
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali, "overrides": {"stdin_input": "1"}})
            check("不允许改 stdin_input", r.status_code == 400, r.text[:100])

            # ---- 反例：禁用必须写理由 ----
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali, "overrides": {"disabled": True}})
            check("禁用不填理由被拒", r.status_code == 400 and "reason" in r.text,
                  r.text[:110])

            # ---- 正例：禁用 + 理由 ----
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali,
                             "overrides": {"disabled": True, "reason": "测试：脚本不可用"}})
            check("禁用 + 理由可预览", r.status_code == 200, r.text[:120])
            tok2, hash2 = r.json()["confirm_token"], r.json()["expect_sha256"]

            # ---- 无票据提交被拒 ----
            r = c.post("/api/console/tools/commit", json={"alias": ali, "expect_sha256": hash2})
            check("无票据提交被拒", r.status_code == 400, str(r.status_code))

            # ---- 正常提交（用 tok2）----
            # 注意：上面那次「无票据」提交**没有消费 tok2**（它在校验 token 时就抛了），
            # 所以 tok2 仍然有效。原来我在这里写「上次已消费掉 tok2」是**错的** ——
            # 重放会成功，而成功才是正确行为（用例前提写错导致的假红）。
            r = c.post("/api/console/tools/commit",
                       json={"alias": ali,
                             "overrides": {"disabled": True, "reason": "测试：脚本不可用"},
                             "confirm_token": tok2, "expect_sha256": hash2})
            check("提交成功", r.status_code == 200, r.text[:140])
            body = r.json()
            # 真正的「一次性」验证：拿刚用过的票据再交一次
            r = c.post("/api/console/tools/commit",
                       json={"alias": ali,
                             "overrides": {"disabled": True, "reason": "测试：脚本不可用"},
                             "confirm_token": tok2, "expect_sha256": hash2})
            check("票据一次性（用过的票据重放被拒）", r.status_code == 400,
                  str(r.status_code))
            check("只写了 overrides 一个文件", body["written"] == ["tool_overrides.json"],
                  str(body["written"]))
            check("回显重载结果（改了没生效就白改）",
                  bool(body["reload"]["actions"]), str(body["reload"]))
            # ---- 关键：重载后真的生效 ----
            from app.registry import registry as _reg
            t = _reg.get_by_alias(ali)
            check("重载后该工具真的被禁用", t is not None and t.disabled,
                  str(t.disabled if t else "工具不存在"))
            check("重载后清单仍不重复（幂等）",
                  len(_reg.tools) == len({x.alias for x in _reg.tools}))
            check("被禁用的工具已不在模型清单",
                  ali not in {x.alias for x in _reg.usable_scriptable()})

            # ---- 乐观锁：文件被手工改过 ----
            r = c.post("/api/console/tools/preview",
                       json={"alias": ali, "overrides": {"timeout": 42}})
            tok4, hash4 = r.json()["confirm_token"], dict(r.json()["expect_sha256"])
            hash4["overrides"] = "0" * len(hash4["overrides"])
            r = c.post("/api/console/tools/commit",
                       json={"alias": ali, "overrides": {"timeout": 42},
                             "confirm_token": tok4, "expect_sha256": hash4})
            check("overrides 哈希不符 → 409", r.status_code == 409, str(r.status_code))
    finally:
        config.CONSOLE_PASSWORD = saved


def test_k_params():
    """[K] 运行参数：白名单、取值域、跨值不变量、**热生效**、复位语义。"""
    print("\n[K] 运行参数与闸门（热生效，不用重启）")
    from app import param_spec as ps
    saved = config.CONSOLE_PASSWORD
    orig_steps = config.MAX_STEPS
    try:
        config.CONSOLE_PASSWORD = PW
        # ---- 规格自洽（不依赖服务）----
        check("规格表非空且分组有序", len(ps.SPECS) >= 20 and ps.groups())
        noenv = [s["key"] for s in ps.SPECS if not ps.env_name(s["key"])]
        check("每个规格项都能从 config.py 解析到环境变量名（不猜）", not noenv, str(noenv))
        nodef = [s["key"] for s in ps.SPECS if ps.default_value(s["key"]) is None]
        check("每个规格项都能解析到默认值", not nodef, str(nodef))
        check("排除项都写了理由", all(e.get("why") for e in ps.EXCLUDED))
        check("HOST/PORT 在排除表里（运行时改它们不会换端口 —— 列出来就是界面说谎）",
              any("HOST" in e["key"] for e in ps.EXCLUDED))
        check("CONSOLE_PASSWORD 在排除表里（循环依赖）",
              any("CONSOLE_PASSWORD" in e["key"] for e in ps.EXCLUDED))

        with Sandbox() as _sb, TestClient(app, base_url=LOOPBACK) as c:
            c.post("/api/console/login", json={"password": PW})
            r = c.get("/api/console/params")
            d = r.json()
            check("参数页可读", r.status_code == 200)
            check("分组与项数完整",
                  len(d["groups"]) >= 5 and sum(len(g["items"]) for g in d["groups"]) == len(ps.SPECS))
            it = d["groups"][0]["items"][0]
            check("每项带 当前值/默认值/来源/取值域",
                  {"value", "default", "source", "min", "max"} <= set(it), str(it.keys()))
            check("返回排除清单（否则会被当成漏了）", len(d["excluded"]) >= 3)
            check("声明热生效", d["hot"] is True)

            # ---- 反例 ----
            r = c.post("/api/console/params/preview", json={"values": {"MAX_STEPS": 99999}})
            check("超范围被拒", r.status_code == 400, r.text[:100])
            r = c.post("/api/console/params/preview",
                       json={"values": {"MAX_STEPS": "abc"}})
            check("类型错被拒", r.status_code == 400, r.text[:100])
            r = c.post("/api/console/params/preview", json={"values": {"HOST": "0.0.0.0"}})
            check("白名单外的参数被拒（含可操作的提示）",
                  r.status_code == 400 and "白名单" in r.text, r.text[:120])
            r = c.post("/api/console/params/preview",
                       json={"values": {"EXECUTION_MODE": "turbo"}})
            check("枚举非法被拒", r.status_code == 400, r.text[:100])
            # 跨值不变量：既有的 timeout_warnings + 我补的那几条
            r = c.post("/api/console/params/preview",
                       json={"values": {"TOOL_IDLE_TIMEOUT": 900}})
            check("触发 idle>=total 不变量被拒",
                  r.status_code == 400 and "口径异常" in r.text, r.text[:150])
            r = c.post("/api/console/params/preview",
                       json={"values": {"PY_EXEC_TIMEOUT": 30}})
            check("触发 py_exec<idle 倒挂被拒",
                  r.status_code == 400 and "倒挂" in r.text, r.text[:150])
            r = c.post("/api/console/params/preview",
                       json={"values": {"FAILURE_SWITCH_THRESHOLD": 9}})
            check("触发 switch>=stop 被拒", r.status_code == 400, r.text[:120])
            r = c.post("/api/console/params/preview", json={"values": {}})
            check("空改动被拒", r.status_code == 400, r.text[:80])

            # ---- 正例：提交后热生效 ----
            r = c.post("/api/console/params/preview", json={"values": {"MAX_STEPS": 12}})
            check("合法改动可预览", r.status_code == 200, r.text[:120])
            prev = r.json()
            check("风险等级为 mid（非闸门参数）", prev["level"] == "mid", prev["level"])
            r = c.post("/api/console/params/commit",
                       json={"values": {"MAX_STEPS": 12},
                             "confirm_token": prev["confirm_token"],
                             "expect_sha256": prev["expect_sha256"]})
            check("提交成功", r.status_code == 200, r.text[:140])
            check("回显即时生效项", r.json().get("applied") == ["MAX_STEPS"],
                  str(r.json().get("applied")))
            # 关键：**调用点**看到的值必须跟着变（不是只改了配置文件）
            check("config.MAX_STEPS 立即变为 12（热生效）", config.MAX_STEPS == 12,
                  str(config.MAX_STEPS))
            check("覆盖文件已落盘",
                  config_io.read_json(config_io.OVERRIDES_FILE, {}).get("params", {})
                  .get("MAX_STEPS") == 12)
            # 来源应变为 runtime
            r = c.get("/api/console/params")
            item = [x for g in r.json()["groups"] for x in g["items"]
                    if x["key"] == "MAX_STEPS"][0]
            check("来源标记为控制台覆盖", item["source"] == "runtime", item["source"])

            # ---- 关闸门类：高危 ----
            r = c.post("/api/console/params/preview", json={"values": {"ENFORCE_SCOPE": False}})
            check("改安全闸门标记为 high", r.json().get("level") == "high",
                  str(r.json().get("level")))

            # ---- 复位语义：删覆盖 ≠ 写默认 ----
            r = c.post("/api/console/params/preview", json={"reset": ["MAX_STEPS"]})
            check("复位可预览", r.status_code == 200, r.text[:120])
            prev = r.json()
            r = c.post("/api/console/params/commit",
                       json={"reset": ["MAX_STEPS"],
                             "confirm_token": prev["confirm_token"],
                             "expect_sha256": prev["expect_sha256"]})
            check("复位提交成功", r.status_code == 200, r.text[:120])
            check("复位后 config 回到原值", config.MAX_STEPS == orig_steps,
                  f"{config.MAX_STEPS} vs {orig_steps}")
            check("复位是**删掉**覆盖项而不是写默认值",
                  "MAX_STEPS" not in (config_io.read_json(
                      config_io.OVERRIDES_FILE, {}).get("params") or {}),
                  str(config_io.read_json(config_io.OVERRIDES_FILE, {})))
    finally:
        config.MAX_STEPS = orig_steps
        config.CONSOLE_PASSWORD = saved


def test_l_rules_templates_secrets():
    """[L] 合规红线 / 调用模板 / 本机密钥。"""
    print("\n[L] 合规红线 · 调用模板 · 本机密钥")
    saved = config.CONSOLE_PASSWORD
    try:
        config.CONSOLE_PASSWORD = PW
        with Sandbox(seed=("rules/compliance-redlines.md", "invocation_templates.json")) \
                as sb, TestClient(app, base_url=LOOPBACK) as c:
            c.post("/api/console/login", json={"password": PW})

            # ---- 红线 ----
            r = c.get("/api/console/rules")
            d = r.json()
            old_text = d["text"]
            check("红线可读", r.status_code == 200 and len(old_text) > 100,
                  str(len(old_text)))
            check("按 ## 分节", len(d["sections"]) >= 2, str(len(d["sections"])))
            r = c.post("/api/console/rules/preview", json={"text": ""})
            check("拒绝把红线清空（等于移除纪律约束）",
                  r.status_code == 400 and "清空" in r.text, r.text[:110])
            r = c.post("/api/console/rules/preview", json={"text": old_text})
            check("内容无变化被拒", r.status_code == 400, r.text[:80])
            r = c.post("/api/console/rules/preview", json={"text": old_text + "\n\n## 新增章节\n测试。"})
            check("红线可预览", r.status_code == 200, r.text[:100])
            prev = r.json()
            check("预览带 diff 与行数统计",
                  "hunks" in prev and "before_lines" in prev["stats"])
            r = c.post("/api/console/rules/commit",
                       json={"text": old_text + "\n\n## 新增章节\n测试。",
                             "confirm_token": prev["confirm_token"],
                             "expect_sha256": prev["expect_sha256"]})
            check("红线提交成功", r.status_code == 200, r.text[:120])
            check("红线文件真的写入了",
                  "新增章节" in config_io.read_text(console_api._rules_path()))
            check("审计记了这次改动",
                  any(x["face"] == "rules" for x in
                      config_io.read_audit(limit=50)))

            # ---- 调用模板 ----
            r = c.get("/api/console/templates")
            d = r.json()
            check("模板可读", r.status_code == 200 and len(d["items"]) > 0,
                  str(len(d.get("items", []))))
            check("带 target 合法取值清单", "url" in d["targets"])
            items = d["items"]
            bad = [dict(x, cmd="{args} {target}") for x in items[:1]]
            r = c.post("/api/console/templates/preview", json={"items": bad})
            check("cmd 缺 {exe} 被拒", r.status_code == 400 and "exe" in r.text,
                  r.text[:110])
            bad2 = [dict(items[0], target="ftp")]
            r = c.post("/api/console/templates/preview", json={"items": bad2})
            check("target 非法取值被拒", r.status_code == 400, r.text[:110])
            # 新增一条
            new_items = items + [{"alias": "zz_test_tool", "cmd": "{exe} {args} {target}",
                                  "target": "raw"}]
            r = c.post("/api/console/templates/preview", json={"items": new_items})
            check("新增模板可预览", r.status_code == 200, r.text[:110])
            prev = r.json()
            check("预览列出新增项", "zz_test_tool" in prev["added"], str(prev["added"]))
            r = c.post("/api/console/templates/commit",
                       json={"items": new_items, "confirm_token": prev["confirm_token"],
                             "expect_sha256": prev["expect_sha256"]})
            check("模板提交成功", r.status_code == 200, r.text[:120])
            saved_tpl = config_io.read_json(console_api._templates_path(), {}) or {}
            check("模板真的写入了", "zz_test_tool" in saved_tpl)
            check("_说明 等元键被保留（不能被整表覆盖掉）",
                  "_说明" in saved_tpl, str(list(saved_tpl)[:3]))

            # ---- 密钥 ----
            # 把临时 config.yaml 写成确定内容：真实 config.yaml 存在（含用户密钥），
            # 直接复制会让下面「注释是否保留」的断言依赖真实文件里恰好有注释 —— 那是脆的。
            (sb.tmp / "config.yaml").write_text(
                "# 本机个人配置（注释行必须保留）\n"
                "fofaEmail: \"\"\n"
                "fofaKey: \"\"\n"
                "fofaSize: 100\n"
                "customUnknownKey: keep-me\n",
                encoding="utf-8")
            r = c.get("/api/console/secrets")
            d = r.json()
            check("密钥可读", r.status_code == 200 and len(d["items"]) == 5)
            check("不下发明文（只有 has_value 与打码）",
                  all("masked" in x and "value" not in x for x in d["items"]),
                  str(d["items"][0]))
            r = c.post("/api/console/secrets/commit",
                       json={"values": {"notAllowedKey": "x"}})
            check("白名单外的键被拒", r.status_code == 400, r.text[:110])
            r = c.post("/api/console/secrets/commit",
                       json={"values": {"fofaEmail": "a@example.test",
                                        "fofaKey": "key-with:colon#hash"}})
            check("合法键可写", r.status_code == 200, r.text[:120])
            yml = (sb.tmp / "config.yaml").read_text(encoding="utf-8")
            check("值已写入 config.yaml", "a@example.test" in yml and "fofaKey:" in yml)
            check("含冒号/井号的值被引号包住（否则扁平解析器会把行拆坏）",
                  '"key-with:colon#hash"' in yml, yml[:200])
            check("其它行与注释被保留（只改指定键的值）",
                  "# 本机个人配置（注释行必须保留）" in yml and "fofaSize: 100" in yml
                  and "customUnknownKey: keep-me" in yml, yml[:260])
            r = c.get("/api/console/secrets")
            check("回读显示已填且打码", any(x["key"] == "fofaEmail" and x["has_value"]
                                      for x in r.json()["items"]))
            check("审计不记录密钥值",
                  "a@example.test" not in config_io.read_text(config_io.AUDIT_FILE))
    finally:
        config.CONSOLE_PASSWORD = saved


def test_m_registry_idempotent():
    """[M] `registry.load()` 必须幂等 —— 控制台的「改完重载」会反复调它。"""
    print("\n[M] registry.load() 幂等（P2 的重载路径依赖它）")
    from app.registry import ToolRegistry
    r = ToolRegistry()
    counts = []
    for _ in range(3):
        r.load()
        counts.append((len(r.tools), len(r._by_alias)))
    check("连续 3 次 load 的工具数完全一致（原来会 211→408→605 线性膨胀）",
          len({c[0] for c in counts}) == 1, str(counts))
    check("tools 列表与 by_alias 视图规模一致（原来两者矛盾）",
          all(a == b for a, b in counts), str(counts))
    check("errors 不会累积", len(r.errors) == 0, str(r.errors[:2]))


def test_i_ui_regressions():
    """[I] 前端两个「第一次真用就中」的缺陷（v050.1 / v050.2）。

    这两个都不是逻辑错误，而是**平台机制**踩坑，靠读代码很难发现，
    所以各留一条守卫：

    1. **`hidden` 被 CSS 的 `display` 覆盖**（用户截图报的正是这个）：
       `hidden` 靠 UA 样式表 `[hidden] { display: none }` 生效，而**作者样式的
       `display` 会压过 UA 样式**。`console.css` 里 `.app` / `.modal-mask` /
       `.login-mask` / `.ack` 都写了 `display: flex` —— 于是它们上面的 `hidden`
       完全失效：一进 /console 就有「确认」弹窗盖在登录卡上，
       而且点「关闭/取消/确认提交」都没反应（关弹窗就是设 `hidden=true`，同样被压过）。
       → 守卫：必须存在 `[hidden] { display: none !important }`。

    2. **`/console-assets/` 没被 `no-cache` 覆盖**：中间件原本只判 `/static`，
       于是控制台改完 CSS 后**用户浏览器一直吃缓存里的旧样式**，
       现象是「你按说的修了，但我这边还是坏的」（2026-09-18 线索图黑块事故同源）。
       → 守卫：真实请求该路径必须带 `Cache-Control: no-cache`。
    """
    print("\n[I] 前端机制类缺陷的守卫")
    css = read("console/console.css")
    html = read("console/index.html")

    check("console.css 含 [hidden] 强制隐藏规则（否则 hidden 会被 display 压过）",
          "[hidden]" in css and "display: none !important" in css,
          "缺 `[hidden] { display: none !important; }`")
    check("该规则确实用了 !important（不加会被同文件的 display: flex 压过）",
          "display: none !important" in css)

    # 反向：index.html 里所有带 hidden 的元素，其 class 在 CSS 里都设过 display
    # → 正是需要这条守卫的场景。列出来是为了失败时能一眼看出影响面。
    cls_with_hidden = sorted({m for m in _re.findall(
        r'class="([^"]+)"[^>]*\shidden', html)})
    display_rules = {c for c in cls_with_hidden
                     if _re.search(r"\." + _re.escape(c.split()[0]) + r"\s*\{[^}]*display\s*:",
                                   css)}
    check("确实存在「带 hidden 且其 class 设了 display」的元素（用例前提成立）",
          bool(display_rules), f"带 hidden 的 class={cls_with_hidden}")
    check("因此必须先有 [hidden] 守卫才安全（两者同时成立即正确）",
          bool(css.count("display: none !important")))

    # ---- 真实请求验证 no-cache（走中间件，不只看源码）----
    with TestClient(app, base_url=LOOPBACK) as c:
        r = c.get("/console-assets/console.css")
        check("console.css 可取", r.status_code == 200, str(r.status_code))
        check("/console-assets/ 带 Cache-Control: no-cache（否则用户看不到修复）",
              r.headers.get("cache-control") == "no-cache",
              f"实得 {r.headers.get('cache-control')!r}")
        r2 = c.get("/static/style.css")
        check("既有 /static 的 no-cache 未被破坏",
              r2.status_code in (200, 404)
              and (r2.status_code == 404
                   or r2.headers.get("cache-control") == "no-cache"),
              f"{r2.status_code} {r2.headers.get('cache-control')!r}")

    # ---- 资源版本号：改了前端就必须升版本，否则老缓存继续生效 ----
    asset_refs = _re.findall(r"/console-assets/[^'\"\s]+", html + read("console/core.js"))
    unversioned = [x for x in asset_refs
                   if x.endswith((".js", ".css")) and "?v=" not in x]
    check("所有 console 资源引用都带版本号（升版本才能绕过旧缓存）",
          not unversioned, str(unversioned))


def main() -> int:
    print("=" * 68)
    print("v051 配置控制台回归（P1 白名单 + P2 工具分级·运行参数·合规模板）")
    print("=" * 68)
    test_a_gate()
    test_b_login()
    test_c_read_verify()
    test_c2_structured_count()
    test_d_preview_validation()
    test_e_commit_enforcement()
    test_f_end_to_end()
    test_g_migrate()
    test_h_wiring_and_redlines()
    test_i_ui_regressions()
    test_j_tools_edit()
    test_k_params()
    test_l_rules_templates_secrets()
    test_m_registry_idempotent()
    print("\n" + "=" * 68)
    print(f"结果：{PASS} 通过 / {FAIL} 失败")
    print("=" * 68)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
