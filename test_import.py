# -*- coding: utf-8 -*-
"""v017.1 请求导入回归：Burp XML / HAR 解析、脱敏、去重、scope 过滤、入库。

    python test_import.py

离线：数据库与 scope.json 改道临时目录，不联网。
"""
import base64
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_imp_test_"))
config.DATA_DIR = _TMP
scope_file = _TMP / "scope_v017.json"
# scope：example.com + example.com:8443 限定；evil.com 用于验证越权拒绝
scope_file.write_text('{"targets": [{"host": "example.com"}], "domains": ["jiaoyu.cn"]}',
                      encoding="utf-8")
config.SCOPE_FILE = scope_file

import importlib                                         # noqa: E402
from app import store                                    # noqa: E402
importlib.reload(store)
store.DB_PATH = _TMP / "projects.db"
store.init_db()
from app.importers import common, burp_xml, har          # noqa: E402

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
print("== A. 原始 HTTP 报文解析 ==")
raw1 = ("GET /api/user/12345/profile?detail=full HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer sk-abc123secret\r\n"
        "Cookie: SESSIONID=abcd1234; theme=dark\r\n"
        "User-Agent: test\r\n\r\n")
p = common.parse_raw_http(raw1.encode())
check("请求行解析", p["method"] == "GET" and "/api/user/12345/profile" in p["url"])
check("Host 合成 URL", p["url"].startswith("https://example.com"))
check("头解析完整", p["headers"].get("Authorization") == "Bearer sk-abc123secret")

print("== B. 脱敏 ==")
rh = common.redact_headers(p["headers"])
check("Authorization 被打码", "<redacted:" in rh.get("Authorization", ""))
check("普通头保留", rh.get("User-Agent") == "test")
ck = common.split_cookies(p["headers"]["Cookie"])
check("Cookie 值打码但键名保留", "SESSIONID" in ck and "<redacted:" in ck["SESSIONID"])
check("theme 非敏感 Cookie 也统一打码（凭据不区分对待）", "<redacted:" in ck.get("theme", ""))

print("== C. 规范化与去重键 ==")
n1 = common.normalize_url("https://example.com/api/user/12345/profile?detail=full&_t=9")
n2 = common.normalize_url("https://example.com/api/user/99999/profile?detail=brief&_t=1")
check("路径数字归一 {n}", "/api/user/{n}/profile" in n1)
check("不同实例归一后相同（去重生效）", n1 == n2)
k1 = common.dedup_key("GET", "https://example.com/api/user/1?id=2", '{"userId": 2}')
k2 = common.dedup_key("GET", "https://example.com/api/user/2?id=3", '{"userId": 3}')
check("JSON body 值不影响去重键", k1 == k2)
k3 = common.dedup_key("GET", "https://example.com/api/user/1?id=2", "")
check("有无 body 去重键不同", k1 != k3)

print("== D. 对象候选识别 ==")
cands = common.object_candidates(
    "https://example.com/api/order/88123/detail",
    {"userId": "20001", "page": "1"}, '{"orderId": 9001}')
fields = {(c["field"], c["location"]) for c in cands}
check("query 语义键 userId → high", ("userId", "query") in fields)
check("路径语义段 order/88123 → high", any(c["field"] == "order" and c["location"] == "path"
                                          for c in cands))
check("body 键 orderId → high", ("orderId", "body") in fields)
check("噪声键 page 不入选", ("page", "query") not in fields)
masked = [c for c in cands if c["field"] == "userId"][0]["value_masked"]
check("候选值脱敏（中间打码）", "***" in masked)

print("== E. Burp XML 导入 ==")
burp_xml_text = f"""<?xml version="1.0"?>
<items burpVersion="2026.1" exportTime="2026-09-18">
  <item>
    <url>https://example.com/api/user/12345/profile</url>
    <host ip="1.2.3.4">example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api/user/12345/profile</path>
    <extension>null</extension>
    <request base64="true">{b64(raw1)}</request>
    <status></status>
    <response base64="false"></response>
  </item>
  <item>
    <url>https://evil.com/admin</url>
    <host ip="5.6.7.8">evil.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method>GET</method>
    <path>/admin</path>
    <request base64="true">{b64('GET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n')}</request>
    <status>200</status>
  </item>
  <item>
    <url>https://example.com/api/user/12345/profile?detail=full</url>
    <host ip="1.2.3.4">example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api/user/12345/profile?detail=full</path>
    <request base64="true">{b64(raw1)}</request>
    <status>200</status>
  </item>
</items>"""
records, stat = common.parse_import_file("burp_export.xml", b64(burp_xml_text))
check("解析 3 条", stat["total"] == 3, stat)
check("allowed 2 条 / rejected 1 条（evil.com 被拒）",
      stat["allowed"] == 2 and stat["rejected"] == 1, stat)
check("重复 1 条", stat["duplicates"] == 1, stat)
statuses = [r["scope_status"] for r in records]
check("rejected 标记不进执行队列", statuses.count("rejected") == 1)
check("无解析错误", stat["parse_errors"] == 0)

# 坏文件
bad, bad_stat = None, None
try:
    common.parse_import_file("x.xml", b64("not a xml <<<"))
except ValueError:
    pass
records_bad, stat_bad = common.parse_import_file("x.xml", b64("<items><item><request base64=\"true\">!!!notb64!!!</request></item></items>"))
check("坏条目跳过不崩溃", stat_bad["total"] == 0 and len(records_bad) == 0,
      (stat_bad, len(records_bad)))

print("== F. HAR 导入 ==")
har_json = """{
  "log": {"version": "1.2", "creator": {"name": "test"},
    "entries": [
      {"request": {"method": "GET", "url": "https://example.com/api/order/551?userId=7001",
        "headers": [{"name": "Authorization", "value": "Bearer tok-secret"},
                    {"name": "Cookie", "value": "SID=xyz; lang=cn"}],
        "queryString": [{"name": "userId", "value": "7001"}],
        "postData": {"mimeType": "", "text": ""}},
       "response": {"status": 200}},
      {"request": {"method": "POST", "url": "https://evil.com/api/x",
        "headers": [], "queryString": [], "postData": {"text": "a=1"}},
       "response": {"status": 403}}
    ]}}"""
records_h, stat_h = common.parse_import_file("export.har", b64(har_json))
check("HAR 解析 2 条", stat_h["total"] == 2, stat_h)
check("HAR allowed/rejected 分类", stat_h["allowed"] == 1 and stat_h["rejected"] == 1)
r0 = records_h[0]
check("HAR Authorization 打码", "<redacted:" in r0["headers"].get("Authorization", ""))
check("HAR 状态码保留", r0["status_code"] == 200)
check("HAR query 语义键识别", any(c["field"] == "userId" for c in r0["object_candidates"]))

print("== G. 入库与查询（项目隔离） ==")
pid = store.create_project("导入测试", "example.com")["id"]
pid2 = store.create_project("另一个项目", "jiaoyu.cn")["id"]
n_inserted = 0
for rec in records + records_h:
    if rec["scope_status"] == "allowed" and "duplicate" not in rec.get("tags", []):
        store.add_request(pid, rec)
        n_inserted += 1
# burp allowed 2 条中有 1 条 duplicate → 非重复 allowed 1 条；HAR allowed 1 条
check("入库条数 = allowed 且非重复", n_inserted == 2, n_inserted)
items = store.list_requests(pid)
check("列表可读且 JSON 反序列化", isinstance(items[0]["headers"], dict))
check("库内凭据仍是占位（无 sk-abc123secret）",
      all("sk-abc123secret" not in str(i) for i in items))
check("另一个项目看不到该请求库", store.list_requests(pid2) == [])
rid0 = items[0]["id"]
check("删除归属校验（跨项目拒删）", store.delete_request(pid2, rid0) is False)
check("同项目删除成功", store.delete_request(pid, rid0) is True)
check("删除后列表减一", len(store.list_requests(pid)) == n_inserted - 1)

print("== H. scope 双重校验（import 阶段） ==")
from app import scope as scope_mod                      # noqa: E402
check("allowed 记录的 URL 逐条过 scope 仍放行",
      all(scope_mod.check_scope(r["url"]) is None
          for r in (records + records_h) if r["scope_status"] == "allowed"))
check("rejected 记录的 URL 执行层也会拒绝（双闸门）",
      all(isinstance(scope_mod.check_scope(r["url"]), str)
          for r in (records + records_h) if r["scope_status"] == "rejected"))

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
