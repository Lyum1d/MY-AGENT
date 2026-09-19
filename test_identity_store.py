# -*- coding: utf-8 -*-
"""v017.2 身份库回归：DPAPI 往返、项目隔离、零凭据泄露、失效处理。

    python test_identity_store.py

离线：数据库与 scope.json 改道临时目录；有效性检查只测「请求构建与判定」
逻辑（scope 拒绝/解密失败），不真发网络请求。
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app import config                                   # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_id_test_"))
scope_file = _TMP / "scope_v0172.json"
scope_file.write_text('{"domains": ["example.com"]}', encoding="utf-8")
config.SCOPE_FILE = scope_file

from app import secretbox, store                         # noqa: E402
store.DB_PATH = _TMP / "projects.db"
store.init_db()

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


# ---------------------------------------------------------------------------
print("== A. DPAPI 加密往返 ==")
check("DPAPI 可用（Windows）", secretbox.available())
secret = {"Authorization": "Bearer sk-live-secret-999", "X-Api-Key": "key-42"}
sealed = secretbox.seal_dict(secret)
check("加密产物非空且不含明文", sealed and "sk-live-secret-999" not in sealed)
unsealed = secretbox.unseal_dict(sealed)
check("解密还原一致", unsealed == secret)
check("密文 base64 可存 TEXT 列", isinstance(sealed, str) and len(sealed) > 20)

print("== B. 解密失败路径（换用户/损坏语义） ==")
check("损坏密文 → None（身份失效语义）", secretbox.unseal_dict("AAAAgarbage!!!") is None)
check("空串 → None", secretbox.unseal_dict("") is None)
tampered = sealed[:-4] + "AAAA"
check("篡改密文 → None", secretbox.unseal_dict(tampered) is None)
check("空 dict → None（无需加密）", secretbox.seal_dict({}) is None)

print("== C. 身份 CRUD 与项目隔离 ==")
pid = store.create_project("身份测试", "example.com")["id"]
pid2 = store.create_project("别的项目", "example.com")["id"]
rec = store.add_identity(pid, "account_a", role="user",
                         headers_enc=secretbox.seal_dict(secret),
                         cookies_enc=secretbox.seal_dict({"SID": "xyz789"}),
                         check_url="https://example.com/profile")
iid = rec["id"]
check("登记成功", iid and rec["status"] == "active")
check("列表**不含凭据字段**",
      all("headers_enc" not in it and "cookies_enc" not in it
          for it in store.list_identities(pid)))
check("列表含元数据", store.list_identities(pid)[0]["label"] == "account_a")
check("跨项目取身份 → None（归属校验）",
      store.get_identity(pid2, iid) is None)
got = store.get_identity(pid, iid)
# DPAPI 每次加密带随机熵：同明文两次密文不同——比较解密往返而非密文字节
check("同项目可取且解密还原",
      got is not None and secretbox.unseal_dict(got["headers_enc"]) == secret)

print("== D. 解密失败 → 标记 invalid ==")
# 模拟换用户/密文损坏：直接塞坏密文
store.add_identity(pid, "account_b", role="user",
                   headers_enc="AAAAcorrupted!!", cookies_enc="",
                   check_url="https://example.com/profile")
# main.py 的 check 逻辑在解密失败时标记 invalid——此处验证 store 层接口
check("状态更新接口合法值", store.update_identity_status(pid, iid, "expired",
                                                         last_checked_at=1.0))
check("非法状态被拒", store.update_identity_status(pid, iid, "hacked") is False)
store.update_identity_status(pid, iid, "active", last_checked_at=1.0)
check("状态机往返", store.list_identities(pid)[0]["status"] == "active")

print("== E. check_url 的 scope 前置校验 ==")
from app import scope                                    # noqa: E402
check("白名单内 check_url 放行", scope.check_scope("https://example.com/profile") is None)
check("白名单外 check_url 拒绝（check 阶段会拒+标记 invalid）",
      isinstance(scope.check_scope("https://evil.com/profile"), str))

print("== F. 删除清凭据 ==")
check("同项目删除", store.delete_identity(pid, iid))
check("删除后取不到", store.get_identity(pid, iid) is None)
check("计数归零前另一个还在", store.count_identities(pid) == 1)
store.delete_identity(pid, store.list_identities(pid)[0]["id"])
check("清空", store.count_identities(pid) == 0)

print("== G. 匿名身份（无凭据） ==")
rec_anon = store.add_identity(pid2, "anonymous", role="anonymous",
                              headers_enc="", cookies_enc="")
check("匿名身份登记（空凭据）", rec_anon["id"] and rec_anon["role"] == "anonymous")
check("匿名身份列表", store.list_identities(pid2)[0]["label"] == "anonymous")

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
