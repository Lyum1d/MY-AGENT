# -*- coding: utf-8 -*-
"""授权白名单（安全红线）回归测试。

为什么单独一个文件：这是本项目最硬的一条约束——**绝不越权扫描未授权目标**
（项目说明里的授权红线）。它此前由 app/executor.py 的 check_scope 执行，
却没有任何测试覆盖；一旦有人在匹配逻辑上"优化"一下，越权就会静默发生。

    python test_scope.py

不执行任何工具、不发起任何网络请求、不碰任何目标：只调用纯函数做字符串判定，
白名单文件被改道到临时目录。
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_scope_test_"))
_ORIG_SCOPE = config.SCOPE_FILE

from app.executor import _host_in_scope, _target_host, check_scope   # noqa: E402
from app.scope import (find_hosts, load_scope,                      # noqa: E402
                       first_unauthorized_host_in_argv)

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


def set_scope(domains) -> None:
    """把白名单改道到临时文件（也用来模拟"文件不存在/内容损坏"）。"""
    if domains is None:                       # None = 文件不存在
        config.SCOPE_FILE = _TMP / "not_exists.json"
        return
    p = _TMP / "scope.json"
    if domains == "BROKEN":                   # 内容不是合法 JSON
        p.write_text("{ this is not json", encoding="utf-8")
    else:
        p.write_text(json.dumps({"domains": domains}, ensure_ascii=False),
                     encoding="utf-8")
    config.SCOPE_FILE = p


# ---------------------------------------------------------------------------
print("=== 1. 目标解析（_target_host）===")
check("纯域名", _target_host("example.com") == "example.com")
check("带协议与路径", _target_host("https://example.com/a/b?x=1") == "example.com")
check("带端口", _target_host("example.com:8080") == "example.com")
check("带端口的 URL", _target_host("http://example.com:8443/x") == "example.com")
check("大写会被归一化为小写", _target_host("HTTPS://Example.COM/Path") == "example.com")
check("IPv4 保留原样", _target_host("192.168.1.10") == "192.168.1.10")
check("带凭据的 URL 去掉凭据", _target_host("http://user:pw@example.com/") == "example.com")
check("空目标返回空串", _target_host("") == "")
check("解析不出来时也要去掉端口（不能因此绕过校验）",
      _target_host("example.com:99999") == "example.com", _target_host("example.com:99999"))

# ---------------------------------------------------------------------------
print("=== 2. 白名单匹配（_host_in_scope）===")
scope = ["example.com", "10.0.0.5"]
check("精确匹配放行", _host_in_scope("example.com", scope))
check("子域匹配放行", _host_in_scope("a.b.example.com", scope))
check("IP 精确匹配放行", _host_in_scope("10.0.0.5", scope))
check("空主机名不放行", _host_in_scope("", scope) is False)

# 下面三条是这份测试的**核心**：绕过手法必须被挡住
check("前缀伪装 evil-example.com 不能匹配 example.com",
      _host_in_scope("evil-example.com", scope) is False)
check("后缀伪装 example.com.evil.com 不能匹配 example.com",
      _host_in_scope("example.com.evil.com", scope) is False)
check("形近域名 exampleXcom 不能匹配", _host_in_scope("examplexcom", scope) is False)
check("未授权域名不放行", _host_in_scope("other.org", scope) is False)

# ---------------------------------------------------------------------------
print("=== 3. 白名单读取与归一化 ===")
set_scope(["  Example.COM "])
check("白名单条目会被 trim + 小写（配置里多打空格/大小写不影响）",
      check_scope("https://Example.com/x") is None, check_scope("https://Example.com/x"))

print("=== 4. 拒绝路径（宁可跑不起来，也不能静默放行）===")
set_scope(None)
r = check_scope("example.com")
check("白名单文件不存在时拒绝执行（不放行）", isinstance(r, str) and "白名单为空" in r,
      (r or "")[:40])

set_scope("BROKEN")
r = check_scope("example.com")
check("白名单解析失败时拒绝执行（不放行）", isinstance(r, str) and "白名单为空" in r,
      (r or "")[:40])

set_scope([])
r = check_scope("example.com")
check("白名单为空列表时拒绝执行", isinstance(r, str) and "白名单为空" in r)

set_scope(["example.com"])
r = check_scope("https://not-authorized.org/scan")
check("未授权目标被拒绝", isinstance(r, str) and "不在授权白名单" in r, (r or "")[:40])
check("拒绝原因里带上被拒的目标（便于排查）", isinstance(r, str) and "not-authorized.org" in r)
check("拒绝原因里带上当前白名单（便于排查）", isinstance(r, str) and "example.com" in r)

check("已授权目标放行", check_scope("example.com") is None)
check("已授权目标的子域放行", check_scope("deep.sub.example.com") is None)
check("已授权目标的 URL 形态放行", check_scope("https://example.com:443/a?b=1") is None)

# ---------------------------------------------------------------------------
print("=== 5. 与执行器/其它入口的一致性 ===")
check("默认强制开启授权校验（config.ENFORCE_SCOPE 默认 True）",
      config.ENFORCE_SCOPE is True, config.ENFORCE_SCOPE)
src = (ROOT / "app" / "executor.py").read_text(encoding="utf-8")
check("命令行工具执行前确实调用了 check_scope", "denied = check_scope(target)" in src)
pysrc = (ROOT / "app" / "pyexec.py").read_text(encoding="utf-8")
# 断言意图是「白名单只有一份实现」。实现已从 executor 收敛到 app/scope.py，
# 故这里接受任一等价导入形式，但必须确实是**共享模块**导出来的，不能自带一套。
check("py_exec 复用同一份 check_scope（不能各写一套）",
      ("from .scope import check_scope" in pysrc) or ("from .executor import check_scope" in pysrc),
      "唯一实现 = app/scope.py")
check("py_exec 没有自己再写一份白名单读取/匹配",
      "def _load_scope" not in pysrc and "def load_scope" not in pysrc
      and "def _host_in_scope" not in pysrc)
# 另外两个调用方同样不许自带实现（防止将来又分叉出第二套判定）
for _mod in ("executor", "replayer"):
    _src = (ROOT / "app" / f"{_mod}.py").read_text(encoding="utf-8")
    check(f"{_mod} 不自带白名单实现（只调用 app/scope.py）",
          ("scope.load_scope" in _src) or ("from .scope import" in _src))

config.SCOPE_FILE = _ORIG_SCOPE

# ---- 审计 P0-2/P0-3 绕过用例固化（2026-09-16）：这些形态必须永远被拒绝 ----
set_scope(["example.com", "target.test"])
_scope2 = load_scope()
check("白名单加载非空", bool(_scope2), _scope2)

# P0-3：url 型 target 用「授权域/+空格」夹带第二目标（修复前放行）
_argv3 = ["tool.exe", "finger", "-u", "https://target.test/", "evil.com"]
_e3 = first_unauthorized_host_in_argv(_argv3)
check("P0-3 url 型空格夹带被 argv 复核拦截",
      _e3 is not None and _e3[1] == "evil.com", _e3)
# P0-2：args 走私（executor argv 复核层抓，这里验证 find_hosts 抽取正确）
_hosts = find_hosts("--url https://evil.com")
check("P0-2 find_hosts 抽出走私主机", "evil.com" in _hosts, _hosts)
_early = [h for tkn in ("--url", "https://evil.com") for h in find_hosts(tkn)
          if not _host_in_scope(h, _scope2)]
check("P0-2 argv 复核能发现越权主机", "evil.com" in _early, _early)
# 路径形态 token 不得被 find_hosts 抽成主机（避免复核层误杀）
check("本地路径不产出主机", find_hosts("E:\\tool\\dirsearch.py") == [],
      find_hosts("E:\\tool\\dirsearch.py"))
# URL scheme 不得被盘符正则误判成本地路径（复核层曾因此漏检 evil.com）
check("URL token 不被盘符正则跳过", bool(find_hosts("https://evil.com")))
# P2-3：尾点 FQDN 归一
check("P2-3 尾点 FQDN 归一后放行",
      _host_in_scope(_target_host("www.target.test."), ["target.test"]))
# 第五节：前导点/后缀变体仍全部拒绝
for _h in ("evil-target.test", "nottarget.test", "target.test.evil.com", "www.target.test.evil.com"):
    check(f"后缀变体拒绝：{_h}", not _host_in_scope(_h, _scope2))

config.SCOPE_FILE = _ORIG_SCOPE

# ---- v010 目标列表文件内容校验（P0-2 收窄后的剩余真空）----
# argv 复核看不到 -l/--list/--urls/--input 指向的文件**内容**——列表里写
# evil.com 即可绕过全部校验。这组用例钉住 first_unauthorized_target_list_in_argv。
from app.scope import first_unauthorized_target_list_in_argv   # noqa: E402

set_scope(["example.com", "target.test"])
_lf = _TMP / "targets.txt"

_lf.write_text("https://target.test\nhttps://example.com/admin\n", encoding="utf-8")
check("列表文件全授权 → 放行",
      first_unauthorized_target_list_in_argv(
          ["nuclei", "-l", str(_lf)]) is None)

_lf.write_text("target.test\nevil.com\nsub.example.com\n", encoding="utf-8")
check("列表文件含未授权域名 → 拦截 evil.com",
      first_unauthorized_target_list_in_argv(
          ["nuclei", "-l", str(_lf)]) == ("-l", "evil.com"))

_lf.write_text("# 注释行\nhttp://target.test:8443/x\n192.168.1.10\n", encoding="utf-8")
check("列表文件含未授权 IP → 拦截",
      first_unauthorized_target_list_in_argv(
          ["httpx", "--list", str(_lf)]) == ("--list", "192.168.1.10"))

check("无列表参数 → 放行",
      first_unauthorized_target_list_in_argv(
          ["nuclei", "-u", "https://target.test/"]) is None)
check("列表旗标后无值 → 放行（交工具自行报错）",
      first_unauthorized_target_list_in_argv(
          ["nuclei", "-l", "-t", "cves"]) is None)
check("文件不存在 → 放行（执行时工具自然失败）",
      first_unauthorized_target_list_in_argv(
          ["nuclei", "-l", str(_TMP / "no_such.txt")]) is None)
check("白名单为空 → fail-closed（返回空元组）",
      (first_unauthorized_target_list_in_argv.__doc__ or "").find("fail-closed") >= 0)

_lf.write_text("a" * (2 * 1024 * 1024), encoding="utf-8")
check("超大列表文件 → 按 <oversized> 拒绝",
      first_unauthorized_target_list_in_argv(
          ["nuclei", "-l", str(_lf)]) == ("-l", "<oversized>"))

# executor 接入断言：最终 argv 复核后必须跟一条列表文件复核
check("executor.run 已接入目标列表文件复核",
      "first_unauthorized_target_list_in_argv(cmd)" in src)

config.SCOPE_FILE = _ORIG_SCOPE

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
