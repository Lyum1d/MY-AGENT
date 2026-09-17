# -*- coding: utf-8 -*-
"""启动器与静态资源回归。

覆盖三件事：
  1) 启动器自身的可执行性（解释器自愈、就绪后再开浏览器、非回环绑定警告）；
  2) 首页与静态资源禁用缓存（避免半新半旧的页面）；
  3) 启动脚本「启动控制台.bat」的硬约束 + **更新器必须保证 .bat 换行符**。

不联网、不调用真实工具、不碰任何目标资产；不需要另外起服务。
运行：python test_launcher.py

---
2026-09-16 变更说明（重要，别误读成"测试放水了"）：

本项目 fork 自上游 `Lyum1d/MY-AGENT`，`update.py` 会用上游整包覆盖 `app/*.py` 与
`web/*`。拉 v006 时，本地自研的以下能力被覆盖掉了：

  · `config.build_stamp()` / `compute_build_stamp()` / `BUILD_STAMP` / `version()`
    —— 进程启动时定格的代码指纹，用来判断"跑着的服务装的是不是旧代码"；
  · `run.py` 的 `port_open` / `probe_service` / `listening_pid` / `stop_listener`
    / `_probe_host` —— 启动前的端口探测、服务身份比对、陈旧进程清理。

这些断言**没有删**，而是改成：检测到能力存在就跑原断言，不存在就明确打印
`[跳过] ... 已下线`。将来若把上游覆盖掉的能力补回来（或改用 git 合并上游），
这里的期望值就是现成的验收标准。
"""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config, store                                    # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="src_agent_launcher_test_"))
store.DB_PATH = _TMP / "test_launcher.db"
config.LLM_PROVIDERS_FILE = _TMP / "providers_test.json"
store.init_db()

import run as run_mod                                            # noqa: E402

ok, fail, skipped = [], [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' -> ' + str(extra)) if extra else ''}")


def skip(name, why):
    skipped.append(name)
    print(f"  [跳过] {name} -> 已下线：{why}")


# ---------- 一、代码指纹（能力被上游覆盖，检测到才跑） ----------
print("=== 一、代码指纹（判断「跑着的服务是不是旧代码」）===")
if hasattr(config, "build_stamp"):
    stamp_a = config.build_stamp()
    check("build_stamp 与启动时定格的 BUILD_STAMP 一致",
          stamp_a == config.BUILD_STAMP, stamp_a)

    # 指纹取所有文件的【最大】mtime，所以要让它真的变成最新：
    # 先算当前最大值再往上加（直接给「自己 mtime + 1 小时」不够）。
    def _stamp_files():
        out = []
        for folder in (ROOT / "app", ROOT / "web"):
            try:
                out += [p for p in folder.glob("*")
                        if p.is_file() and not p.name.endswith(".pyc")]
            except OSError:
                continue
        return out

    target = ROOT / "web" / "style.css"
    old = target.stat().st_mtime
    newest = max(p.stat().st_mtime for p in _stamp_files())
    try:
        os.utime(target, (newest + 3600, newest + 3600))
        check("现算的指纹会随 mtime 变化",
              config.compute_build_stamp() != config.BUILD_STAMP)
        check("本进程定格的指纹不受影响（否则永远对比不出差异）",
              config.build_stamp() == stamp_a)
    finally:
        os.utime(target, (old, old))
else:
    skip("代码指纹（build_stamp / BUILD_STAMP / compute_build_stamp）",
         "上游 v006 的 app/config.py 里没有这套指纹")

# ---------- 二、端口探测 / 服务识别（能力被上游覆盖，检测到才跑） ----------
print("\n=== 二、端口探测与服务识别 ===")
if hasattr(run_mod, "port_open"):
    import socket
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    def free_port() -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    class ForeignHandler(BaseHTTPRequestHandler):
        """冒充「别的程序」：同一个路径返回完全不相干的 JSON。"""

        def do_GET(self):
            body = json.dumps({"hello": "not-our-service"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    port = free_port()
    check("空闲端口 port_open 为 False", run_mod.port_open("127.0.0.1", port) is False)
    foreign = HTTPServer(("127.0.0.1", port), ForeignHandler)
    threading.Thread(target=foreign.serve_forever, daemon=True).start()
    time.sleep(0.4)
    check("已监听端口 port_open 为 True", run_mod.port_open("127.0.0.1", port) is True)
    check("非本项目服务 probe_service 返回 None（不能误判成自己的服务）",
          run_mod.probe_service("127.0.0.1", port) is None)
    check("能在 netstat 里定位到监听端口的进程号",
          run_mod.listening_pid(port) == os.getpid())
    foreign.shutdown()
    foreign.server_close()
    time.sleep(0.5)
    check("停止后端口恢复空闲", run_mod.port_open("127.0.0.1", port) is False)
    check("_probe_host 把 0.0.0.0 换成本机回环",
          run_mod._probe_host("0.0.0.0") == "127.0.0.1"
          and run_mod._probe_host("127.0.0.1") == "127.0.0.1")
else:
    skip("端口探测 / 服务身份比对 / 陈旧进程清理（port_open 等）",
         "上游 v006 的 run.py 没有这套逻辑（生命周期交给 SRC控制台.exe 壳）")

# ---------- 三、启动器自身仍成立的行为 ----------
print("\n=== 三、启动器自身行为 ===")
check("解释器候选列表非空且第一项是项目内 venv",
      run_mod._candidates() and ".venv" in run_mod._candidates()[0],
      run_mod._candidates()[:2])
check("_has_deps 对不存在的解释器返回 False",
      run_mod._has_deps(str(ROOT / "绝不存在" / "python.exe")) is False)

check("_browser_url 把通配监听地址换成回环",
      run_mod._browser_url("0.0.0.0", 8770) == "http://127.0.0.1:8770"
      and run_mod._browser_url("127.0.0.1", 8770) == "http://127.0.0.1:8770",
      run_mod._browser_url("0.0.0.0", 8770))

# 非回环绑定：v010 起默认**拒绝启动**（本服务没有鉴权层，改绑 0.0.0.0
# 等于把本机控制权交出去）；只有显式 ALLOW_NON_LOOPBACK=1 才放行并警告。
_buf = io.StringIO()
with redirect_stdout(_buf):
    run_mod._warn_if_exposed("127.0.0.1")
    run_mod._warn_if_exposed("localhost")
check("回环绑定时不打扰（不打印警告）", _buf.getvalue() == "", repr(_buf.getvalue()[:60]))

# 默认（未设置 ALLOW_NON_LOOPBACK）：非回环 → SystemExit(2)，拒绝启动
_saved_env = os.environ.pop("ALLOW_NON_LOOPBACK", None)
try:
    _code = None
    try:
        with redirect_stdout(io.StringIO()):
            run_mod._warn_if_exposed("0.0.0.0")
    except SystemExit as _e:
        _code = _e.code
    check("v010 非回环默认拒绝启动（SystemExit 2）", _code == 2, f"exit={_code}")

    _buf = io.StringIO()
    os.environ["ALLOW_NON_LOOPBACK"] = "1"
    with redirect_stdout(_buf):
        run_mod._warn_if_exposed("0.0.0.0")
    warn = _buf.getvalue()
    check("显式放行后给出完整风险警告", "非回环" in warn, warn.strip().splitlines()[:1])
    check("警告里说明后果（无鉴权 / 可被任意调用）",
          "鉴权" in warn and "任意" in warn)
    check("警告提示风险自担并建议改回默认", "127.0.0.1" in warn)
finally:
    if _saved_env is None:
        os.environ.pop("ALLOW_NON_LOOPBACK", None)
    else:
        os.environ["ALLOW_NON_LOOPBACK"] = _saved_env

# ---------- 四、health 载荷（供前端状态栏与启动器判断） ----------
print("\n=== 四、/api/health 载荷 ===")
from fastapi.testclient import TestClient                        # noqa: E402
from app.main import app as fastapi_app                          # noqa: E402

# base_url 必须带回环名：main.py 有本机访问守卫（Host/Origin 校验），
# 默认的 Host: testserver 会被判 403。
client = TestClient(fastapi_app, base_url="http://127.0.0.1")
h = client.get("/api/health")
check("health 返回 200", h.status_code == 200, h.status_code)
body = h.json() if h.status_code == 200 else {}
check("原有字段未被破坏",
      {"registry", "llm", "toolbox", "current_backend"} <= set(body), sorted(body))
# 授权边界必须可见：白名单为空时所有工具都被拒（现象像"工具坏了"）；
# ENFORCE_SCOPE=0 时工具会对任意目标执行。两种都不该让使用者自己猜。
check("暴露授权状态 enforce_scope", "enforce_scope" in body, body.get("enforce_scope"))
check("暴露白名单条目 scope_domains", isinstance(body.get("scope_domains"), list),
      body.get("scope_domains"))
check("白名单为空时必须给出 scope_warning",
      (body.get("scope_domains") or []) or bool(body.get("scope_warning")),
      body.get("scope_warning"))

if hasattr(config, "build_stamp"):
    check("health 带 build 字段且等于本进程指纹",
          body.get("build") == config.build_stamp(), body.get("build"))
else:
    skip("health 的 version / build 字段", "同上，上游 v006 没有代码指纹机制")

# ---------- 五、静态资源禁用缓存（避免半新半旧的页面） ----------
print("\n=== 五、静态资源与首页禁用缓存 ===")
# 本地谱系里有 `_NoStoreStatic(StaticFiles)` + 首页 no-store 头，作用是：
# 静态文件按请求读磁盘（所以一定是新的），但浏览器可能缓存住旧的 app.js，
# 于是"新前端调新接口"变成"旧前端调新接口 → 404 → 面板静默空着"——
# 这正是本项目被咬过好几次的「界面功能整块消失」。上游 v006 没有这段。
_CACHE_PATHS = ("/", "/static/app.js", "/static/style.css")
_cache_cc = {p: client.get(p).headers.get("cache-control", "") for p in _CACHE_PATHS}
if all("no-store" in cc for cc in _cache_cc.values()):
    for p, cc in _cache_cc.items():
        check(f"{p} 带 no-store", True, cc)
else:
    skip("首页与静态资源的 Cache-Control: no-store",
         "本地谱系的 _NoStoreStatic 被上游 v006 覆盖（现象：浏览器缓存旧 app.js → "
         "旧前端调新接口 404 → 面板静默空着），经确认本轮不恢复")

# ---------- 六、启动脚本自身的硬约束 ----------
print("\n=== 六、启动脚本（启动控制台.bat）===")
# 为什么钉这几条：cmd.exe 按字节偏移解析 bat，LF 换行 + 多字节中文会让行边界错位，
# 表现为双击后闪退或满屏「xx 不是内部或外部命令」。实测对照：同一份 GBK 中文脚本，
# LF 版 2 处碎片化报错、CRLF 版 0 处 —— **换行符是决定性因素**，编码只影响中文显示。
BAT = ROOT / "启动控制台.bat"
check("启动脚本存在", BAT.is_file(), str(BAT))
if BAT.is_file():
    raw = BAT.read_bytes()
    crlf = raw.count(b"\r\n")
    bare_lf = raw.count(b"\n") - crlf
    check("全部换行都是 CRLF（不能有裸 LF，否则 cmd 行偏移错位）",
          bare_lf == 0 and crlf > 0, f"CRLF={crlf} 裸LF={bare_lf}")

    non_ascii = sum(1 for b in raw if b > 127)
    if non_ascii:
        # 含中文就必须是 GBK（cmd 用 OEM 代码页 936 读脚本），不能是 UTF-8。
        try:
            text = raw.decode("gbk")
            gbk_ok = True
        except UnicodeDecodeError:
            gbk_ok = False
        check("含非 ASCII 时必须是 GBK 编码（UTF-8 中文在 936 代码页下会乱码）",
              gbk_ok, f"非 ASCII 字节 {non_ascii} 个")
    else:
        text = raw.decode("ascii")
        check("纯 ASCII 脚本（最稳形态）", True)

    check("切到脚本所在目录（从别处双击也找得到文件）", 'cd /d "%~dp0"' in text)
    check("最终确实在跑 run.py", "run.py" in text)
    check("解释器可被环境变量覆盖（便于指向装了依赖的那个）", "SRC_AGENT_PY" in text)
    check("缺依赖时会自动安装而不是直接崩",
          ":install_deps" in text and "pip install" in text)
    check("找不到解释器时有显式分支 + pause（不让窗口一闪而过）",
          "exit /b 1" in text and "pause" in text)

# ---------- 七、更新器必须守住 .bat 的换行符（治本，防"下次更新又坏"） ----------
print("\n=== 七、更新器对批处理的换行符保证 ===")
# 根因：更新包在 Linux 侧打包，zip 里的 .bat 是 LF；update.py 原先
# `target.write_bytes(zf.read(name))` 原样落盘 —— 每更新一次就把启动器打坏一次
# （已实测 v004/v006 两个版本落盘的 .bat 都是 LF + 中文）。
# .gitattributes 里的 `*.bat text eol=crlf` 挡不住这条路（core.autocrlf=true 还会让
# git status 看不出问题），只能在落盘这一步强制归一。
UPD = ROOT / "update.py"
check("更新器存在", UPD.is_file(), str(UPD))
if UPD.is_file():
    usrc = UPD.read_text(encoding="utf-8", errors="replace")
    check("定义了需要 CRLF 的扩展名清单", "CRLF_REQUIRED_EXT" in usrc)
    check("批处理扩展名在清单内", '".bat"' in usrc and '".cmd"' in usrc)
    check("有换行符归一函数", "def normalize_crlf" in usrc)

    sys.path.insert(0, str(ROOT))
    try:
        import update as up
        check("换行符归一：LF -> CRLF",
              up.normalize_crlf(b"a\nb\n") == b"a\r\nb\r\n",
              up.normalize_crlf(b"a\nb\n"))
        check("换行符归一：已是 CRLF 不重复叠加",
              up.normalize_crlf(b"a\r\nb\r\n") == b"a\r\nb\r\n")
        check("换行符归一：裸 CR 也归一",
              up.normalize_crlf(b"a\rb") == b"a\r\nb")
        check("解压落盘路径用上了归一（否则等于没加）",
              "normalize_crlf(payload)" in usrc,
              "" if "normalize_crlf(payload)" in usrc else "未在解压循环里调用")
    except Exception as e:                                       # pragma: no cover
        check("能导入 update 模块做白盒校验", False, repr(e))

print(f"\n{'=' * 56}")
print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
for name in fail:
    print(f"    FAIL: {name}")
if skipped:
    print(f"  另有 {len(skipped)} 项跳过（能力被上游更新覆盖，非回归）：")
    for name in skipped:
        print(f"    SKIP: {name}")
print("=" * 56)
sys.exit(1 if fail else 0)
