# -*- coding: utf-8 -*-
"""v053 外部审计报告修复的回归测试（§2.1 ~ §2.5 + 环境自检）。

对应 `审计报告.md`（v052 基线）里**经核实属实**的 5 条问题。
每条测试都钉「修复后的行为」，而不是「代码里出现了某个字符串」——
否则改回去也能过。

    python test_053_audit_fixes.py

不执行任何工具、不发起任何网络请求、不碰真实 `data/`（全部改道临时目录）。
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config, config_io, providers, scope          # noqa: E402
from app.agent import Agent, Session, Step, l4_no_output_feedback  # noqa: E402
from app.executor import _strip_target_arg                    # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="src_agent_053_"))
ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" → {extra}" if extra else ""))


# ============================================================ §2.1
def test_l4_feedback():
    print("\n=== §2.1 「成功但无输出」必须回填原始输出 ===")
    out = l4_no_output_feedback("nuclei", "[错误] 目标不在白名单内")
    check("原始报错原文出现在回喂内容里（原实现被整条丢弃）",
          "[错误] 目标不在白名单内" in out, out[:90].replace("\n", "⏎"))
    check("仍保留归因标记 L4", "归因 L4" in out)
    check("仍保留「别重复调用」的指引", "重复调用" in out)
    check("明确指出 [错误] 行≠测试面不存在（防止模型误判换方向）",
          "不是**「目标不存在该测试面」**" in out or "而**不是**" in out)
    out2 = l4_no_output_feedback("nuclei", "")
    check("输出为空时给出占位串而不是空白",
          "（工具无输出）" in out2, out2[:60].replace("\n", "⏎"))
    check("工具名出现在内容里（便于模型定位是哪一步）", "nuclei" in out2)


# ============================================================ §2.2
def test_execute_unknown_alias():
    print("\n=== §2.2 别名查不到时必须「响铃」而不是静默 return ===")
    ag = Agent()
    sess = Session(id="t053-session")
    step = Step(id="s1", tool_alias="definitely_no_such_alias_053",
                tool_name="x", target="a.test", args="", risk={})
    # 不碰真实 DB：save_step / save_event 全部改道
    with mock.patch.object(sys.modules["app.store"], "save_step", lambda *a, **k: 1), \
         mock.patch.object(sys.modules["app.store"], "save_event", lambda *a, **k: 1):
        asyncio.run(ag._execute(sess, step, "call-053"))

    check("step.status 不再是 pending（原来停在默认值）",
          step.status == "error", step.status)
    check("finished_at 已写入（原来为 None）", step.finished_at is not None)
    tail = sess.messages[-1] if sess.messages else {}
    check("追加了 role=tool 消息（原来一条都没有 → tool_calls 失配）",
          tail.get("role") == "tool", str(tail.get("role")))
    check("tool_call_id 正确回填（协议一致性的关键）",
          tail.get("tool_call_id") == "call-053", str(tail.get("tool_call_id")))
    check("内容说明了原因与下一步", "不存在" in (tail.get("content") or "")
          and "重新选择" in (tail.get("content") or ""))
    # 事件流：至少要有 error 与 step_done，否则界面看起来"卡住了"
    events = []
    while not sess.events.empty():
        events.append(sess.events.get_nowait())
    types = [e.get("type") for e in events]
    check("发出了 error 事件（响铃）", "error" in types, str(types))
    check("发出了 step_done（界面不会停在 running）", "step_done" in types, str(types))
    # 调用方逻辑复现：status=error 必须让连续失败计数累加
    consec = 0
    if step.status == "done":
        consec = 0
    elif step.status == "error":
        consec += 1
    check("调用方的失败计数会累加（原来既不 done 也不 error → 熔断失效）", consec == 1)


# ============================================================ §2.3
def test_strip_target_arg():
    print("\n=== §2.3 _strip_target_arg：判据是「取值是不是本步 target」 ===")
    # 原始要解决的场景：模型把本步目标又填了一遍 → 必须剥掉（否则工具收到两个目标，
    # dirsearch 会栈溢出崩溃 0xC0000004）
    check("重复填写的目标（同主机、带路径与引号）被剥掉",
          _strip_target_arg('-u "http://a.test/-"', "-u", "https://a.test") == "",
          repr(_strip_target_arg('-u "http://a.test/-"', "-u", "https://a.test")))
    check("剥掉后其余参数保留",
          _strip_target_arg("-u http://a.test/ --depth 3", "-u", "https://a.test")
          == "--depth 3",
          repr(_strip_target_arg("-u http://a.test/ --depth 3", "-u", "https://a.test")))
    check("无 scheme 的裸主机也算同一个目标",
          _strip_target_arg("-u a.test -z", "-u", "https://a.test") == "-z",
          repr(_strip_target_arg("-u a.test -z", "-u", "https://a.test")))

    # ★ 本次修复点：审计报告举的那个例子 —— args 里该旗标只出现一次、取值是**别的**目标。
    # 只加 `count=1` **修不好**它（它本来就是"第一个匹配"），必须靠取值判据。
    mid = _strip_target_arg("-x --url http://other.test/ -y", "--url", "https://a.test")
    check("位于 args 中段、且取值是别的目标 → **保留**（count=1 修不好这个例子）",
          "--url http://other.test/" in mid, repr(mid))
    check("中段场景下前后参数都还在", "-x" in mid and "-y" in mid, repr(mid))

    # 保守性：主机相同但端口不同 → 保留（"不确定就不动"，宁可交给 argv 复核也别静默丢参数）
    keep = _strip_target_arg("--url http://a.test:8080/x", "--url", "https://a.test")
    check("同主机不同端口 → 保留（保守：不确定就不改写命令）",
          "a.test:8080" in keep, repr(keep))

    check("没有该旗标时原样返回", _strip_target_arg("-x -y", "-u", "https://a.test") == "-x -y")
    check("flag 为 None 时原样返回",
          _strip_target_arg("-u http://x/", None, "https://a.test") == "-u http://x/")
    check("= 形式的取值也能剥掉",
          _strip_target_arg("--url=http://a.test/ -z", "--url", "https://a.test") == "-z",
          repr(_strip_target_arg("--url=http://a.test/ -z", "--url", "https://a.test")))
    check("长旗标不被误伤（--target-extra 不是 --target）",
          "--target-extra" in _strip_target_arg("--target-extra 1", "--target", "a.test"),
          repr(_strip_target_arg("--target-extra 1", "--target", "a.test")))
    # 旧调用点（不传 target）行为不变：只剥第一个
    check("不传 target 时退化为「只剥第一个」（旧调用点行为不变）",
          _strip_target_arg("-u http://x/ -u http://y/", "-u") == "-u http://y/",
          repr(_strip_target_arg("-u http://x/ -u http://y/", "-u")))


# ============================================================ §2.4
def test_target_list_file():
    print("\n=== §2.4 目标列表文件校验：不可读/编码异常一律 fail-closed ===")
    saved = config.SCOPE_FILE
    config.SCOPE_FILE = TMP / "scope053.json"
    config.SCOPE_FILE.write_text(json.dumps({"domains": ["a.test"]}), encoding="utf-8")
    try:
        # ① 不存在 → 放行（原意保留：工具自己会报错，不是授权问题）
        check("文件不存在 → 放行（不改原有语义）",
              scope.first_unauthorized_target_list_in_argv(
                  ["t.exe", "-l", str(TMP / "no_such_053.txt")]) is None)

        # ② 存在但解码失败 → 拒绝（本次修复点）
        bad = TMP / "undecodable_053.txt"
        bad.write_bytes(b"\xff\xff\xff")          # utf-8/gbk 都不认，且无 BOM 不试 utf-16
        r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(bad)])
        check("存在但无法解码 → 拒绝且标记 <unreadable>（原来静默放行）",
              r is not None and r[1] == "<unreadable>", str(r))

        # ③ 读取抛 OSError（权限/锁定）→ 拒绝
        # 注意：不能 patch `Path.stat` —— `load_scope()` 内部也走 `p.exists()`→`stat()`，
        # 一 patch 就连白名单读取一起打崩（第一次写这条用例时就踩了）。
        # 只 patch `read_bytes`，正好命中 `_read_text_multi_encoding` 的读取点。
        with mock.patch.object(Path, "read_bytes",
                               side_effect=OSError(13, "Permission denied")):
            r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(bad)])
        check("读取抛 OSError → 拒绝且标记 <unreadable>（原来 continue 放行）",
              r is not None and r[1] == "<unreadable>", str(r))

        # ④ GBK 中文注释 + 未授权主机 → 必须查出来（原来 errors=replace 会抽不出主机名）
        gbk = TMP / "gbk_053.txt"
        gbk.write_bytes("扫描目标如下\nevil.example.net\n".encode("gbk"))
        r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(gbk)])
        check("GBK 编码的列表文件里的未授权主机被抓到（编码回退生效）",
              r is not None and "evil.example.net" in (r[1] or ""), str(r))

        # ⑤ UTF-8 正常文件（回归：别把正常路径改坏）
        good = TMP / "good_053.txt"
        good.write_bytes("a.test\nsub.a.test\n".encode("utf-8"))
        check("UTF-8 且全部授权 → 放行",
              scope.first_unauthorized_target_list_in_argv(
                  ["t.exe", "-l", str(good)]) is None)
        mixed = TMP / "mixed_053.txt"
        mixed.write_bytes("a.test\nevil.example.net\n".encode("utf-8"))
        r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(mixed)])
        check("UTF-8 混合文件里的未授权主机被抓到",
              r is not None and "evil.example.net" in (r[1] or ""), str(r))

        # ⑥ 带 BOM 的 UTF-16 → 可读（回退链覆盖）
        u16 = TMP / "u16_053.txt"
        u16.write_bytes("evil.example.net\n".encode("utf-16"))   # 自带 BOM
        r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(u16)])
        check("带 BOM 的 UTF-16 列表文件可读且未授权主机被抓到",
              r is not None and "evil.example.net" in (r[1] or ""), str(r))

        # ⑦ 超限 → 拒绝（哨兵，行为不变）
        big = TMP / "big_053.txt"
        big.write_bytes(b"a" * (scope.TARGET_LIST_MAX_BYTES + 10))
        r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(big)])
        check("超过大小上限 → 拒绝且标记 <oversized>",
              r is not None and r[1] == "<oversized>", str(r))

        # ---------- v054：审计二次复核发现的两处「仍会静默放行」 ----------
        print("  -- v054 补：目录路径 / 二进制「成功」解码 --")

        # §3.1 目录路径：原来 `is_file()` 为 False 就 continue → 静默放行
        adir = TMP / "adir_054"
        adir.mkdir(exist_ok=True)
        r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(adir)])
        check("「-l 指向目录」→ 拒绝（原来静默放行；且旧注释声称会走 OSError 分支，实际不可达）",
              r is not None and r[1] == "<unreadable>", str(r))

        # §3.2 二进制被「成功」解码：该串以 FF FE 开头 → 命中 UTF-16 BOM 白名单，
        # 即使后面是二进制也会"解码成功"，解出含私有使用区码位的乱码 → 抽不出主机 → 放行
        binfile = TMP / "bin_054.txt"
        binfile.write_bytes(bytes([0xFF, 0xFE, 0x00, 0x81, 0x99, 0xAB, 0xCD, 0xEF]))
        r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(binfile)])
        check("二进制文件（带 UTF-16 BOM、能被「成功」解码）→ 拒绝（原来静默放行）",
              r is not None and r[1] == "<unreadable>", str(r))
        # 判据是**字符类**而非"控制字符占比"：该例解出 0 个控制字符，但有私有使用区码位
        check("字符类判据能识别这类乱码（含私有使用区码位）",
              scope._looks_like_text("脀ꮙ\uefcd") is False,
              repr(scope._looks_like_text("脀ꮙ\uefcd")))
        check("正常中文文本仍判为文本（不能误伤）",
              scope._looks_like_text("扫描目标如下\nevil.example.net\n") is True)
        check("正常 ASCII 主机列表仍判为文本",
              scope._looks_like_text("a.test\nsub.a.test\n") is True)
        check("空文本判为文本（空文件不该被当成乱码）",
              scope._looks_like_text("") is True)

        # 反例：正常文件必须照常工作（这两处修复不能顺带误伤）
        for label, data, want in (
                ("UTF-8 全授权", "a.test\nsub.a.test\n".encode(), None),
                ("含未授权", "a.test\nevil.example.net\n".encode(), "evil.example.net"),
                ("GBK 中文注释", "扫描目标\nevil.example.net\n".encode("gbk"),
                 "evil.example.net"),
                ("带 BOM 的 UTF-16", "evil.example.net\n".encode("utf-16"),
                 "evil.example.net"),
                ("空文件", b"", None),
                ("只有注释", "# 说明\n\n".encode(), None)):
            p = TMP / f"c054_{abs(hash(label))}.txt"
            p.write_bytes(data)
            r = scope.first_unauthorized_target_list_in_argv(["t.exe", "-l", str(p)])
            got = r[1] if r else None
            check(f"未误伤：{label}", got == want, f"{got!r}（期望 {want!r}）")
    finally:
        config.SCOPE_FILE = saved


# ============================================================ §2.5
def test_providers_atomic_write():
    print("\n=== §2.5 供应商配置：原子写 + 解析失败要备份而不是静默丢 ===")
    saved_file = config.LLM_PROVIDERS_FILE
    saved_backup_dir = config_io.BACKUP_DIR
    p = TMP / "providers053.json"
    config.LLM_PROVIDERS_FILE = p
    # 把「写前备份目录」指到项目外，便于断言「没有往项目里写密钥副本」
    config_io.BACKUP_DIR = TMP / "bk053"
    try:
        providers._write({"providers": [{"id": "x", "api_key": "sk-secret-053"}]})
        check("写入后文件是合法 JSON", json.loads(p.read_text(encoding="utf-8"))
              ["providers"][0]["id"] == "x")
        check("写入后同目录没有半截临时文件残留",
              not [f for f in TMP.glob(".providers053*")], str(list(TMP.glob(".providers053*"))))
        # 关键：密钥文件不得在项目目录里留下副本
        leaked = list((TMP / "bk053").glob("*")) if (TMP / "bk053").exists() else []
        check("写前备份**没有**产生（密钥不得复制进项目目录）",
              not leaked, str([x.name for x in leaked]))
        # 再次写入（覆盖）后内容正确
        providers._write({"providers": [{"id": "y"}]})
        check("覆盖写入内容正确",
              json.loads(p.read_text(encoding="utf-8"))["providers"][0]["id"] == "y")
        # 坏文件：解析失败 → 返回空 + 备份坏文件 + 不炸
        p.write_text('{"providers": [{"id": "z"', encoding="utf-8")     # 半截 JSON
        got = providers._read()
        check("坏文件解析失败返回空（不抛异常）", got == {}, str(got))
        broken = list(TMP.glob("providers053.broken_*.json"))
        check("坏文件被另存一份带时间戳的副本（原来直接丢掉、无任何提示）",
              len(broken) == 1, str([b.name for b in broken]))
        check("备份保留了原始内容（可人工抢救）",
              broken and "providers" in broken[0].read_text(encoding="utf-8"))
    finally:
        config.LLM_PROVIDERS_FILE = saved_file
        config_io.BACKUP_DIR = saved_backup_dir


# ============================================================ 环境自检
def test_preflight():
    print("\n=== §2.6 环境自检（临时目录不可写时要说清是环境问题）===")
    import run_all_tests as rt
    check("提供 preflight_tmp_writable()", hasattr(rt, "preflight_tmp_writable"))
    check("本机自检通过（返回空串）", rt.preflight_tmp_writable() == "",
          rt.preflight_tmp_writable()[:80])
    # 模拟「mkdtemp 成功但不可写」：patch open 抛 PermissionError
    real_open = io.open
    with mock.patch("tempfile.mkdtemp", return_value=str(TMP / "fake_env")), \
         mock.patch("builtins.open", side_effect=PermissionError(13, "denied")):
        msg = rt.preflight_tmp_writable()
    check("不可写时返回非空诊断", bool(msg))
    check("诊断里明确说「这是环境问题，不是被测代码缺陷」",
          "环境问题" in msg and "不是被测代码" in msg, msg[:120].replace("\n", "⏎"))
    check("诊断里给出可操作的下一步（换临时根/换环境）",
          "临时根" in msg or "可写环境" in msg)
    check("诊断里点出典型症状（数据库打不开），便于对号入座",
          "database" in msg or "数据库" in msg)


def main() -> int:
    print("=" * 68)
    print("v053 外部审计修复回归（§2.1 回填原文 / §2.2 响铃 / §2.3 只剥首个 /"
          " §2.4 列表文件 fail-closed / §2.5 原子写）")
    print("=" * 68)
    test_l4_feedback()
    test_execute_unknown_alias()
    test_strip_target_arg()
    test_target_list_file()
    test_providers_atomic_write()
    test_preflight()
    print("\n" + "=" * 68)
    print(f"结果：{len(ok)} 通过 / {len(fail)} 失败")
    if fail:
        print("失败项：" + "、".join(fail))
    print("=" * 68)
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
