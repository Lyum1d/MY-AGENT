# -*- coding: utf-8 -*-
"""通用 LLM 供应商 + 项目增删改 接口回归脚本。

用法（需服务已在 8770 运行）：
  venv_python test_llm_providers.py

## v049 修：两条长期假红（「切到 deepseek」「模型下拉含当前项」）

**真因**：这两条切的是内置 `deepseek`，而本机没配 DeepSeek Key，于是
`providers.set_current` **正确地**返回 400 `未填写 API Key：DeepSeek 深度求索`。
两条断言都要求 `d["current"] == "deepseek"`，所以一起红。

**根因不在切换机制，也不在网络。** 而且这两条假红**误导过两次诊断**：

  ① 第一次归因为「deepseek DNS 解析失败」—— 依据是输出里出现了
     `[Errno 11001] getaddrinfo failed`。**但那行来自第 4 节，而且它是 PASS**：
     第 4 节故意用一个假端点（`api.example.com`）去探测，断言的就是「优雅报错」。
     我把一条**通过**用例里的报错信息当成了失败原因。
  ② 第二次归因为「环境代理拦回环请求」—— 依据是本机有 `HTTP(S)_PROXY`。
     实际 `urllib` 对本机回环是通的（隔离实验验证过），代理不是原因。

**教训（与 v045/v048 同一条）**：失败信息里没带 `d["detail"]`，看的人只能猜；
而「猜出来的因果」比「没有因果」更有害 —— 它会把人带去排查无关的方向。
所以本次顺手把断言失败时的 extra 改成优先打 `detail`。

**改法**：见第 8 节 —— 对**两种环境都成立**（配不配 Key 都绿），
且不再依赖任何本机密钥配置。
"""
import json
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8770"
OK, FAIL, SKIPPED = [], [], []


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    safe_path = urllib.parse.quote(path, safe="/?#&=%")   # 兼容非 ASCII id
    r = urllib.request.Request(
        BASE + safe_path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    # 本机 127.0.0.1 必须绕开全局代理
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(r, timeout=120) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def check(name, cond, extra=""):
    (OK if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' → ' + str(extra)) if extra else ''}")


def skip(name, why):
    """环境不满足时**跳过**而不是判失败。

    为什么需要（v049）：把「Ollama 没起」这类环境问题记成失败，会让「零回归」
    这条信号失真 —— 每次都要人工回忆「这几条是环境红的」，时间一长就没人看了，
    真正的产品问题也会被混在里面。跳过 + 写明原因，跑的人一眼知道该做什么。
    """
    SKIPPED.append(f"{name}（{why}）")
    print(f"  [SKIP] {name} → {why}")


# 运行前的供应商：跑完必须**还回去**。原来收尾硬切 ollama，于是每次回归都把用户的
# 模型选择改掉，下次实战前还得手工切回来（2026-09-23 / 09-25 实测各踩一次）。
_oc, _od = req("GET", "/api/llm/providers")
ORIGINAL_PROVIDER = _od.get("current", "") if _oc == 200 else ""


print("== 1. 预设模板 ==")
code, d = req("GET", "/api/llm/presets")
items = d.get("items", [])
check("预设模板可读", code == 200 and len(items) >= 20, f"{len(items)} 个厂商")
names = [p["name"] for p in items]
check("覆盖主流厂商", all(any(k in n for n in names) for k in
                        ("OpenAI", "DeepSeek", "通义", "GLM", "Kimi", "火山", "硅基", "混元", "Groq", "OpenRouter", "Claude", "Gemini")))

print("== 2. 供应商列表 ==")
code, d = req("GET", "/api/llm/providers")
check("列表接口", code == 200 and len(d["items"]) >= 3, f"current={d.get('current')}")
check("密钥已打码不下发", all("api_key" not in p for p in d["items"]))
check("本地供应商免 Key 判定", [p for p in d["items"] if p["id"] == "ollama"][0]["configured"])

print("== 3. 新增自定义供应商 ==")
code, d = req("POST", "/api/llm/providers", {
    "name": "回归测试端点", "type": "openai",
    "base_url": "https://api.example.com/v1", "api_key": "sk-regress1234567890",
    "model": "test-model",
})
check("创建成功", code == 200 and d.get("ok"), d.get("provider", {}).get("id"))
pid = (d.get("provider") or {}).get("id", "")

print("== 4. 连通性探测（假端点，应优雅报错） ==")
code, d = req("POST", f"/api/llm/providers/{pid}/test")
check("探测不崩、返回结构化结果", code == 200 and "chat" in d, f"chat={d.get('chat')} error={str(d.get('error'))[:60]}")

print("== 5. 拉取模型列表 ==")
code, d = req("GET", f"/api/llm/providers/{pid}/models")
check("模型列表接口", code == 200 and "models" in d)

print("== 6. 编辑（打码值不覆盖密钥） ==")
code, d = req("POST", "/api/llm/providers", {"id": pid, "name": "回归测试端点改名", "api_key": "sk-re…7890"})
check("重命名成功", code == 200 and d["provider"]["name"] == "回归测试端点改名")
code, d = req("GET", "/api/llm/providers")
p = [x for x in d["items"] if x["id"] == pid][0]
check("打码值未污染真实密钥", p["has_key"] and p["key_masked"] == "sk-r…7890", p["key_masked"])

print("== 7. 删除自定义 / 内置保护 ==")
code, _ = req("DELETE", f"/api/llm/providers/{pid}")
check("删除自定义供应商", code == 200)
code, d = req("DELETE", "/api/llm/providers/deepseek")
check("内置供应商拒绝删除", code == 400, d.get("detail"))

print("== 8. 切换供应商 ==")
# ⚠️ v049 修：这一段原先切的是内置 `deepseek`。
# 本机没配 DeepSeek Key 时，`set_current` 会**正确地**拒绝
# （`400 未填写 API Key：DeepSeek 深度求索`），于是每次回归都红两条 ——
# **而红的原因和「切换机制是否正常」毫无关系**。
# 这个假红还误导过两次诊断：先后被归因为「deepseek DNS 解析失败」和
# 「环境代理拦回环」，两次都错（详见文件末的说明）。真凶就是本机缺一个 Key。
#
# 现在的写法对**两种环境都成立**：
#   ① 用测试**自己创建的**供应商验证「切换机制」——它一定有 Key，不依赖本机配置；
#   ② 把「未配 Key 的云端供应商必须被拒，且理由要说明缺 Key」当作**显式契约**钉住
#      （这本来就是产品的正确行为，值得有测试守着，而不是靠环境偶然红绿）。
code, d = req("POST", "/api/llm/providers", {
    "name": "切换测试端点", "type": "openai",
    "base_url": "https://switch.example.com/v1", "api_key": "sk-switch1234567890",
    "model": "switch-model",
})
pid_sw = (d.get("provider") or {}).get("id", "")
check("为切换测试创建供应商（自带 Key，不依赖本机配置）",
      code == 200 and bool(pid_sw), d.get("detail") or d)

code, d = req("POST", f"/api/llm/providers/{pid_sw}/use", {"id": pid_sw})
check("切到自定义供应商", code == 200 and d.get("current") == pid_sw,
      d.get("detail") or d.get("model"))
code, d = req("GET", "/api/models")
check("模型下拉含当前项", code == 200 and d.get("current") == pid_sw,
      f"{len(d.get('items', []))} 个可选，current={d.get('current')}")

# 负向契约：未配 Key 的云端供应商必须被拒，且理由要指明是缺 Key。
# 若本机确实配了 Key，则改为断言「允许切换」—— 两种环境下断言的都是正确行为。
_code, _list = req("GET", "/api/llm/providers")
_ds_has_key = any(x["id"] == "deepseek" and x.get("has_key")
                  for x in _list.get("items", []))
code, d = req("POST", "/api/llm/providers/deepseek/use", {"id": "deepseek"})
if _ds_has_key:
    check("deepseek 已配 Key → 允许切换",
          code == 200 and d.get("current") == "deepseek", d.get("detail"))
else:
    check("未配 Key 的云端供应商被拒（400 且理由指明缺 Key）",
          code == 400 and "API Key" in str(d.get("detail", "")),
          f"{code} {d.get('detail')}")

req("DELETE", f"/api/llm/providers/{pid_sw}")      # 清理：不留垃圾供应商

# 恢复运行前的供应商（而不是硬切 ollama —— 见文件头 ORIGINAL_PROVIDER 的说明）
_rc = 0
if ORIGINAL_PROVIDER:
    _rc, _ = req("POST", f"/api/llm/providers/{ORIGINAL_PROVIDER}/use",
                 {"id": ORIGINAL_PROVIDER})
if _rc != 200:
    req("POST", "/api/llm/providers/ollama/use", {"id": "ollama"})
    print(f"     [提示] 原供应商 {ORIGINAL_PROVIDER!r} 无法恢复"
          f"（可能 Key 已被清空），已回落到 ollama")
    ORIGINAL_PROVIDER = "ollama"
code, d = req("GET", "/api/health")
check(f"恢复运行前的供应商（{ORIGINAL_PROVIDER}）后 health 正常",
      code == 200 and d["current_provider"] == ORIGINAL_PROVIDER,
      f"ready={d['llm']['ready']}")

print("== 9. 项目增删改 ==")
code, p = req("POST", "/api/projects", {"name": "回归测试项目", "target": "example.com"})
check("新建项目", code == 200 and p.get("id"), p.get("id"))
pid_proj = p["id"]
code, d = req("PUT", f"/api/projects/{pid_proj}", {"name": "回归测试项目改名", "target": "demo.example.com"})
check("重命名 + 改目标", code == 200 and d["name"] == "回归测试项目改名" and d["target"] == "demo.example.com")
code, d = req("PUT", f"/api/projects/{pid_proj}", {"note": "备注只改这一个字段"})
check("部分字段更新不丢其它字段", code == 200 and d["name"] == "回归测试项目改名"
      and d["target"] == "demo.example.com" and d["note"] == "备注只改这一个字段")
code, d = req("PUT", "/api/projects/not-exist-id", {"name": "x"})
check("改不存在项目返回 404", code == 404)
code, d = req("PUT", f"/api/projects/{pid_proj}", {"name": "  "})
check("空名称被拒", code == 400, d.get("detail"))
code, d = req("GET", "/api/projects")
check("列表可见该项目", code == 200 and any(x["id"] == pid_proj for x in d["items"]))
code, d = req("DELETE", f"/api/projects/{pid_proj}")
check("删除项目", code == 200 and d.get("ok"))
code, d = req("DELETE", f"/api/projects/{pid_proj}")
check("重复删除返回 404", code == 404)

print("== 10. 本地 Ollama 真实探测（对话 + 工具调用） ==")
# Ollama 没起是**环境**问题，不该判失败 —— 否则「零回归」这条信号会失真：
# 每次都要人工回忆「这几条是环境红的」，久了就没人看了，真正的产品问题也会被埋掉。
code, d = req("POST", "/api/llm/providers/ollama/test")
if code == 200 and d.get("chat"):
    check("本地模型可连通", True,
          f"tools={d.get('tools')} models={len(d.get('models', []))}")
    if d.get("tools"):
        check("本地模型支持 function calling", True)
    else:
        print(f"     [提示] 工具调用探测未通过：{d.get('hint') or d.get('error')}")
else:
    skip("本地模型可连通",
         f"Ollama 未运行或不可用：{d.get('error') or d.get('hint') or code}")

print()
_line = f"结果：{len(OK)} 通过 / {len(FAIL)} 失败"
if SKIPPED:
    _line += f" / {len(SKIPPED)} 跳过"
print(_line)
if FAIL:
    print("失败项：" + "、".join(FAIL))
if SKIPPED:
    print("跳过项：" + "、".join(SKIPPED))
    raise SystemExit(1)
