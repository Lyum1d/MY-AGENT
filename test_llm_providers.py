# -*- coding: utf-8 -*-
"""通用 LLM 供应商 + 项目增删改 接口回归脚本。

用法（需服务已在 8770 运行）：
  venv_python test_llm_providers.py
"""
import json
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8770"
OK, FAIL = [], []


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
code, d = req("POST", "/api/llm/providers/deepseek/use", {"id": "deepseek"})
check("切到 deepseek", code == 200 and d["current"] == "deepseek", d.get("model"))
code, d = req("GET", "/api/models")
check("模型下拉含当前项", code == 200 and d["current"] == "deepseek",
      f"{len(d['items'])} 个可选")
req("POST", "/api/llm/providers/ollama/use", {"id": "ollama"})   # 切回本地
code, d = req("GET", "/api/health")
check("切回 ollama 后 health 正常", code == 200 and d["current_provider"] == "ollama",
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
code, d = req("POST", "/api/llm/providers/ollama/test")
check("本地模型可连通", code == 200 and d.get("chat"), f"tools={d.get('tools')} models={len(d.get('models', []))}")
if d.get("tools"):
    check("本地模型支持 function calling", True)
else:
    print(f"     [提示] 工具调用探测未通过：{d.get('hint') or d.get('error')}")

print()
print(f"结果：{len(OK)} 通过 / {len(FAIL)} 失败")
if FAIL:
    print("失败项：" + "、".join(FAIL))
    raise SystemExit(1)
