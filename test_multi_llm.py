# -*- coding: utf-8 -*-
"""多模型供应商回归测试（Python 模块层）：预设目录 + 配置读写 + 切换校验 + 后端工厂 + 连通性探测。

与 test_llm_providers.py 的分工：那个走 **HTTP 接口**，这个直接测 **providers / llm 模块**，
粒度更细（能验证 Key 脱敏规则、签名缓存、按 type 分派后端这些接口层看不到的东西）。

    python test_multi_llm.py

安全约束（重要）：
  · **绝不碰真实配置**。供应商配置默认在 ~/.src_agent_llm.json，测试一开始就把
    config.LLM_PROVIDERS_FILE 改道到临时目录，结束再还原并 invalidate()。
  · **不发任何真实请求给厂商**。连通性只打 127.0.0.1:9（必然连不上），
    不消耗云端额度，也不依赖网络。
  · 唯一需要网络的是本地 Ollama 探测，那里做了降级断言（不通不算失败）。

历史：本文件曾因「通用供应商接入」重构而失效（原用 all_ids/resolve/cloud_ids/set_config/
reset_config/resolve_override/llm.reset_backend，这些 API 已全部移除），且有 3 条断言与
当前设计相反（「内置厂商 ≥9」「未配 Key 的 qwen」「端点不可达 → ok=False」）。
本版按当前设计重写，并特意把这几条**反过来的正确行为**钉成断言，防止再退化。
"""
import asyncio
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app import config                                          # noqa: E402

# ---- 必须在 import providers 之前改道，否则会读到/写到用户真实配置 ----
_TMP = Path(tempfile.mkdtemp(prefix="src_multi_llm_"))
_ORIG_FILE = config.LLM_PROVIDERS_FILE
config.LLM_PROVIDERS_FILE = _TMP / "llm_providers.json"

from app import llm, providers                                   # noqa: E402

FAKE_KEY = "sk-regression-test-not-a-real-key"
DEAD_URL = "http://127.0.0.1:9/v1"        # 必然连不上，用来验证失败/降级分支

ok: list[str] = []
fail: list[str] = []


def check(name: str, cond, extra="") -> None:
    (ok if cond else fail).append(name)
    tag = "PASS" if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" → {extra}" if extra else ""))


def reset_all() -> None:
    """回到出厂状态：清空配置缓存 + 后端实例缓存。"""
    providers.invalidate()
    llm._backends.clear()
    llm._backend_sig.clear()


async def main() -> int:
    reset_all()

    # ---------------------------------------------------------------
    print("=== 1. 预设目录与内置注册表 ===")
    presets = providers.presets()
    check("预设模板数量足够", len(presets) >= 20, f"{len(presets)} 个")
    names = " ".join(p["name"] for p in presets)
    check("预设覆盖主流厂商",
          all(k in names for k in ("DeepSeek", "通义千问", "智谱", "Kimi", "OpenAI", "Claude")),
          names[:60])
    # custom 是「自定义端点」模板，端点与模型本来就该留空让用户填，不计入完整性
    check("预设字段完整（custom 模板的端点/模型按设计留空）",
          all(p.get("key") and p.get("name") and p.get("type")
              and (p["key"] == "custom" or (p.get("base_url") and p.get("model")))
              for p in presets),
          [p["key"] for p in presets
           if not (p.get("key") and p.get("name") and p.get("type"))])
    check("预设含 anthropic 协议类型（不是所有端点都走 /chat/completions）",
          any(p["type"] == "anthropic" for p in presets),
          [p["key"] for p in presets if p["type"] == "anthropic"])
    probe = presets[0]
    probe["name"] = "被外部改坏了"
    check("presets() 返回副本，外部改动不污染模块常量",
          providers.presets()[0]["name"] != "被外部改坏了")

    check("内置三个供应商", set(providers.BUILTIN_IDS) == {"ollama", "deepseek", "anthropic"},
          providers.BUILTIN_IDS)
    ids = [p["id"] for p in providers.list_providers()]
    check("默认配置内置齐全", all(b in ids for b in providers.BUILTIN_IDS), ids)
    check("内置供应商拒绝删除", providers.delete("ollama") is False)

    listed = {p["id"]: p for p in providers.list_providers()}
    check("ollama 免 Key 即视为已配置", listed["ollama"]["configured"] is True)
    check("未填 Key 的云端供应商未配置", listed["deepseek"]["configured"] is False)

    # ---------------------------------------------------------------
    print("=== 2. 配置读写与脱敏 ===")
    providers.upsert({"id": "deepseek", "api_key": FAKE_KEY})
    p = providers.get("deepseek")
    check("写入 Key 后 get() 能取到原文", p["api_key"] == FAKE_KEY)
    check("写入后变为已配置", providers.list_providers()[ids.index("deepseek")]["configured"])

    masked = providers.mask(FAKE_KEY)
    check("Key 已脱敏（不含原文）", FAKE_KEY not in masked and "…" in masked, masked)
    check("短 Key 脱敏为 ****", providers.mask("abc") == "****", providers.mask("abc"))
    check("空 Key 脱敏为空串", providers.mask("") == "")
    lst = providers.list_providers()
    check("列表接口绝不下发 api_key 原文",
          all("api_key" not in p for p in lst))
    with_key = [p for p in lst if p["has_key"]]
    check("有 Key 的供应商都给出打码值",
          with_key and all(p["key_masked"] and p["key_masked"] != FAKE_KEY for p in with_key),
          f"{len(with_key)} 个有 Key")
    check("无 Key 的供应商打码值为空串",
          all(p["key_masked"] == "" for p in lst if not p["has_key"]))

    # 这两条是刻意设计：编辑其它字段（比如只改模型名）保存时不能把 Key 清空
    providers.upsert({"id": "deepseek", "model": "deepseek-reasoner", "api_key": ""})
    check("空 Key 不覆盖已有密钥（改模型名别把 Key 清了）",
          providers.get("deepseek")["api_key"] == FAKE_KEY)
    providers.upsert({"id": "deepseek", "api_key": providers.mask(FAKE_KEY)})
    check("打码值回传不覆盖已有密钥",
          providers.get("deepseek")["api_key"] == FAKE_KEY)
    check("模型名确实改掉了", providers.get("deepseek")["model"] == "deepseek-reasoner")

    # R4 红线：内置 ollama 思考模式恒开，关掉会退化成纯文本、不再调工具
    providers.upsert({"id": "ollama", "thinking": False})
    check("内置 ollama 的 thinking 被强制锁定为 True",
          providers.get("ollama")["thinking"] is True)

    custom = providers.upsert({"name": "回归测试自定义端点", "type": "openai",
                               "base_url": DEAD_URL, "api_key": FAKE_KEY,
                               "model": "regression-model"})
    cid = custom["id"]
    check("新建供应商自动生成 id", bool(cid) and cid not in providers.BUILTIN_IDS, cid)
    check("base_url 末尾斜杠被规范化", custom["base_url"] == DEAD_URL)
    providers.upsert({"id": cid, "name": "回归测试改名"})
    check("重命名生效", providers.get(cid)["name"] == "回归测试改名")

    # ---------------------------------------------------------------
    print("=== 3. 切换与校验 ===")
    providers.reset_builtin("deepseek")
    check("恢复默认清空 Key", providers.get("deepseek")["api_key"] == "",
          providers.get("deepseek")["api_key"])
    try:
        providers.set_current("deepseek")
        check("切到未填 Key 的云端应报错", False)
    except ValueError as e:
        check("切到未填 Key 的云端应报错", True, str(e)[:40])
    try:
        providers.set_current("不存在的供应商")
        check("切到不存在的 id 应报错", False)
    except ValueError:
        check("切到不存在的 id 应报错", True)
    providers.upsert({"id": cid, "enabled": False})
    try:
        providers.set_current(cid)
        check("切到已停用的供应商应报错", False)
    except ValueError:
        check("切到已停用的供应商应报错", True)
    providers.upsert({"id": cid, "enabled": True})

    providers.set_current("ollama")
    check("切换到 ollama 成功并持久化", providers.current_id() == "ollama")
    check("current() 返回完整配置", providers.current()["id"] == "ollama")

    # ---------------------------------------------------------------
    print("=== 4. 后端工厂与缓存 ===")
    b_ollama = llm.build_backend(providers.get("ollama"))
    check("本地 ollama 走 OllamaBackend（用 /api/tags 探测）",
          isinstance(b_ollama, llm.OllamaBackend), type(b_ollama).__name__)
    check("普通 OpenAI 兼容端点走 OpenAICompatBackend",
          isinstance(llm.build_backend(providers.get("deepseek")), llm.OpenAICompatBackend))
    check("anthropic 类型走原生协议后端",
          isinstance(llm.build_backend(providers.get("anthropic")), llm.AnthropicBackend))
    check("ollama 后端免 Key 可用", b_ollama.available() is True)
    check("未配 Key 的云端后端不可用",
          llm.build_backend(providers.get("deepseek")).available() is False)

    # 用随机模型名：万一和默认模型同名，签名不变、实例就不会重建，断言会变成假失败
    new_model = "regression-" + uuid.uuid4().hex[:6]
    b1 = llm.get_backend("deepseek")
    providers.upsert({"id": "deepseek", "model": new_model})
    b2 = llm.get_backend("deepseek")
    check("改配置后后端实例被重建（签名缓存生效，无需重启）", b1 is not b2)
    check("重建后拿到新模型", b2.model == new_model, b2.model)
    check("同一配置复用同一实例", llm.get_backend("deepseek") is b2)

    check("无可用云端时自动路由返回 None（不会悄悄改道）",
          llm.auto_route_candidate("ollama") is None)
    providers.upsert({"id": "deepseek", "api_key": FAKE_KEY, "base_url": DEAD_URL})
    cand = llm.auto_route_candidate("ollama")
    check("配好云端后自动路由给出目标", cand is not None and cand.id == "deepseek",
          getattr(cand, "id", None))
    check("当前就是云端时不重复路由", llm.auto_route_candidate("deepseek") is None)
    providers.set_auto_route(False)
    check("关闭自动路由后不再改道", providers.auto_route_id() == "")

    # ---------------------------------------------------------------
    print("=== 5. 连通性探测（只打不可达端点） ===")
    dead = llm.build_backend({"id": "dead", "name": "不可达", "type": "openai",
                              "base_url": DEAD_URL, "model": "m", "api_key": FAKE_KEY})
    h = await dead.health()
    # 当前设计：模型列表不通不代表聊天不通（部分网关禁用 /models），降级为 ok=True + reason
    check("不可达端点降级为 ok=True + reason（不再判死）", h.get("ok") is True,
          str(h.get("reason"))[:50])
    check("降级时模型列表为空", h.get("models") == [], h.get("models"))
    check("降级时仍标记可用（不阻塞使用）", h.get("ready") is True)

    unconf = llm.build_backend({"id": "x", "name": "未配置", "type": "openai",
                                "base_url": "", "model": "", "api_key": ""})
    h2 = await unconf.health()
    check("未配置后端判为不可用", h2.get("ok") is False, h2.get("reason"))

    local = await llm.build_backend(providers.get("ollama")).health()
    check("本地 ollama 探测不抛异常", isinstance(local, dict) and "ok" in local,
          f"ok={local.get('ok')} model={local.get('model')}")

    # ---------------------------------------------------------------
    print("=== 6. 删除与回退 ===")
    providers.set_current(cid)
    check("切到自定义供应商", providers.current_id() == cid)
    check("删除自定义供应商成功", providers.delete(cid) is True)
    # [2026-09-16 对齐 v006] 回退目标由「一律回本地 ollama」改成「默认优先云端」：
    # config.PREFERRED_PROVIDER = deepseek（用户 2026-09-15 的明确要求），
    # providers._pick_default 的顺序为 ①PREFERRED_PROVIDER（已启用且配置完整）
    # ②其它已启用且配置完整的非本地供应商 ③本地 ollama 兜底。
    # 所以删掉当前供应商后应回落到 deepseek，只有云端全不可用才回本地。
    fallback = providers.current_id()
    check("删除当前供应商后回退到云端首选（deepseek）", fallback == "deepseek", fallback)
    check("本地 ollama 仍在候选里兜底（没被顺手删掉）",
          any(i["id"] == "ollama" for i in providers.list_providers()),
          [i["id"] for i in providers.list_providers()])
    check("再次删除返回 False", providers.delete(cid) is False)

    return 0


if __name__ == "__main__":
    code = 0
    try:
        code = asyncio.run(main())
    finally:
        # 无论如何都要还原：真实配置文件路径 + 缓存，别把测试状态留给下一次运行
        config.LLM_PROVIDERS_FILE = _ORIG_FILE
        reset_all()
        shutil.rmtree(_TMP, ignore_errors=True)

    print(f"\n{'=' * 56}")
    print(f"  通过 {len(ok)} 项，失败 {len(fail)} 项")
    for name in fail:
        print(f"    FAIL: {name}")
    print(f"  临时配置：{_TMP}")
    print("=" * 56)
    sys.exit(1 if fail else (code or 0))
