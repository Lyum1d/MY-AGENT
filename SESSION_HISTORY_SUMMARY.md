# SRC Agent 项目 · 会话历史总结（可移植版）

> 用途：把多轮压缩过的会话浓缩成一份自包含文本。新对话直接读这份即可快速理解项目、当前进度、待办与关键坑位。
> 最后更新：2026-09-03

---

## 〇、TL;DR（给新对话的 30 秒速览）

- **用户目标**：西南石油大学网络空间安全本科（成都），主攻渗透测试 / SRC 漏洞挖掘，正在补天漏洞响应平台做实战，目标是拿下安全服务工程师实习。技术博客 lyum1d.xyz。本地维护「天狐渗透工具箱 V3.0」+ 多套 VMware 虚拟机。
- **本会话主线项目**：一个**本地可控的 SRC 渗透测试编排 Agent**——调度天狐工具箱的工具，自动对**授权目标 `www.jiaoyu.cn`**（公益 SRC，全部 scope 为授权测试资产）做信息收集 / 目录爆破 / 指纹识别 / 漏洞扫描。
- **当前代码状态**：executor / registry 已完成 Phase 1-4 的代码改造（含本会话新增的 `stdin_input` 喂入与 `rscan` 子命令模板）。**但 Phase 4 的数据文件改动（packerfuzzer stdin_input、httpx caveat）尚未写入，服务也未重启验证。** 详见第五节 Pending。
- **模型**：决策循环用本地 Ollama `qwen3.5:9b`，**思考模式必须开**（关掉会退化成纯文本、不调工具）。
- **本会话额外问答**：用户问过「启用云端服务后如何关闭本地模型」——答案见第七节。

---

## 一、系统架构

- **天狐渗透工具箱 V3.0**：PyQt5 启动器，197 工具（50 可编排），由 `config/tools.json` 驱动。
- **Agent 决策**：ReAct 单步决策循环 + Ollama OpenAI 兼容 API（`/v1/chat/completions`，`tools` + `tool_choice:auto`）。模型 `qwen3.5:9b`，约 13-25s/决策。
- **风险分级 L0–L3**：L0/L1 自动执行；L2/L3 需确认（L3 加二次确认）。`www.jiaoyu.cn` 是授权目标，可放开自动执行。
- **服务**：FastAPI + SSE 流式输出，监听 `127.0.0.1:8770`。

## 二、代码位置（`src-agent/`）

| 文件 | 职责 |
|---|---|
| `app/registry.py` | 工具注册表。`Tool` dataclass、`ALIAS_OVERRIDES`（中文名→英文别名）、`load_overrides()`、`build_schemas()`（生成 function calling schema）。 |
| `app/executor.py` | 命令构造与执行。`build_command→_from_template`，参数清洗函数（`_strip_target_arg` / `_filter_unknown_flags` / `_strip_one_layer_quotes` / `_strip_args_quotes`），`run()` 流式执行子进程。 |
| `app/config.py` | 全局配置。`TOOLBOX_ROOT=E:/BaiduNetdiskDownload/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0`；`TOOLBOX_PYTHON`、`JAVA8/11_BIN`；超时与风险常量；`OLLAMA_MODEL=qwen3.5:9b`。 |
| `data/tool_overrides.json` | 每工具的 `caveat` / `allowed_flags` / `value_flags` / `stdin_input` / `timeout` / `disabled`。 |
| `data/invocation_templates.json` | 每工具命令行模板 `{exe}/{target}/{args}` + `target` 形式（url/host/domain/raw）。 |
| `data/risk_grades.json` | 风险分级表。 |
| `data/tiny_wordlist.txt` | 15 条目录字典，端到端验证用。 |
| `test_jiaoyu.py` | 端到端测试驱动。`TARGET="www.jiaoyu.cn"`，`AUTO_APPROVE={"L1","L2"}`，接受 `argv[1]` 自定义任务，用 `httpx.Client(trust_env=False)`。 |
| `run.py` | uvicorn 启动器。 |

## 三、已完成的修复（Phase 1–4 代码部分）

- **Phase 1 — 重复 `-u` 崩溃（0xC0000004）**：`_strip_target_arg` 接入 `_from_template`，剥掉模型在 `args` 里重复填的目标旗标，解决 dirsearch 拼出 `-u a -u b`。
- **Phase 2 — 参数白名单**：`registry.Tool` 加 `allowed_flags` / `value_flags`；`executor` 加 `_filter_unknown_flags`（按白名单剥掉模型臆造的非法旗标）；`dirsearch` 写入 97 个真实 flag 白名单；`build_schemas` 把白名单写进工具说明。
- **Phase 3 — 引号归一化**：`_strip_one_layer_quotes` 改为**递归**（剥 `'"C:/a/b.txt"'` 多层引号）；`_strip_args_quotes` 用于无模板分支；解决模型给路径多包引号导致文件找不到。
- **Phase 4（本会话，代码改完、数据未完）**：
  - `registry.py`：`Tool` 新增 `stdin_input: str = ""`；`load_overrides` 读取 `ov.get("stdin_input", "")`。
  - `executor.py`：`run()` 按 `tool.stdin_input` 决定是否挂 `stdin=PIPE`，启动后用 `asyncio.create_task` **异步喂入并关闭**（与 stdout 读取并行，避免死锁）；用于绕过 `input()` 类交互提问（如 packerfuzzer 的 EOFError）。
  - `invocation_templates.json`：新增 `rscan` → `"{exe} scan -u {target} {args}"`（**注意：本会话修正过一次——之前误写成 `"RScan scan -u ..."` 会重复 `RScan` 字面量导致 `unknown command`；已改为 `{exe}` 占位**）。rscan 是命令行二进制 `Rscan_win64.exe`，cobra 子命令 `scan` 不依赖二进制名。

## 四、关键约定与坑位（务必记住）

- **HTTP_PROXY 污染**：WorkBuddy 设 `HTTP_PROXY=127.0.0.1:52617`；本地 `httpx` 调用必须 `trust_env=False`，否则请求被转发到代理而失败。
- **PowerShell 进程枚举在沙箱失效**：`Get-CimInstance Win32_Process` 返回空。定位端口占用用 `netstat -ano | grep :8770` + `taskkill /PID <pid> /F`（Git Bash）。
- **命令构造管线**（`build_command→_from_template`）：归一化 target → 剥重复 target 旗标 → 按白名单剥非法 flag → 剥冗余引号 → 渲染模板。
- **flag 白名单规则**：`allowed_flags` 为空 = 不校验；`value_flags` 标记会吞下一个 token 的取值旗标；布尔旗标不吞下一个 token（避免误删真实位置参数）。
- **`_target_flag` 用负向前瞻** `(?![-\w])` 避免误伤 `--target-extra` 类长旗标。
- **总时长超时 vs 空闲超时**：连续输出工具（如 enscan 每 10s 刷「需要安全验证」）必须设**绝对 deadline**，不能只靠 idle 超时。
- **自动批准的脆弱工具**：`packerfuzzer`(L1)、`rscan`(L1)、`httpx`(L1) 均为自动批准——它们的失败必须在跑真实任务前修掉，否则每轮决策都崩。
- **Ollama 思考模式**：`qwen3.5:9b` 关闭 thinking 会退化、不再调工具，必须保持开启（`OLLAMA_THINKING=True`）。

## 五、Pending（Phase 4 尚未完成的数据 / 验证步骤）✅ 已全部完成（2026-09-03）

> **完成记录**：2026-09-03 已按本清单逐项收尾，全部通过：
> 1. `tool_overrides.json` 两项已写入：`packerfuzzer.stdin_input="\n\n"`（附 caveat 说明自动应答按非暴力默认模式）+ `timeout: 300`；`httpx` caveat（-timeout 纯数字、勿重复 -u）。
> 2. `python -m compileall -q app` 通过，registry 加载确认 stdin_input / caveat 生效。
> 3. 服务已重启（含模型切换功能与 DeepSeek Key）。
> 4. 实测验证（`verify_phase4.py`，直接驱动 executor 对 `https://www.jiaoyu.cn`，不经 LLM）：
>    - **httpx**：`-timeout 5` 正常，exit 0，检出站点存活 ✅
>    - **rscan**：模板 `{exe} scan -u` 渲染正确，exit 0，无 unknown command，正常产出扫描结果 ✅
>    - **packerfuzzer**：stdin 喂入 `\n\n` 后两处 `input()` 均按默认应答，exit 0，无 EOFError / Traceback，完整跑完并生成报告 ✅
>    （注：packerfuzzer 会尝试访问 api.ceye.io 做 API 收集，未配置 ceyeApi 时该分支自动跳过，不影响运行。）
> 5. Phase 1–4 代码 + 数据已全部在当前运行实例中生效。

**原始 Pending 清单（存档）：**

1. **`data/tool_overrides.json` 仍需添加**：
   - `packerfuzzer`：`{"stdin_input": "\n\n"}`（或足够换行，绕过 `lib/ApiCollect.py:207` 与 `:240` 两处 `input()` 提问）。注意：第一处是「强检测/暴力模式」提问，空输入应走默认（非暴力）模式，对授权测试更安全。**换行数需实测确认**（可能要 2 个以上或特定字符）。
   - `httpx`：`{"caveat": "...-timeout 只用纯数字秒数，不要带 s 后缀（fork 拒绝 3s 这种写法，会报 invalid）..."}`。
2. **重新编译**：`python -m compileall -q app`（或 `py_compile`）。
3. **重启服务**：先 `netstat -ano | grep :8770` 找旧 PID（上一次是 `38988`）并 `taskkill /PID <pid> /F`；再以 `TOOL_TIMEOUT=180 TOOL_IDLE_TIMEOUT=90 AGENT_MAX_STEPS=14 python run.py --no-browser` 启动。
4. **重跑验证** `test_jiaoyu.py`：确认 packerfuzzer 退出 0（无 EOFError）、rscan 使用 `scan -u`、httpx 不再因 `-timeout 3s` 失败。
5. **当前运行的服务（PID 38988）仍是 Phase 2-3 代码，未含 Phase 4 改动，必须重启后生效。**

## 六、下一步建议（给未来会话）

- ~~优先完成第五节~~（✅ 2026-09-03 已完成）。
- ~~让 Agent 在 `www.jiaoyu.cn` 完整跑一轮多工具编排，产出首份 SRC 报告~~（✅ 2026-09-03 完成，三轮编排：httpx/veo/OneForAll → dirsearch → OneForAll/PackerFuzzer 全部跑通；完整版报告在 `data/artifacts/b2d75b1a58ab/报告_补天公益SRC-www.jiaoyu.cn_20260903_完整版.md`）。
  - **新坑 A（已修复）**：服务从精简环境 shell 启动时缺 `APPDATA`，dirsearch 的 pyfiglet 直接 KeyError 崩溃 → executor 已做防御性补全（APPDATA/LOCALAPPDATA/TEMP/TMP）。
  - **新坑 B（已修复）**：dirsearch 用 `\r` 刷进度条，readline 的 64KB 缓冲被积压超长行打爆（"Separator is not found"）→ executor 读取循环已改为按 4096 字节块读取 + 按 `\r\n|\n|\r` 切行。
  - **挖洞研判**：该站有 WAF（目录爆破全量 500/502 拦截页），字典爆破无效；下一步攻击面是 PackerFuzzer 提取的 65 条真实 API（越权方向）；`/actuator/dump` 已复核为 **SPA fallback 假阳性**（200 + text/html + 1536B 与主页一致，非真实 Actuator）。
- **agent.py 兜底解析（2026-09-03 新增）**：qwen 偶尔把工具调用写成 markdown 代码块或不产生 tool_calls（产生 name="tool_call" 的畸形调用）。新增 `_parse_tool_from_markdown()`：从输出文本的 ```bash/```json 代码块恢复真实调用（首个 token 必须能 resolve 到真实工具才触发，防误伤）；已接入 run() 的「无 tool_calls」与「工具名不存在」两条分支。注意 `springboot_scan` 是注册表真实工具，模型写它不再被拦截。服务重启后生效。
- **API 未授权探测（2026-09-03，只读完成）**：`api_auth_test.py` 对 31 条 API 无参 GET + 基线对照。结论：www 主站 /api/* 全为 SPA fallback，真实后端在专用域 `apps-api`（鉴权正常）/`xuexi-api`（鉴权正常）/`api-yxt`（PHP/CodeIgniter，未登录可达业务逻辑层但需有效实体 ID）；无 swagger/actuator 暴露；**0 可提交漏洞**。明细 `api_auth_test_results.json`。下一步方向已写入报告 §4.3。
- 可选（此前决定「先只管 Windows」暂缓）：接 Kali VM SSH executor，实现 `SSHExecutor`。

## 七、本会话关键问答：SRC Agent 启用云端模型后如何停用本地模型

**用户实际问题是**：SRC Agent 当前决策循环跑在本地 Ollama `qwen3.5:9b` 上（思考必须开）。若切换到云端模型，本地 Ollama 该怎么停、Agent 怎么改配置。

**答（针对 SRC Agent 代码，不是桌面端 WorkBuddy）**：
1. **切换 Agent 后端到云端（路径 A：换 backend 类）**：在 `app/config.py` 把 `DEFAULT_BACKEND` 从 `"ollama"` 改为 `"deepseek"`，并设置环境变量 `DEEPSEEK_API_KEY`（见 `README.md`）。`agent.py:149` 用 `backend_name or config.DEFAULT_BACKEND` 选后端，`get_backend()` 据此返回 `DeepSeekBackend`（走 `config.DEEPSEEK_BASE_URL` / `DEEPSEEK_MODEL`）。重启 `run.py` 即生效；也可新建 Agent 时显式传 `backend_name="deepseek"`。
2. **切换 Agent 后端到云端（路径 B：复用 ollama 客户端类，只改端点）**：保留 `DEFAULT_BACKEND="ollama"`，把 `OLLAMA_BASE_URL` 指向任意云端 OpenAI 兼容 `/v1` 端点（OllamaBackend 本质就是 OpenAI 兼容客户端）。这样无需改 backend 类即可用云端模型。
3. **确认本地 Ollama 不再被调用**：后端切到云端后，决策循环不再访问 `http://localhost:11434`，本地 Ollama 自然不再被 Agent 使用。
4. **真正停掉 Ollama 后台进程（释放显存/内存）**：Ollama 默认后台常驻。Windows 右键托盘 Ollama 图标退出 / 任务管理器结束 `ollama.exe`；macOS/Linux `ollama stop` 或 `pkill ollama`。
5. **⚠️ 已知小坑**：`app/main.py:61` 的 `/api/health` 健康检查**硬绑了 `get_backend("ollama")`**——即使 `DEFAULT_BACKEND=deepseek`，health 接口仍会去 ping 本地 Ollama。若把 Ollama 彻底停了，该接口会报 unhealthy。如需彻底解耦，可把该行改为 `get_backend()`（用默认后端）。
6. **切换前注意**：`qwen3.5:9b` 依赖 thinking 模式才能稳定调工具；换云端模型需确认其支持 function calling / tool use，否则 ReAct 决策循环会失效（如 deepseek-chat 支持工具调用，可平滑替换）。

> 注：本节最初误写成「桌面端 WorkBuddy 如何关闭本地模型」（选择器/设置/停 Ollama 三层法），那是 WorkBuddy 客户端自身话题，与 SRC Agent 无关，已按用户实际意图（src agent 启用云端模型后停用本地模型）更正。

---

## 八、新增功能：前端模型切换（2026-09-02 完成）

用户需求：前端可一键选择本地模型 / 云端模型。已实现并验证：

- **`app/llm.py`**：新增运行时后端状态 `_current_backend`（默认 `config.DEFAULT_BACKEND`），`set_backend(name)` 切换并持久化到 `data/runtime.json`（服务重启保持选择）；DeepSeek 未配 Key 时切换被拦截（RuntimeError）；非法后端名拦截（ValueError）。`DeepSeekBackend` 补了 `health()`（只查 Key 配置，不真实探测、不耗配额）。Ollama/DeepSeek 的 httpx 客户端都加了 `trust_env=False`（防 HTTP_PROXY 污染，见第四节坑位）。
- **`app/main.py`**：新增 `GET /api/models`（当前后端 + 可选项列表）与 `POST /api/models {"backend": "ollama"|"deepseek"}`（切换，校验失败返回 400）。**顺带修复 `/api/health` 硬绑 `get_backend("ollama")` 的旧坑**（第七节第 5 条）——现在按当前运行时后端检查。
- **`app/agent.py`**：`Agent.__init__` 不再在模块加载时钉死后端（`self.backend_name` 保持 None），每轮 `run()` 时取运行时当前后端，**切换后无需重启即对新任务生效**。会话开始时向前端推 `{"type": "model", ...}` 事件。
- **`web/index.html` + `web/app.js`**：任务输入框左侧新增模型下拉框（`#modelSelect`），显示「本地模型 · qwen3.5:9b / 云端模型 · deepseek-chat（未配置时禁用）」；切换即时生效并写日志；状态栏显示当前后端及就绪状态；每轮任务开始时日志会打印本轮使用的模型。
- **云端切换方法**：先设置环境变量 `DEEPSEEK_API_KEY`（重启服务使变量生效），前端下拉框即自动启用云端选项。

> **2026-09-02 补充**：DeepSeek API Key 已实测有效并写入 `启动控制台.bat`（`set DEEPSEEK_API_KEY=...`），双击 bat 启动即自动带上；云端 `deepseek-chat` 已验证支持 function calling（tool_call + 参数正确产出）。当前默认后端保持 ollama，云端切换在前端下拉框点选即可。注意：Key 以明文存在于 bat 中，勿将项目目录打包外发；Key 若泄露需在 DeepSeek 平台重置。

> 注意：本节改动与第五节 Pending 互相独立——Phase 4 的 `tool_overrides.json` 两项数据改动已于 2026-09-03 补完并验证通过（见第五节完成记录）。

---

## 附：本会话实际改动清单

- `app/registry.py`：`Tool` 加 `stdin_input` 字段 + `load_overrides` 读取。
- `app/executor.py`：`run()` 子进程按 `stdin_input` 挂 PIPE 并异步喂入关闭。
- `data/invocation_templates.json`：新增 `rscan` 模板（并修正为 `{exe} scan -u ...`）。
- 待补：`data/tool_overrides.json` 的 `packerfuzzer.stdin_input` 与 `httpx.caveat`（见第五节）。
