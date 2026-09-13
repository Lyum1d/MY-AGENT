# SRC 渗透 Agent · 本地控制台

对话驱动的渗透测试编排平台，可调度天狐渗透工具箱 V3.0 中的工具，面向 SRC（补天）漏洞挖掘场景。

## 快速开始

三种启动方式（任选其一）：

```bat
双击「SRC控制台.exe」  → 桌面独立窗口（推荐，自动拉起 Ollama，见下节）
双击「启动控制台.bat」 → 浏览器打开
python run.py          → 命令行启动（--no-browser 不自动开浏览器）
```

默认地址：<http://127.0.0.1:8770>（exe/bat 均已内置 `TOOLBOX_ROOT` 与本机 venv 定位，无需手配环境变量）

> 首次使用建议：先建「项目」（如"补天-XX厂商"），把任务发到选中的项目下，Agent 的每步输出、
> 已证事实与漏洞登记才会归档到该项目，报告才能聚合生成。
> **项目里的「目标」会自动注入每次决策**：任务描述没写域名/企业名时，模型以项目目标为准；
> 填的是企业名会先引导用 app_info 扩展资产（enscan 因需人工验证码已禁用）。
>
> 界面为 Trae/WorkBuddy 风格对话式布局（深色/亮色可切换，右上角 🌙/☀️ 按钮）：
> 左侧边栏管「项目/工具箱」，中间是对话气泡流（AI 回复内含执行计划、命令/输出代码块与结论），
> 右侧「报告」面板记录漏洞发现与已证事实（可折叠）。
> 左栏项目列表支持**重命名与删除**：鼠标移到条目上会出现「重命名 / 删除」按钮，重命名是
> 内联编辑（改名称与目标），删除需二次确认（会连带删除该项目下的漏洞、已证事实与会话记录）。
> 决策模型在底部下拉框或「设置 → 模型供应商」中切换，可接入任意 OpenAI 兼容 / Anthropic 端点。

## 桌面版（SRC控制台.exe）

`desktop_launcher.py` 为桌面壳启动器，双击 `dist/SRC控制台.exe`（约 8.6MB）即可弹出独立桌面窗口：

- 自动检测并拉起本地 Ollama（11434 未监听时）；后端服务若未在运行则自动启动，随后弹窗加载界面。
- 单实例互斥（重复双击只会提示已有实例）；错误以原生弹窗提示；运行日志在 `logs/desktop.log`。
- 该 exe 是「委派式」轻量壳：定位本机 venv 的 python 来执行 GUI（PyInstaller 冻结 pythonnet 在本机
  webview 启动会原生崩溃，已实测多方案后采用此架构），因此需与 `desktop_launcher.py` 放在同一目录
  （项目根）使用。
- 自检：`python desktop_launcher.py --smoke`（无窗口验证链路）；重新打包 exe 见文件头注释。


## 核心设计

### 单步决策 ReAct 循环

**不要让模型一次规划全部步骤**——实测 `qwen3.5:9b` 在这种模式下只输出文字方案、不产生工具调用。
这里每次只让它决定"下一步用哪个工具"，执行完把真实结果回喂，再问下一步。

### 思考模式必须开启

实测关闭思考模式（`thinking: false`）后，模型退化成纯文本输出、不再调用工具。
`config.py` 中 `OLLAMA_THINKING = True`，**不要为了省时间关掉**。

### 三层防幻觉

本地小模型有三类典型错误，都已针对性拦截：

| 问题 | 表现 | 处理 |
|---|---|---|
| 编造工具名 | 返回工具箱没有的 `subfinder` | 用 `tools.json` 注册表校验，不认识就拒绝并回传可用清单 |
| 拼错工具名 | `eohole` | 模糊匹配自动纠正为 `ehole` |
| 参数填错 | 把"请提供目标"当 target | `validate_target()` 拦截说明性文字 |

### 目标重申

模型在工具执行失败后常"忘记"目标并反问用户。
每轮决策时从任务描述提取目标并注入系统提示，实测可解决。

### 已证事实库（防幻觉/防重复）

每个项目有一张「已证事实」表，只存放**由工具输出证实的客观事实**（凭据、漏洞点、敏感路径等）：

- Agent 可随时调用内置工具 `note_fact`（L0）把确证内容写入；右栏「已证事实」区也可人工登记/删除。
- 每轮决策自动把最近 20 条事实注入上下文，标注「可直接引用、不得推翻或重复验证」。
- 提示词内固化纪律：禁止编造漏洞/凭据/flag；报告结论先给证据确凿者，再扩展可疑点。

### 内置工具（始终对 LLM 可见，不占配额）

除工具箱工具外，注册表内置 8 个能力（`app/registry.py::_add_builtin_tools`）：

| 别名 | 风险 | 作用 |
|---|---|---|
| httpreplay | L2 | 受控 HTTP 重放（只读方法 + 域名白名单） |
| nuclei_cli | L2 | nuclei 模板漏洞验证 |
| note_fact | L0 | 记录已证事实（见上） |
| py_exec | L3 | **Python 代码执行通道**：让 Agent 对单点任务直接写代码（HTTP 用 httpx/requests），代码留档 `data/scripts/exec/`，超时自动中断 |
| search_history | L0 | 跨线索检索项目内历史工具输出 |
| kb_search / kb_read | L0 | **SRC 知识库检索/阅读**（`data/kb/` 49 篇漏洞类型打法 + `data/rules/` 11 篇工作流规则，来自外部方法论包经安全审查后移植） |
| fofa_search | L1 | **FOFA 资产测绘**（key 在本机 config.yaml 的 fofaEmail/fofaKey，未配置则提示；查询只走 fofa.info） |

知识库使用纪律已写入系统提示：进站先读「打穿短表」，按目标特征（用户体系→越权、上传→file-upload、
支付→logic+race-condition 等）kb_search 找对应篇目再动手；CORS 永不挖；写正式报告前先读
`vuln-report-format`（取舍闸门）；FOFA 按「一种子闭环」节奏使用。

`py_exec` 借鉴了 Intent Engineering 思路（意图直出代码而非碎片化工具串），能力等同本机命令行，
故定级 L3：需用户确认 + 勾选书面授权才会执行。

### 对话树（线索分支，非线性对话）

单条对话聊太久后模型会"遗忘"细节，无法对单个方向深挖。对话树把一次测试拆成
多条独立线索并行推进：

- **横向小地图**：聊天区上方是当前项目的「线索树」，节点按分支层级从左到右排列，
  颜色区分状态（进行中 / 已完成 ✓ / 已放弃 ✕），点击节点即切换到那条对话（**历史对话按原气泡样式回放**：
  用户消息、AI 说明与结论均持久化在 chat_messages 表，旧会话自动回退为步骤+摘要展示）。
- **开新线索（两种方式）**：
  - AI 发现值得单独深挖的可疑点时，调用内置工具 `propose_branch` 在聊天里发一张
    「开新线索」卡片（含建议标题与可打包的执行记录勾选清单），确认后自动创建并切换；
  - 手动：线索树节点 / 顶栏「＋ 分支」按钮，从该线索最近的步骤里勾选记录打包带走。
- **开局背景**：新线索携带打包记录（工具输出摘要），系统提示明确「可直接引用、不要重复验证」。
- **翻旧账**：内置工具 `search_history`（L0）跨线索检索项目内所有会话的历史工具输出，
  其他线索的进展摘要也会注入系统提示；同线索内连续发消息即续聊（上下文累积）。
- **成果回流**：线索给出结论后，摘要自动落库并实时推送给父会话（`branch_update` 事件），
  主对话随时掌握全局。
- 风险分级（L2 确认 / L3 二次确认）与授权白名单校验在线索间**完全一致**，切换对话形式不放松任何闸门。

相关接口：`GET /api/projects/{pid}/tree`、`POST /api/sessions/{sid}/branch`、
`PUT /api/sessions/{sid}/meta`、`POST /api/sessions`（body 带 `sid` 时为恢复已有会话续聊）。

## 工具能力边界

工具箱 199 个工具 + 4 个内置能力；其中 **54 个可编排**（有 stdout，能进自动化流水线，
含内置的 httpreplay / nuclei_cli / note_fact / py_exec），其余为图形界面工具（一键启动）与网页工具。

可编排工具按风险分为四级（实测分布 L0:14 / L1:11 / L2:8 / L3:21）：

| 等级 | 含义 | 策略 | 数量 |
|---|---|---|---|
| L0 | 只读 / 本地分析 | 自动执行 | 14 |
| L1 | 主动探测扫描 | 自动执行（留痕） | 11 |
| L2 | 漏洞验证与利用 | 需确认 | 8 |
| L3 | 权限 / 横向 / 接管 | 需确认 + 勾选授权 | 21 |

拒绝执行时 Agent 会自动改用更低风险的工具继续任务。

## 目录结构

```
src-agent/
├── run.py                    启动入口
├── requirements.txt
├── 启动控制台.bat             浏览器一键启动（GBK/CRLF，勿改编码）
├── desktop_launcher.py       桌面壳启动器（SRC控制台.exe 的源脚本，支持 --smoke 自检）
├── src_console.ico / src_version.txt   exe 图标与版本信息
├── dist/SRC控制台.exe         打包产物（双击即用）
├── logs/desktop.log          桌面壳运行日志
├── app/
│   ├── config.py             路径、模型、风险等级配置
│   ├── registry.py           工具注册表 + 内置工具（httpreplay/nuclei_cli/note_fact/py_exec）
│   ├── executor.py           执行器抽象（工具箱子进程）
│   ├── pyexec.py             Python 代码执行通道（py_exec 后端）
│   ├── replayer.py           HTTP 重放器 / nuclei 托管运行器
│   ├── intel.py              项目情报库注入
│   ├── kb.py                 SRC 知识库/工作流规则检索（data/kb + data/rules）
│   ├── fofa.py               FOFA 资产测绘客户端（key 走本机 config.yaml，trust_env=False）
│   ├── providers.py        通用 LLM 供应商注册中心（预设厂商 / 增删改 / 持久化）
│   ├── llm.py              模型层：OpenAI 兼容 + Anthropic 原生双协议通用后端
│   ├── agent.py            ReAct 单步决策循环（SOP 与事实纪律在 SYSTEM_PROMPT；对话树上下文注入/结论回流）
│   ├── store.py            SQLite 项目仓储（projects/sessions(含线索树字段)/steps/findings/intel/facts）
│   ├── report.py           补天格式报告生成
│   └── main.py             FastAPI 后端（供应商管理 / 项目 / 会话 / 工具接口）
├── web/                      原生前端（index.html / app.js / style.css）
└── data/
    ├── risk_grades.json      风险分级（可手改）
    ├── invocation_templates.json  工具调用模板（可手改）
    ├── tool_overrides.json   禁用清单（可手改）
    ├── scope.json            授权域名白名单
    ├── scripts/exec/         py_exec 代码留档
    └── projects.db           SQLite 数据库
```

## 可调配置

### 风险分级

编辑 `data/risk_grades.json`，或改根目录的 `build_risk_table.py` 后重新运行（会同时更新文档与 JSON）。

### 工具调用模板

编辑 `data/invocation_templates.json`。格式为：

```json
"alias": "{exe} -u {target} {args}"
```

`{exe}` 可执行文件路径，`{target}` 目标，`{args}` 模型给的附加参数。
未配置的工具默认 `{exe} {args} {target}`。

**已实测校准**的工具：enscan、httpx、ehole、veo、packerfuzzer、dirsearch、sqlmap、afrog、fscan、kscan、dddd、sharpscan、oneforall。

### 禁用工具

编辑 `data/tool_overrides.json`。当前禁用了 6 个实测不可用的：

| 工具 | 原因 |
|---|---|
| TideFinger | 已过期（2026.03.01） |
| nuclei | 是图形界面封装，命令行无输出 |
| Serein | `--help` 无响应，疑似交互程序 |
| Xscan | v3.4 提示需下载新版 |
| P1finger | 扫描入口为 `rule`/`fofa`，参数待确认 |
| EZ | 未找到可用扫描参数 |

把 `disabled` 改为 `false` 即可重新启用。

### 模型：通用 LLM 接入

顶栏右侧「设置」→**模型供应商**，可接入市面上几乎所有大模型服务。统一用
「协议类型 + Base URL + API Key + 模型名」四件套描述，保存即生效，无需重启：

| 协议 | 适用 | 说明 |
|---|---|---|
| OpenAI 兼容 | OpenAI、DeepSeek、通义千问、GLM、Kimi、火山方舟、硅基流动、混元、文心、Groq、OpenRouter、Grok、Gemini（兼容层）、Mistral，以及本地 Ollama / LM Studio / vLLM / Xinference | 走 `/chat/completions`。Base URL 没带 `/v1` 会自动补 |
| Anthropic 原生 | Anthropic Claude 官方及各类 Anthropic 兼容网关 | 走 `/v1/messages`，自动做 messages ↔ blocks 结构互转 |

内置 **22 个厂商预设模板**（设置页「从模板添加」一键建好端点与默认模型，只差填 Key）。
自定义供应商可自由增改删，内置三个（ollama / deepseek / anthropic）不可删除，可「恢复默认」。

配置持久化在 `%USERPROFILE%\.src_agent_llm.json`，**密钥不进项目仓库**、接口回显一律打码
（回传打码值视为「不修改」，不会覆盖已存密钥）。旧版 `.deepseek_api_key` /
`.llm_anthropic.json` 会在首次加载时自动迁移。

每个供应商都有「**测试**」按钮：真实发一条极短消息验证连通性，并探测该模型是否支持
**function calling**（不支持的模型会明确提示换型号，因为它无法调度工具）；同时可「拉取模型」
从端点 `/models` 直接选型号。

底部还有「漏洞验证类任务自动路由到云端」开关：命中漏洞/注入/越权等关键词时，
把该轮决策临时切到指定云端供应商（默认 deepseek），本地模型继续做常规编排。

相关接口：

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/llm/presets` | 厂商预设模板 |
| GET/POST | `/api/llm/providers` | 列表 / 新增或更新 |
| DELETE | `/api/llm/providers/{id}` | 删除（内置拒绝） |
| POST | `/api/llm/providers/{id}/use` | 设为当前决策供应商（可带 auto_route） |
| POST | `/api/llm/providers/{id}/test` | 连通性 + 工具调用探测 |
| GET | `/api/llm/providers/{id}/models` | 拉取该端点的模型列表 |
| POST | `/api/llm/providers/{id}/reset` | 内置供应商恢复默认 |
| GET/POST | `/api/models` | 前端下拉框数据 / 切换供应商 |

环境变量 `DEEPSEEK_API_KEY` / `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` /
`ANTHROPIC_MODEL` / `OLLAMA_BASE_URL` / `OLLAMA_MODEL` 仍作为**首次默认值**兜底。
未配置 Key 的云端供应商自动禁用，不影响本地运行。

> 实测提醒：并非所有模型都支持 function calling。控制台「测试」里工具调用显示 ✗ 的型号，
> 只能当聊天模型用，无法驱动工具编排。

### 其他

`app/config.py` 中：`MAX_STEPS`（单轮最大步数，默认 12）、`TOOL_TIMEOUT`（单工具超时，默认 600s）、`PORT`。

团队协作时，工具箱路径通过环境变量 `TOOLBOX_ROOT` 指定（各成员机器路径不同）；未设置时回退到 `config.py` 里的本机默认路径。详见 `团队协作指南.md`。

## 已知限制

1. **ENScan 需要过验证码** —— 爱企查数据源会要求浏览器验证，未验证时工具会重试报错。
2. **OneForAll 联网检测** —— 启动时检测 `ip-api.com`，访问不到会告警但仍会执行（子域名收集可能受限）。
3. **GUI 工具无输出** —— 图形界面工具只能启动，Agent 拿不到它们的运行结果。
4. **本地模型决策较慢** —— 单次决策 13~25 秒，复杂任务会更久。着急时可临时调低 `MAX_STEPS`。
5. **桌面 exe 依赖 venv** —— `SRC控制台.exe` 为委派式壳，需本机 venv（`%USERPROFILE%\.workbuddy\binaries\python\envs\src-agent`）且与 `desktop_launcher.py` 同目录；其他电脑使用需自行准备 venv 与工具箱。
6. **Anthropic 兼容端点的 tool_use 支持** —— 走 messages API 的标准结构，个别兼容端点对 function calling 实现不完整时会退化为纯文本，请以实测为准。

## 合规

仅限已获得**书面授权**的目标测试。L3 级操作（含 `py_exec` 代码执行）需手动勾选授权确认才可放行。
根目录 `免责声明.txt` 明确了工具箱的合规要求。
