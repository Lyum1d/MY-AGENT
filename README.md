# SRC 渗透 Agent · 本地控制台

对话驱动的渗透测试编排平台，可调度天狐渗透工具箱 V3.0 中的工具，面向 SRC（补天）漏洞挖掘场景。

## 快速开始

```bat
python -m pip install -r requirements.txt   :: 首次：安装依赖（fastapi/uvicorn/httpx/pyyaml）
双击「启动控制台.bat」                        :: 浏览器打开（关闭窗口即停服务）
python run.py                               :: 命令行启动（--no-browser 不自动开浏览器）
```

默认地址：<http://127.0.0.1:8770>

**解释器怎么找（排障必看）**：`启动控制台.bat` 依次探测 `SRC_AGENT_PY` 环境变量 →
项目内 `.venv\Scripts\python.exe` → `py -3` 启动器 → PATH 里的 `python`
（每个候选都实际执行 `--version` 验证，绕开 Windows 商店的 python 占位程序）。
`run.py` 启动前还会自查依赖：若当前解释器没装 `uvicorn/fastapi/httpx/pydantic`，
会自动切换到带依赖的那个解释器并重启自身。因此「双击后窗口一闪」「报
ModuleNotFoundError: No module named 'uvicorn'」这类打不开的情况不会再出现；
万一所有候选都缺依赖，会打印明确的修复指引（而不是直接崩掉）。
团队协作时每人解释器位置不同，可用 `SRC_AGENT_PY` 显式指定。

> 首次使用建议：先建「项目」（如"补天-XX厂商"），把任务发到选中的项目下，Agent 的每步输出、
> 已证事实与漏洞登记才会归档到该项目，报告才能聚合生成。
> **项目里的「目标」会自动注入每次决策**：任务描述没写域名/企业名时，模型以项目目标为准；
> 填的是企业名会先引导用 app_info 扩展资产（enscan 因需人工验证码已禁用）。
>
> **先配授权白名单**：`data/scope.json` 的 `domains` 默认只有 `example.com`，
> 且白名单为空时一律拒绝执行（宁可跑不起来也不放行未授权目标）。换目标前先改这里，
> 否则命令行工具 / HTTP 重放器 / py_exec 都会被拦下。
>
> 界面为 Trae/WorkBuddy 风格对话式布局（深色/亮色可切换，右上角 🌙/☀️ 按钮）：
> 左侧边栏管「项目/工具箱」，中间是对话气泡流（AI 回复内含执行计划、命令/输出代码块与结论），
> 右侧「报告」面板记录漏洞发现与已证事实（可折叠）。
> 左栏项目列表支持**重命名与删除**：鼠标移到条目上会出现「重命名 / 删除」按钮，重命名是
> 内联编辑（改名称与目标），删除需二次确认（会连带删除该项目下的漏洞、已证事实与会话记录）。
> 决策模型在底部下拉框或「设置 → 模型供应商」中切换，可接入任意 OpenAI 兼容 / Anthropic 端点。

## 桌面版（可选，未随本源码快照分发）

桌面壳 `desktop_launcher.py`、打包产物 `dist/SRC控制台.exe`、图标 `src_console.ico` /
`src_version.txt` 以及 `logs/` **不在本源码快照中**（仅随发布包分发）。本快照请用
`启动控制台.bat` 或 `python run.py` 启动——功能完全一致，只是界面呈现在浏览器而非独立窗口。

若要自行修复/打包桌面壳，恢复上述文件后注意：

- exe 是「委派式」轻量壳：定位本机 venv 的 python 来执行 GUI（PyInstaller 冻结 pythonnet
  在本机 webview 启动会原生崩溃，实测多方案后采用此架构），因此需与 `desktop_launcher.py`
  放在同一目录（项目根）使用。
- 自检：`python desktop_launcher.py --smoke`（无窗口验证链路）。


## 核心设计

### 单步决策 ReAct 循环

**不要让模型一次规划全部步骤**——实测本地 `qwen3.5:9b` 在这种模式下只输出文字方案、不产生
`tool_calls`。这里每次只让它决定"下一步用哪个工具"，执行完把真实结果回喂，再问下一步。

> 这条约束来自**本地小模型**。现在默认决策已切到云端（见「默认供应商：云端优先」），
> 云端模型扛得住多步规划；但单步循环仍然保留——它对本地模型是必需的，对云端模型也只是
> "每轮多一次调用"，换来的是每一步都基于真实结果决策，更不容易跑偏。

### 思考模式必须开启（本地 Ollama 专属）

实测本地 Ollama 关闭思考模式（`thinking: false`）后，模型退化成纯文本输出、不再调用工具。
`config.py` 中 `OLLAMA_THINKING = True`，**不要为了省时间关掉**。
（云端供应商是否开启思考由各自模型决定，与此无关。）

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

### 长任务稳定性（上下文压缩 / 失败归因 / 两档止损 / 预算熔断）

长任务跑到一半「变傻、反复失败、没到步数上限就停」是本地小模型的三类典型症状，这里针对性处理
（机制来源见 `docs/LuaN1ao对比分析.md`）：

- **上下文压缩（机械式）**：消息数超过 `HISTORY_COMPRESS_AFTER_MESSAGES`（24）时，把较早的
  `role=tool` 输出压成一行带 `〔已压缩〕` 标记的摘要，保留最近 `HISTORY_KEEP_RECENT`（12）条原文。
  **只改正文、绝不删除消息** —— 删消息会破坏 `assistant.tool_calls` 与 `role=tool` 的
  `tool_call_id` 配对，协议会直接报错。这里**刻意不做「LLM 摘要」**：让本地小模型写摘要，
  本身就会产生幻觉，等于用一个不可靠环节去修另一个不可靠环节。
- **失败归因分层**：失败回喂内容带 `归因 L1 / L3 / L4 / SCOPE` 标签，让模型知道该往哪个方向调整 ——
  `L1` 工具没跑起来（换参数 / 放大超时 / 换同类工具）；`L3` 被环境或权限拦下（换编码 / 换参数位置 / 换手法，
  换工具通常无效）；`L4` 跑通但没拿到结果（该换思路，别在原假设上加码）；
  `SCOPE` 被授权白名单拒绝（授权边界，必须停手而不是绕过）。
- **两档止损**：连续失败到 `FAILURE_SWITCH_THRESHOLD`（3）先**要求模型换策略**继续挖，
  到 `FAILURE_STOP_THRESHOLD`（6）才停止。此前是 3 次即停，而连续三次失败往往只是
  「同一思路被环境挡住」——这是「没到最大步数就停」的主因。
- **成本熔断**：单次任务累计 token 超过 `RUN_TOKEN_BUDGET` 即停止并说明原因。
  本地 Ollama 不返回 usage 所以不会触发；云端供应商则用来防止失控任务无声烧钱。

### 内置工具（始终对 LLM 可见，不占配额）

除工具箱工具外，注册表内置 10 个能力（`app/registry.py::_add_builtin_tools`）：

| 别名 | 风险 | 作用 |
|---|---|---|
| httpreplay | L2 | 受控 HTTP 重放（只读方法 + 域名白名单） |
| nuclei_cli | L2 | nuclei 模板漏洞验证 |
| note_fact | L0 | 记录已证事实（见上） |
| py_exec | L3 | **Python 代码执行通道**：让 Agent 对单点任务直接写代码（HTTP 用 httpx/requests），代码留档 `data/scripts/exec/`，超时自动中断 |
| search_history | L0 | 跨线索检索项目内历史工具输出 |
| propose_branch | L0 | 建议开辟新线索（发卡片，用户确认后建分支） |
| split_task | L0 | **任务分片并行**：拆成 2~4 份并发跑，跑完汇总回本线索 |
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
  **父子之间用肘形连线连接**（SVG 覆盖层，端点按节点实际渲染位置现算，因此标题长短、
  分支多少都能画准；同列节点按前序遍历排序，连线不会交叉），当前线索所在的整条祖先链
  高亮为强调色；颜色区分状态（进行中 / 已完成 ✓ / 已放弃 −），点击节点即切换到那条对话
  （**历史对话按原气泡样式回放**：用户消息、AI 说明与结论均持久化在 chat_messages 表，
  旧会话自动回退为步骤+摘要展示）。
- **开新线索（两种方式）**：
  - AI 发现值得单独深挖的可疑点时，调用内置工具 `propose_branch` 在聊天里发一张
    「开新线索」卡片（含建议标题与可打包的执行记录勾选清单），确认后自动创建并切换；
  - 手动：线索树节点 / 顶栏「＋ 分支」按钮，从该线索最近的步骤里勾选记录打包带走。
- **删除线索**：卡片右上角悬停出现的 `×` 可彻底删除该分支，删除前有二次确认。
  删除是**级联**的——该线索及其全部后代、执行步骤、对话历史一并清除，不可恢复。
- **开局背景**：新线索携带打包记录（工具输出摘要），系统提示明确「可直接引用、不要重复验证」。
- **翻旧账**：内置工具 `search_history`（L0）跨线索检索项目内所有会话的历史工具输出，
  其他线索的进展摘要也会注入系统提示；同线索内连续发消息即续聊（上下文累积）。
- **成果回流**：线索给出结论后，摘要自动落库并实时推送给父会话（`branch_update` 事件），
  主对话随时掌握全局。
- 风险分级（L2 确认 / L3 二次确认）与授权白名单校验在线索间**完全一致**，切换对话形式不放松任何闸门。

相关接口：`GET /api/projects/{pid}/tree`、`POST /api/sessions/{sid}/branch`、
`PUT /api/sessions/{sid}/meta`、`DELETE /api/sessions/{sid}`（级联删除该分支及后代）、
`POST /api/sessions`（body 带 `sid` 时为恢复已有会话续聊）。

### 任务分片并行（拆小份 → 并发跑 → 合并）

任务面较宽、子任务互不依赖时，模型可调用内置工具 `split_task`（L0）把任务拆成 2~4 份：

- **拆**：`args` 每行一个子任务描述；每个子任务生成一个**子会话**并挂在当前线索下，
  因此它会直接出现在线索树小地图上，点进去可看全过程。
- **并发跑**：所有子会话用 `asyncio` 并发执行（**不是多进程** —— 本工作负载是 I/O 密集，
  等模型、等工具，单进程足够；多进程反而要重建事件流与确认通道，收益不抵复杂度）。
  并发上限 `SUBTASK_MAX_CONCURRENCY`（默认 3），单个子任务步数上限 `SUBTASK_MAX_STEPS`（默认 8）。
- **合并**：全部跑完后，把每个子任务的结论摘要 + 用过的工具 + 子任务期间新增的已证事实
  合成一个「结果汇总」块注入主线索，并发出 `subtask_merged` 事件；主线索据此继续推进。

两条硬约束是**写在代码里的，不是靠提示词**：

1. **子任务内禁止 L2/L3**。确认通道是「一次一步」的交互式，且前端只订阅当前会话的 SSE ——
   并行时弹不出确认，硬跑只会得到无人确认的悬空步骤。子任务内遇到 L2/L3 会直接拒绝，
   并提示「这一步留给主线索，由人工确认后单独执行」。
2. **子任务不允许再拆**（只允许一层），避免任务数指数膨胀。

> 调高并发前请先想清楚：并行 = 对目标同时发起更多请求。平台规则禁止影响业务可用性的高并发，
> 云端供应商那边也会推高 token 消耗（有 `RUN_TOKEN_BUDGET` 兜底，但那是总量闸门、不是速率闸门）。

### 记忆机制与「约束的强制边界」

**六层记忆**（写入时机不同，异常时的存活情况也不同）：

| 层 | 载体 | 写入时机 |
|---|---|---|
| 工作记忆 | `Session.messages`（内存） | ReAct 每步；超阈值由 `_compress_history` 确定性压缩（不调 LLM，只改内容、不删消息以保 `tool_calls` 配对） |
| 对话原文 | 表 `chat_messages` | 用户消息 / 模型说明 / 最终结论；**切回线索续聊时会被还原成 messages 交给模型**（此前只用于前端回放，导致「继续聊 = 失忆」） |
| 已证事实 | 表 `facts` + 因果图 `causal_nodes/edges` | `note_fact` 调用时（执行中即时落库） |
| 项目情报库 | 表 `intel`（每项目一行 JSON） | `_persist_intel()`：run() 正常收尾 **以及 `_run_agent` 的 finally**（异常中断同样沉淀） |
| 跨线索 | `records` / `summary` / 线索树 | 开分支打包时 / 给出结论时 |
| 知识记忆 | `data/kb` 49 篇 + `data/rules` 12 篇 | 静态文件，按需 `kb_search` / `kb_read` |

**检索面**：内置 `search_history` 覆盖 **工具执行输出 + 已证事实 + 项目情报库** 三类，
结果按 `step / fact / intel` 标注来源。步骤输出落库时保留**首尾**（`STEP_OUTPUT_HEAD` /
`STEP_OUTPUT_TAIL`），不再只留尾部。

**⚠ 约束的强制边界（重要，别混为一谈）**

| 类别 | 例子 | 强制？ | 拦在哪 |
|---|---|---|---|
| **执行层闸门** | 授权白名单、L2/L3 二次确认 | ✅ 强制 | `app/scope.py`（fail-closed）、`run()` 的风险闸门 |
| **提示词约定** | SYSTEM_PROMPT 里的合规红线（禁爆破 / 禁拖库 / 禁横向移动）、「进站先 `kb_read` 打穿短表」 | ❌ **只是建议** | 无强制层，模型可以不听 |

写在系统提示词里的合规红线属于**第二类**：它是给模型的强约束说明，但
**没有任何代码在执行前校验它**。实测例子：`oneforall` 分级为 L0（自动放行），
而它内部会跑 massdns + 9 万条字典的子域爆破 —— 提示词里的「禁止暴力爆破」没有拦住它，
也拦不住（分级只到"工具名"粒度，不看"动作"）。

需要**必须有强制性**的约束，请放在执行层，而不是提示词里：
`data/scope.json`（目标粒度）、`data/risk_grades.json`（工具粒度）、
`data/tool_overrides.json` 的 `disabled`（不进模型工具清单）。

## 工具能力边界

工具箱 199 个工具 + 10 个内置能力；其中 **54 个可编排**（有 stdout，能进自动化流水线，
含全部 10 个内置能力：httpreplay / nuclei_cli / note_fact / py_exec / search_history /
propose_branch / split_task / kb_search / kb_read / fofa_search），其余为图形界面工具（一键启动）与网页工具。

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
├── run.py                    启动入口（缺依赖时自动切换解释器并重启自身）
├── requirements.txt          依赖（fastapi / uvicorn / httpx / pyyaml / pytest）
├── 启动控制台.bat             一键启动（UTF-8/CRLF，含解释器探测）
├── 团队协作指南.md            团队环境（TOOLBOX_ROOT 等）说明
├── update.py                 更新工具（更新包 / 备份）
├── upgrade_templates.py      调用模板批量升级
├── migrate_templates.py      调用模板格式迁移
├── test_*.py                 离线回归测试 8 个（见「测试」一节）
├── app/
│   ├── config.py             路径、模型、风险等级、各类超时与上限
│   ├── scope.py              授权白名单唯一实现（executor / replayer / pyexec 共用）
│   ├── registry.py           工具注册表 + 9 个内置能力
│   ├── executor.py           执行器抽象（工具箱子进程）+ 参数清洗
│   ├── pyexec.py             Python 代码执行通道（py_exec 后端）
│   ├── replayer.py           HTTP 重放器 / nuclei 托管运行器
│   ├── intel.py              项目情报库注入
│   ├── kb.py                 SRC 知识库/工作流规则检索（data/kb + data/rules）
│   ├── fofa.py               FOFA 资产测绘客户端（无 pyyaml 时走内置兜底解析）
│   ├── usage.py              Token 用量聚合与模型单价表（data/usage_prices.json）
│   ├── providers.py        通用 LLM 供应商注册中心（预设厂商 / 增删改 / 持久化）
│   ├── llm.py              模型层：OpenAI 兼容 + Anthropic 原生双协议通用后端
│   ├── agent.py            ReAct 单步决策循环（SOP 与事实纪律在 SYSTEM_PROMPT；对话树上下文注入/结论回流）
│   ├── store.py            SQLite 项目仓储（WAL；projects/sessions/steps/findings/intel/facts/usage）
│   ├── report.py           补天格式报告生成
│   └── main.py             FastAPI 后端（本地访问防护 / 供应商 / 项目 / 会话 / 工具接口）
├── web/                      原生前端（index.html / app.js / style.css）
├── docs/                     设计决策文档（LuaN1ao 架构对比分析）
└── data/
    ├── risk_grades.json      风险分级（可手改）
    ├── invocation_templates.json  工具调用模板（可手改）
    ├── tool_overrides.json   禁用清单 + 参数白名单（可手改）
    ├── scope.json            授权域名白名单（默认仅 example.com）
    ├── kb/ · rules/          知识库 49 篇 + 工作流规则 11 篇
    ├── scripts/exec/         py_exec 代码留档（运行时生成）
    ├── projects.db           SQLite 数据库（运行时生成）
    └── usage_prices.json     模型单价表（运行时生成）
```

> 桌面版相关文件（`desktop_launcher.py`、`dist/`、`src_console.ico`、`src_version.txt`、`logs/`）
> 与 `build_risk_table.py` **不在本源码快照中**，详见「桌面版」与「可调配置」两节。

## 可调配置

### 风险分级

直接编辑 `data/risk_grades.json`：键为工具的**原始中文名**，值为
`{"level": "L1", "reason": "..."}`；未在表里的可编排工具一律按 `L2` 处理。

> 旧文档提到的 `build_risk_table.py` **不在本快照中**（它只是「改 JSON 并同步文档表格」的
> 辅助脚本），手动编辑 JSON 效果相同。

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

#### 默认供应商：云端优先、本地兜底

**默认优先云端模型**；本地 Ollama 仍完整保留、随时可切回，但**不再被优先使用**。
当"当前选择"为空或已失效（被删 / 停用 / Key 被清空）时，按下列顺序自动挑选：

1. `config.PREFERRED_PROVIDER`（默认 `deepseek`，环境变量 `AGENT_PREFERRED_PROVIDER`）
   —— 前提是它已启用且配置完整；
2. 其它任何「已启用 + 配置完整 + 非本地」的供应商；
3. 本地 Ollama（**仅当没有任何可用云端时兜底**）；
4. 最后退到列表第一个，保证永远不返回空。

> 全新安装、一个 Key 都没填时，第 1–2 步落空，最终仍会选到本地 Ollama（不会变砖）；
> 一旦填了任一云端 Key，就会自动切到云端。想固定用本地，把 `AGENT_PREFERRED_PROVIDER`
> 设为 `ollama`，或在界面上显式选中它。
> 使用云端模型时注意 `RUN_TOKEN_BUDGET` 成本熔断（见「其他」一节的配置表）。

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

### Token 用量统计

顶栏「📊 用量」按钮（带今日 token 徽标）或「设置 → 用量统计」打开独立弹窗：

- **三档汇总卡**：今日 / 本月 / 累计（token 数 + 人民币费用估算 + 调用次数）
- **按天趋势图**（最近 30 天，纯 SVG 无外部依赖）
- **分模型占比 + 分项目排行**（本地 Ollama 统计 token、费用为 0）
- **调用明细表**：逐条 LLM 调用（时间/项目/模型/输入/输出/耗时），可按项目、模型、时间筛选
- **单价管理**：输入/输出分开计价（¥/百万 token），预填常见模型价，可改可增删、可恢复默认
- **数据管理**：清空（全部或 N 天前）、导出 CSV

实现：每次 LLM 调用成功后从响应 usage 提取 token 数落库（`usage_log` 表，自上线起统计，
旧会话无 usage 数据不回填；失败调用不计费）；接口 `GET /api/usage/{summary,daily,list,prices,export.csv}`、
`POST /api/usage/{prices,prices/reset,clear}`。费用为估算值，请在单价表里按自己账单校准。

### 其他

`app/config.py` 中的可调项（括号内为对应环境变量）：

| 配置 | 含义 | 默认 | 环境变量 |
|---|---|---|---|
| `MAX_STEPS` | 单轮最大步数 | 12 | `AGENT_MAX_STEPS` |
| `TOOL_TIMEOUT` | 单工具总时长(秒) | 600 | `TOOL_TIMEOUT` |
| `TOOL_IDLE_TIMEOUT` | 无输出判卡死(秒) | 120 | `TOOL_IDLE_TIMEOUT` |
| `CONFIRM_TIMEOUT` | L2/L3 等用户确认上限(秒) | 600 | `AGENT_CONFIRM_TIMEOUT` |
| `MAX_TOOL_SCHEMAS` | 单次决策回传工具数上限 | 40 | `AGENT_MAX_TOOL_SCHEMAS` |
| `INTEL_CAP` | 情报库每类条目上限 | 150 | `INTEL_CAP` |
| `FAILURE_SWITCH_THRESHOLD` | 连续失败到几次改为要求「换策略」 | 3 | `AGENT_FAILURE_SWITCH` |
| `FAILURE_STOP_THRESHOLD` | 连续失败到几次才停止 | 6 | `AGENT_FAILURE_STOP` |
| `RUN_TOKEN_BUDGET` | 单次任务 token 预算（成本熔断） | 800000 | `AGENT_RUN_TOKEN_BUDGET` |
| `PREFERRED_PROVIDER` | 首选供应商（云端优先的解析首位） | deepseek | `AGENT_PREFERRED_PROVIDER` |
| `SUBTASK_MAX_CONCURRENCY` | 子任务并发上限 | 3 | `SUBTASK_MAX_CONCURRENCY` |
| `SUBTASK_MAX_STEPS` | 单个子任务步数上限 | 8 | `SUBTASK_MAX_STEPS` |
| `SUBTASK_MAX_COUNT` | 单次最多拆几个子任务 | 4 | `SUBTASK_MAX_COUNT` |
| `SUBTASK_MERGE_FACTS` | 合并时最多带多少条新增事实 | 20 | `SUBTASK_MERGE_FACTS` |
| `HISTORY_COMPRESS_AFTER_MESSAGES` | 消息数超过多少触发上下文压缩 | 24 | `HISTORY_COMPRESS_AFTER_MESSAGES` |
| `HISTORY_KEEP_RECENT` | 压缩时保留最近多少条原文 | 12 | `HISTORY_KEEP_RECENT` |
| `HISTORY_SUMMARY_CHARS` | 压缩后每条保留多少字 | 300 | `HISTORY_SUMMARY_CHARS` |
| `RESTORE_CHAT_MAX` | 续聊时最多还原多少条历史对话 | 24 | `AGENT_RESTORE_CHAT_MAX` |
| `RESTORE_CHAT_CHARS` | 续聊还原时单条截断字符 | 1200 | `AGENT_RESTORE_CHAT_CHARS` |
| `STEP_OUTPUT_HEAD` / `_TAIL` | 步骤输出落库保留的首/尾字符数 | 1500 / 2000 | `AGENT_STEP_OUTPUT_HEAD` / `_TAIL` |
| `FACT_INJECT_MAX` | 系统提示最多注入多少条已证事实 | 20 | `AGENT_FACT_INJECT_MAX` |
| `RECORD_INJECT_MAX` | 最多注入多少条开局打包记录 | 20 | `AGENT_RECORD_INJECT_MAX` |
| `BRANCH_INJECT_MAX` | 最多注入多少条其他线索摘要 | 8 | `AGENT_BRANCH_INJECT_MAX` |
| `ENFORCE_SCOPE` | 执行前强制授权白名单 | 开 | `ENFORCE_SCOPE` |
| `CLOUD_EGRESS_MODE` | 云端外发策略：`local_only` 禁发云端 / `redact` 脱敏后上云 / `allow` 原样 | redact | `AGENT_CLOUD_EGRESS` |
| `PY_EXEC_TMP_ROOT` | py_exec 沙箱一次性工作目录的父目录 | data/scripts/tmp | — |
| `PY_EXEC_ENV_ALLOW_JSON` | py_exec 允许额外继承的环境变量清单 | data/pyexec_env_allow.json | — |
| `PORT` / `HOST` | 监听端口 / 地址（非回环默认拒绝启动，`ALLOW_NON_LOOPBACK=1` 显式放行） | 8770 / 127.0.0.1 | `PORT` / `HOST` |

团队协作时，工具箱路径通过环境变量 `TOOLBOX_ROOT` 指定（各成员机器路径不同）；未设置时回退到 `config.py` 里的本机默认路径。详见 `团队协作指南.md`。

## 安全基线（v010）

1. **py_exec 进程级沙箱**：子进程不再继承宿主环境变量（凭据/代理 Key 被白名单挡住，确需某个变量写入 `data/pyexec_env_allow.json`）；执行 cwd 与 TEMP/TMP 指向一次性临时目录，结束即清理；Windows Job Object 保证超时/取消时**整棵进程树**终止（嵌套 `subprocess` 也不会残留）。Job 不可用时退回 `taskkill /T /F` 兜底。
2. **目标列表文件校验**：argv 逐 token 授权复核之外，`-l/--list/--urls/--input` 指向的目标列表文件内容也逐行过白名单（此前列表里写未授权主机可绕过全部校验）。超大文件（>1MB）按拒绝处理。
3. **云端外发控制**（`AGENT_CLOUD_EGRESS`，默认 `redact`）：工具输出进云端 LLM 前，Cookie/Bearer/JWT/password=/api_key= 等键值对、邮箱、手机号会被打码为占位符（`app/redact.py`），命中摘要记日志；`local_only` 模式下默认路由与手动切换都只允许本地供应商；脱敏只作用于发往云端的那份副本，落库原文不变。
4. **数据归属校验**：删除事实/漏洞发现必须匹配 `project_id`，跨项目 ID 一律 404。
5. **非回环监听默认拒绝**：`--host` 指向非 127.0.0.1/localhost/::1 时启动即失败；确需局域网访问设 `ALLOW_NON_LOOPBACK=1`（风险自担，启动时仍打印完整提示）。
6. **更新器完整性校验**：update.exe 下载后对照仓库根 `SHA256SUMS.txt`（发布 commit 内生成）校验 sha256，不匹配即中止；解压启用 Zip Slip 防护（`..`/盘符/绝对路径成员一律跳过）。远端暂无清单时告警跳过（兼容旧版本）。

## 可靠性（v011）

1. **任务取消**：`POST /api/sessions/{sid}/cancel`——软取消，在步骤边界与确认等待处生效（正在执行的工具步骤跑完即停，单步本有总时长上限）；取消后半程成果照常沉淀为【中断】摘要。
2. **SSE 断线重放**：所有事件同步落库（`events` 表，自增 seq）；断线/刷新重连时带 `Last-Event-ID` 头（或 `?last_event_id=`）自动补发中间事件，去重不重不漏；服务重启后内存会话丢失，仍可带游标回放历史。
3. **模型调用重试**：连接失败/超时/429/临时 5xx 按指数退避自动重试（默认 3 次，`AGENT_LLM_RETRY_MAX`）；401/400 等不可重试错误直接上抛。
4. **供应商故障转移**：重试耗尽后自动切换到其他可用供应商并继续任务（单次任务最多 2 次，`AGENT_LLM_FAILOVER_MAX`），切换原因写入事件流与日志。
5. **时间预算熔断**：`AGENT_RUN_TIME_BUDGET`（默认 1800s）——token 预算管钱、步数管轮次，此项管墙钟时间，超时按中断处理。
6. **因果图收紧**：未知边标签归一为 `UNKNOWN`（不再默认当作 SUPPORTS 人为推高置信度）；置信度传播按边幂等（重复提交同一条支撑边不重复加分）；单批写入上限（节点 200/边 500）。

## 证据与授权（v012）

1. **事实状态模型**：`verified / candidate / rejected`——人工登记或带工具输出溯源（step_id）的事实为 verified；AI 记录且无溯源的自动降为 **candidate**，不会注入「已证事实库」冒充已证结论。人工复核走 `POST /api/projects/{pid}/facts/{fid}/review`。
2. **漏洞状态模型**：`draft / needs_review / confirmed / closed`——**AI 与首次登记一律 draft（候选）**，只有人工确认（`POST .../findings/{fid}/review`，action=confirmed）后才进入正式报告的「已确认漏洞」章节。
3. **漏洞结构化字段**：登记时可填 `vuln_type / cwe / cvss / impact_scope / reproduction / remediation`；修复建议留空时按 vuln_type 套内置模板（SQL 注入/XSS/弱口令/未授权/信息泄露/上传/SSRF/RCE/CSRF/反序列化），不再「待补充」。
4. **报告增强**：已确认与待验证候选分章（候选在附录、明确标注不作为结论提交）；Markdown 表格单元格统一转义（标题/目标含 `|` 不再毁表）；导出前完整性检查——已确认漏洞缺证据或缺复现步骤时在报告头部给出告警清单。
5. **端口/协议授权**：scope.json 新增结构化写法（与旧 domains 混用、完全向后兼容）：
   ```json
   {"targets": [{"host": "example.com", "ports": [80, 443], "schemes": ["https"]}]}
   ```
   host 命中但端口/协议不在授权列表时拒绝执行；未声明 ports/schemes 则不限制。结构化 host 自动纳入 argv 复核与目标列表校验的白名单视图。
6. **FOFA 范围约束**：fofa_search 的查询语句必须包含至少一个授权白名单内的主机，否则拒绝执行（防在授权范围外收集资产）。

## 测试

`test_*.py` 是自带的回归脚本（非 pytest 收集式，直接 `python test_xxx.py` 运行，退出码 0 表示全过）。
**改完代码先跑前四个**——它们不联网、不调用真实工具，数据库与供应商配置都落在临时目录：

| 脚本 | 覆盖内容 | 外部依赖 |
|---|---|---|
| `test_scope.py` | 授权白名单 / argv 复核 / 目标列表文件校验（安全红线） | 无 |
| `test_sandbox.py` | py_exec 沙箱：env 白名单 / 临时目录 / Job 杀树 | 无（杀树起真实子进程） |
| `test_redact.py` | 云端外发脱敏规则 / 模式语义 / 深拷贝契约 | 无 |
| `test_ownership.py` | 事实与漏洞的跨项目删除拒绝 | 无 |
| `test_tree.py` | 对话树 / 会话恢复 / 内置工具 / 结论回流 | 无 |
| `test_usage.py` | Token 用量采集 / 聚合 / 单价表 / CSV 导出 | 无 |
| `test_kb_fofa.py` | 知识库检索 / 内置工具注册 / FOFA 未配置兜底 | 无 |
| `test_agent_smoke.py` | 供应商 → 后端 / 自动路由 / ReAct 全链路（假后端） | 无 |
| `test_llm_providers.py` | 供应商增删改与持久化接口 | 需服务在跑 |
| `test_e2e_deepseek.py` | 云端供应商端到端 | 需服务在跑 + 可用 Key |
| `test_api.py` | 项目→会话→SSE→确认→报告全链路 | 需服务在跑 + 可用模型 |
| `test_agent.py` | 真实模型 + 真实工具执行 | 需模型后端 + 工具箱 |

```bat
python -m pip install -r requirements.txt
python test_tree.py
```

> `test_tree.py` 会显式关闭「漏洞类任务自动路由云端」：本机若存在 `~/.deepseek_api_key`，
> 它会被迁移进供应商配置使 deepseek 变为可用，任务文案里的「验证 / 注入」就会触发路由，
> 把测试注入的假后端换成真实云端模型，导致断言随机失败。

## 已知限制

1. **ENScan 需要过验证码** —— 爱企查数据源会要求浏览器验证，未验证时工具会重试报错。
2. **OneForAll 联网检测** —— 启动时检测 `ip-api.com`，访问不到会告警但仍会执行（子域名收集可能受限）。
3. **GUI 工具无输出** —— 图形界面工具只能启动，Agent 拿不到它们的运行结果。
4. **本地模型决策较慢** —— 单次决策 13~25 秒，复杂任务会更久。默认决策已切云端，只有显式选用
   本地模型时才会遇到；着急时可临时调低 `MAX_STEPS`。
5. **桌面 exe 不在本快照内** —— `SRC控制台.exe` / `desktop_launcher.py` 仅随发布包分发；本快照用
   `启动控制台.bat` 或 `python run.py`。两者都依赖一个装了项目依赖的解释器，探测顺序见「快速开始」；
   其他电脑使用需自行准备 venv 与工具箱。
6. **Anthropic 兼容端点的 tool_use 支持** —— 走 messages API 的标准结构，个别兼容端点对 function calling 实现不完整时会退化为纯文本，请以实测为准。
7. **线索图前端未接回（后端已就绪）** —— `/api/projects/{pid}/graph/attack|causal` 等 4 个路由
   与 `web/graph.js` 渲染库已在仓库中，但 `index.html` 当前未加载 `graph.js`（v006 拉上游覆盖时
   前端入口丢失，经确认暂不恢复）。恢复前端时可直接复用 `test_graph_js.js` / `test_graph_e2e.py`
   的既有期望值。在此之前这些后端路由是「预留能力」。
8. **授权白名单不区分端口** —— 白名单条目是主机名级（`example.com` 即放行其全部端口）。
   这是设计取舍：SRC 测试通常按主机授权。若需要按 `host:port` 收紧，需扩展 `scope.json`
   条目格式与 `host_in_scope` 匹配逻辑。
9. **`data/scope.json` 已移出版本控制** —— 本机真实授权数据不入库；新环境请复制
   `data/scope.example.json` 为 `data/scope.json` 再填入授权目标（白名单为空时服务会
   fail-closed 拒绝一切执行）。

## 合规

仅限已获得**书面授权**的目标测试。L3 级操作（含 `py_exec` 代码执行）需**两次独立确认**才可放行（后端强制：确认必须绑定当前步骤 id，两轮都 approved 才执行，任何一轮拒绝/超时即取消）。

**绝对不能碰的合规红线（必背）**：禁止测试企业内网 / 内部 OA / 员工办公系统 / 第三方合作平台；
禁止暴力爆破账号、高频端口扫描、DDoS 压测；禁止拖库、批量下载用户隐私数据（确需取证只截图，
不保存、不外传）；禁止植入后门、修改或删除服务器文件、篡改订单 / 密码等真实业务数据；
禁止社工钓鱼与短信轰炸；禁止横向移动（拿到权限后不再向内网其他主机探测）。
完整版见 `团队协作指南.md`「四、绝对不能碰的合规红线（必背）」与 `data/rules/compliance-redlines.md`
——后者已写入 Agent 的系统提示词（每轮携带），也可用 `kb_read compliance-redlines` 查阅。

`data/scope.json` 的授权白名单是执行前的**硬闸门**（命令行工具 / HTTP 重放器 / py_exec 共用
`app/scope.py` 一份实现）：白名单为空一律拒绝执行，重放器只允许只读方法（GET/HEAD/OPTIONS）。
服务默认只监听 `127.0.0.1`，并在应用层校验 `Host` 与 `Origin`，拦截跨站请求与 DNS 重绑定
（详见 `app/main.py` 的本地访问防护）。

> 说明：`Host/Origin` 校验挡的是「浏览器里的其他网页」，`curl` 之类的本地非浏览器客户端仍无鉴权；
> 若需对后者也做鉴权，可在该中间件上加一层 `X-Auth-Token`。
> 原 `免责声明.txt` 随工具箱发布包分发，不在本快照内。
