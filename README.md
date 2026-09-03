# SRC 渗透 Agent · 本地控制台

对话驱动的渗透测试编排平台，可调度天狐渗透工具箱 V3.0 中的工具，面向 SRC（补天）漏洞挖掘场景。

## 快速开始

```bat
双击「启动控制台.bat」
```

或命令行：

```bash
cd src-agent
python run.py              # 自动打开浏览器
python run.py --no-browser # 不打开浏览器
```

默认地址：<http://127.0.0.1:8770>

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

## 工具能力边界

工具箱 197 条清单中：

- **50 个可编排**（有 stdout，能进自动化流水线）
- **81 个图形界面**（只能一键启动，程序取不到输出）
- **66 个网页工具**（浏览器打开）

50 个可编排工具按风险分为四级：

| 等级 | 含义 | 策略 | 数量 |
|---|---|---|---|
| L0 | 只读 / 本地分析 | 自动执行 | 13 |
| L1 | 主动探测扫描 | 自动执行（留痕） | 11 |
| L2 | 漏洞验证与利用 | 需确认 | 6 |
| L3 | 权限 / 横向 / 接管 | 需确认 + 勾选授权 | 20 |

拒绝执行时 Agent 会自动改用更低风险的工具继续任务。

## 目录结构

```
src-agent/
├── run.py                    启动入口
├── requirements.txt
├── 启动控制台.bat
├── app/
│   ├── config.py             路径、模型、风险等级配置
│   ├── registry.py           工具注册表（解析 tools.json、别名映射、模糊匹配）
│   ├── executor.py           执行器抽象（本地 / 预留 SSH）
│   ├── llm.py                模型层（Ollama / DeepSeek 双通道）
│   ├── agent.py              ReAct 单步决策循环
│   ├── store.py              SQLite 项目仓储
│   ├── report.py             补天格式报告生成
│   └── main.py               FastAPI 后端
├── web/                      原生前端（index.html / app.js / style.css）
└── data/
    ├── risk_grades.json      风险分级（可手改）
    ├── invocation_templates.json  工具调用模板（可手改）
    ├── tool_overrides.json   禁用清单（可手改）
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

### 模型

默认本地 `qwen3.5:9b`。要启用云端 DeepSeek：

```bash
set DEEPSEEK_API_KEY=sk-xxxxx
python run.py
```

未设置 Key 时云端通道自动禁用，不影响本地运行。

### 其他

`app/config.py` 中：`MAX_STEPS`（单轮最大步数，默认 12）、`TOOL_TIMEOUT`（单工具超时，默认 600s）、`PORT`。

团队协作时，工具箱路径通过环境变量 `TOOLBOX_ROOT` 指定（各成员机器路径不同）；未设置时回退到 `config.py` 里的本机默认路径。详见 `团队协作指南.md`。

## 已知限制

1. **ENScan 需要过验证码** —— 爱企查数据源会要求浏览器验证，未验证时工具会重试报错。
2. **OneForAll 联网检测** —— 启动时检测 `ip-api.com`，访问不到会告警但仍会执行（子域名收集可能受限）。
3. **GUI 工具无输出** —— 81 个图形界面工具只能启动，Agent 拿不到它们的运行结果。
4. **本地模型决策较慢** —— 单次决策 13~25 秒，复杂任务会更久。着急时可临时调低 `MAX_STEPS`。

## 合规

仅限已获得**书面授权**的目标测试。L3 级操作需手动勾选授权确认才可放行。
根目录 `免责声明.txt` 明确了工具箱的合规要求。
