# 补天公益 SRC · www.jiaoyu.cn 渗透测试报告（完整版）

- **测试日期**：2026-09-03
- **测试主体**：本地 SRC 渗透 Agent（天狐工具箱编排，qwen3.5:9b 决策）
- **授权依据**：补天漏洞响应平台公益 SRC，www.jiaoyu.cn 及其子域均为授权测试资产
- **关联项目**：`data/artifacts/b2d75b1a58ab`（控制台自动报告同目录）
- **漏洞数量**：0（`/actuator/dump` 疑似点已复核为 SPA fallback 假阳性，见 §4.1）

---

## 1. 目标概况

| 项目 | 内容 |
|---|---|
| 主站 | https://www.jiaoyu.cn（存活，HTTP 200） |
| 站点标题 | 「中教云课」 |
| 技术栈 | Vue CLI 打包 SPA（chunk-vendors / chunk-*.js 特征，PackerFuzzer 确认"前端打包器构建"） |
| 权威 NS | dns1/dns2.resource.edu.cn |
| 解析 IP | 202.205.109.10 / 202.205.11.70 / 202.205.109.1（教育网段） |
| 防护 | **存在 WAF**（证据见 §4.2） |

## 2. 执行过程（三轮编排）

| 轮次 | 环节 | 工具 | 结果 |
|---|---|---|---|
| 1 | 存活探测 | httpx (-timeout 5) | ✅ exit 0，站点存活 |
| 1 | 指纹+轻目录 | veo（692 指纹规则 + 38 敏感规则） | ✅ exit 0，见 §3.2 |
| 1 | 子域名 | OneForAll | ✅ exit 0，43 存活子域 |
| 2 | 目录爆破 | dirsearch | ❌ 首次因执行环境缺 APPDATA 崩溃（已修复） |
| 3 | 目录爆破 | dirsearch (-t 30 --max-time 150) | ✅ exit 0，11000+ 条目跑完 |
| 3 | 子域名复测 | OneForAll | ✅ exit 0，49 存活子域（较上轮 +6） |
| 3 | JS 分析 | PackerFuzzer | ✅ exit 0，提取 65 条 API |

## 3. 关键情报

### 3.1 子域名资产（49 存活）
- 爆破模块命中 11–16 个新子域；IP138 贡献 10 个；CertSpotter/Crtsh/HackerTarget/RapidDNS 各有补充
- 完整清单见工具箱输出：`tools/gui_shouji/oneforall/results/jiaoyu.cn.csv`
- 通配符解析已关闭（无泛解析噪声），后续可逐个对存活子域做指纹归类

### 3.2 路径与入口（veo + dirsearch）
| 路径 | 状态 | 说明 |
|---|---|---|
| `/admin.html` | 200 | 管理后台入口，返回「Firewall Captcha Authentication」页——后台存在但有防火墙验证码前置 |
| `/actuator/dump` | 200 | ⚠️ 疑似 Spring Boot Actuator，**但响应 1536B 与主页一致，大概率为 SPA fallback 假阳性**，需复核 |
| `/robots.txt` | 200 | 内容 22B，无有价值 disallow |
| `/fonts/`、`/js/` | 403 | 目录列表已关 |
| `/login/../;/actuator/info` | 500 | 返回「The URL you requested has been blocked」→ **WAF 拦截的直接证据** |

### 3.3 JS 分析揭示的 API 架构（PackerFuzzer + JS 静态分析）
- www.jiaoyu.cn 上的 `/api/*` 路径**并非本站后端**：无凭据 GET 全部返回 1528B SPA fallback（含基线对照），nginx 未在本站路由 /api/
- 前端实际通过 **专用 API 域名**调用后端（app.js 中硬编码），已确认存活的：
  - `apps-api.jiaoyu.cn` — 应用 API（`/api/user/info` 无凭据返回 `{"code":"2001","message":"未登录"}`，鉴权正常）
  - `xuexi-api.jiaoyu.cn` — 学习 API（`/api/user/info` 返回 `{"code":"2001","message":"账号未登录"}`，鉴权正常）
  - `api-yxt.jiaoyu.cn` — 云学堂 API（PHP/CodeIgniter，`ci_session`，Server: ZS-Proxy21/v201）
  - JS 中另引用（未深测）：`jw.jiaoyu.cn`（教务）、`sz`、`bk`、`kcsz`、`qmt`、`rmt` 子域及外部 `eol.cn` 系
- PackerFuzzer 提取的 40 条 `/api/*` 路径（65 条含变体）归属于上述各 API 域名使用
- 请求拦截器为透传实现，JS 中无硬编码 token/AK 泄露

### 3.4 API 未授权探测结果（2026-09-03，只读 GET，含基线对照）
| 目标 | 结果 | 判定 |
|---|---|---|
| www.jiaoyu.cn/api/* （31 条抽样） | 全部 200 + 1528B SPA fallback，与不存在路径基线一致 | 无后端，无暴露面 |
| apps-api `/swagger-ui.html`、`/v2|v3/api-docs`、`/actuator/health` | 404 | ✅ 无文档/组件暴露 |
| xuexi-api 同上 4 项 | 404 | ✅ 无文档/组件暴露 |
| apps-api `/api/login/info` | 200 JSON：登录配置（is_captcha_check:true 等） | 公开配置项，低价值 |
| api-yxt `/api/home/home`、`/api/course/teacher` | 200 JSON `code:2002`，要求提供学校/课程参数 | ⚠️ 未登录可达业务逻辑层，但需有效实体 ID |
| api-yxt `/api/course/teacher?course_id=1..3` | `{"code":"2004","message":"课程不存在"}` | 有效 ID 未知，盲枚举低效且具噪声，暂停 |

明细数据：`src-agent/api_auth_test_results.json`（脚本 `api_auth_test.py`，全程无参 GET、0.4s 限速）

## 4. 分析与研判

### 4.1 疑似点：/actuator/dump（已复核，确认为假阳性 ❌）
2026-09-03 复核：`curl https://www.jiaoyu.cn/actuator/dump` 返回 HTTP 200 + `Content-Type: text/html`，响应体 1536 字节，与主页**完全一致**且含 `<div id="app">`（Vue 挂载点）——确认是 SPA 把任意未知路径 fallback 到 index.html，**并非真实暴露的 Spring Boot Actuator**。该项从疑似漏洞中移除。

### 4.2 WAF 对挖洞路径的影响
- 目录爆破全量返回 500（38KB 统一拦截页）或 502（562B），**字典爆破在该站基本无效**，后续不要再用 dirsearch 硬冲
- `/admin.html` 有人机验证，弱口令爆破不可行

### 4.3 API 层安全态势（2026-09-03 只读探测结论）
- **鉴权基本到位**：apps-api / xuexi-api 的用户信息接口无凭据均正确返回「未登录」（code 2001）；swagger / api-docs / actuator 端点全部 404，无文档与组件暴露
- **api-yxt 的边界形态**：无登录即可到达业务逻辑层（按参数校验返回业务错误码 2002/2004），但未证实可获取数据——`course_id=1..3` 均返回「课程不存在」，有效 ID 需从业务页面获取后再评估；且课程/教师列表在教育平台通常属公开数据，即便可枚举价值有限
- **不建议继续**：course_id 盲枚举（噪声大）；POST 型接口探测（有产生写请求的风险）
- **值得继续**：① 从正常业务流收集有效 course_id 后复测 teacher/comment 接口；② 49 个存活子域中 sz/bk/kcsz/qmt/jw 等应用型子域逐一指纹归类，找后台/管理类资产；③ `api-yxt` 等 API 域的历史漏洞面（PHP + CodeIgniter + ZS-Proxy）可关注版本类漏洞披露

## 5. 结论

本轮通过 Agent 编排 5 类工具完成了 www.jiaoyu.cn 的基础信息收集：确认站点为教育网段的 Vue SPA，面内有 WAF 防护，收集到 49 个存活子域；通过 JS 静态分析厘清了真实 API 架构——www 主站无后端，业务由 apps-api / xuexi-api / api-yxt 等专用域承载。API 层只读探测未发现可提交漏洞：鉴权响应正确、无文档/组件暴露、无未授权数据访问被证实。`/actuator/dump` 已复核为 SPA fallback 假阳性。

该站安全基线较好，属「低垂果实已摘尽」形态。首份报告的价值在于完整的资产地图与「排除项」记录——后续换目标或深入子域时可直接复用本轮方法论（存活探测 → 指纹 → 子域 → JS 分析 → API 只读探测 → 假阳性复核）。

---

> 报告由本地 SRC 渗透 Agent 辅助生成。所有测试均在补天公益 SRC 授权范围内进行；后续任何 L2/L3 验证动作须逐项确认授权。
