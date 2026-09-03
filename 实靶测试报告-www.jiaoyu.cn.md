# SRC Agent v0.1.0 实靶测试报告

**测试目标**：`www.jiaoyu.cn`
**授权依据**：补天平台公益 SRC，全部范围为测试资产
**测试时间**：2026-08-31 ~ 2026-09-01
**测试任务**：对目标做存活探测、子域名收集与指纹识别
**结论**：✅ 端到端流程跑通，产出可用侦察结果；过程中发现并修复 4 个缺陷

---

## 一、执行结果

### 最终一轮的工具执行轨迹

| # | 工具 | 风险 | 结果 | 说明 |
|---|---|---|---|---|
| 1 | Httpx 辅助工具 | L0 | ✅ done | 确认 `https://www.jiaoyu.cn` 存活 |
| 2 | ENScan | L0 | ❌ error | 爱企查强制验证码，被 90s 总时长上限终止 |
| 3 | OneForALL | L0 | ✅ done | 收集到 24 个唯一子域 |
| 4 | VEO 指纹识别工具 | L0 | ✅ done | 识别出主站指纹 + 目录扫描结果 |

### 子域名收集结果（24 个唯一子域，全部解析到 202.205.109.115）

| 子域名 | 状态 | 标题 | 关注点 |
|---|---|---|---|
| oa.jiaoyu.cn | 403 | 403 Forbidden | ⭐ OA 系统，高价值目标 |
| hw.jiaoyu.cn | 200 | 登录 | ⭐ 登录入口 |
| ks.jiaoyu.cn | 200 | 1+X职业技能等级证书考试平台 | ⭐ 考试业务系统 |
| apps-api.jiaoyu.cn | 404 | Not Found | API 端点 |
| xuexi-api.jiaoyu.cn | 404 | Not Found | API 端点 |
| ai.jiaoyu.cn | 200 | 无权限页面 | 鉴权绕过可测 |
| qmt.jiaoyu.cn | 200 | 无权限页面 | 鉴权绕过可测 |
| rmt.jiaoyu.cn | 200 | 无权限页面 | 鉴权绕过可测 |
| mz.jiaoyu.cn | 200 | 智能媒资管理平台 | 文件上传面 |
| jw.jiaoyu.cn | 200 | 中教云课-全媒体人才培养实训教学平台 | 业务系统 |
| yq.jiaoyu.cn | 200 | 中教云课-全媒体人才培养实训教学平台 | 业务系统 |
| bk.jiaoyu.cn | 200 | 课程思政资源管理平台 | 业务系统 |
| shijian.jiaoyu.cn | 200 | 高校思想政治理论课实践教学平台 | 业务系统 |
| kcsz.jiaoyu.cn | 200 | 思政资源库 | 业务系统 |
| sz.jiaoyu.cn | 200 | 思政资源库 - 中国教育在线 | 业务系统 |
| zhsz.jiaoyu.cn | 200 | 思政资源库 - 中国教育在线 | 业务系统 |
| apps.jiaoyu.cn | 200 | 信息服务中心-教育在线 | 业务系统 |
| photo.jiaoyu.cn | 200 | 头像生成 | 图片处理面 |
| video1.jiaoyu.cn | 400 | forbidden access root | ⭐ 云存储桶特征 |
| qmt-static.jiaoyu.cn | 403 | 403 Forbidden | 静态资源 |
| www.jiaoyu.cn | 200 | 中教云课 | 主站 |
| jiaoyu.cn | 200 | 中教云课 | 主站 |
| yxt.jiaoyu.cn | 200 | 中教云课 | 业务系统 |
| mail.jiaoyu.cn | — | — | 未解析/未响应 |

### 主站指纹识别结果（VEO）

```
https://www.jiaoyu.cn                     [200] [中教云课] [1536] [text/html]
https://www.jiaoyu.cn/robots.txt          [200] [无标题]   [22]   [text/plain]
https://www.jiaoyu.cn/admin.html          [200] [Firewall Captcha Authentication]
https://www.jiaoyu.cn/css/                [403]
https://www.jiaoyu.cn/js/                 [403]
https://www.jiaoyu.cn/fonts               [301]
```

**关键线索**：
- `admin.html` 返回 `Firewall Captcha Authentication` → 存在 WAF / 防火墙验证码防护
- 探测 `/actuator/env` 被拦截（返回 `The URL you requested has been blocked`）
- EHole 识别 Web Server 为 `ZS-Proxy21/v201`（反向代理），站点标题「中教云课」

---

## 二、发现并修复的缺陷

### 缺陷 1：工具超时形同虚设（严重）

**现象**：ENScan 撞上验证码后每 10 秒刷一行重试日志，无限运行；手动杀进程前已空转 10 分钟以上。

**根因**：`executor.run()` 用的是 `asyncio.wait_for(proc.stdout.readline(), timeout=TOOL_TIMEOUT)`——这是**逐行空闲超时**，只约束「多久没输出」。工具只要持续输出就永远不会超时。

**修复**：改为双重超时——
- 总时长上限 `TOOL_TIMEOUT`（默认 600s，可按工具覆写）
- 空闲上限 `TOOL_IDLE_TIMEOUT`（默认 120s）
- 新增 `MAX_OUTPUT_LINES`（默认 2000）截断，防止狂刷输出撑爆上下文

### 缺陷 2：模型反复调用同一失败工具

**现象**：ENScan 失败后，模型又连续调用了它两次；httpx 已成功返回仍被重复调用 4 次。

**根因**：系统提示词每轮固定，模型看不到自己已经试过什么。

**修复**：新增 `Agent._build_reminder()`，每轮动态注入「本轮已尝试过的工具」清单，并标注失败次数，明确禁止同参数重复调用；同时在工具失败回执里点名禁止重试该工具。

### 缺陷 3：目标格式不匹配导致工具静默失败

**现象**：`ehole finger -u www.jiaoyu.cn` 返回空、退出码 1，看起来像工具坏了。

**实测**：带 scheme 后正常——
```
$ EHole finger -u https://www.jiaoyu.cn
[ https://www.jiaoyu.cn | baidu站长平台 | ZS-Proxy21/v201 | 200 | 1536 | 中教云课 ]
```

**修复**：给 43 个调用模板补充 `target` 格式声明（`url` / `host` / `domain` / `raw`），执行前自动归一化：

| 形式 | 处理 | 适用 |
|---|---|---|
| `url` | 补全 `https://` | ehole / sqlmap / dirsearch / afrog 等 |
| `host` | 去掉 scheme 与路径，保留端口、保留 CIDR | fscan / kscan / goon 等 |
| `domain` | 再去 `www.` 与端口，保留 CIDR | oneforall |
| `raw` | 原样 | enscan（企业名）等 |

顺带修掉两个边界 bug：CIDR `192.168.1.0/24` 被截断成 `192.168.1.0`（扫描器会漏掉整个网段）、`domain` 形式保留了端口。

### 缺陷 4：ENScan 不可用但仍被编排

**现象**：加注意事项后模型依然选它，每轮白耗 90 秒。

**处理**：`disabled: true`（与其他 6 个实测不可用工具一致），保留 `reason` 说明，人工过验证码后可改回 `false`。

---

## 三、验证通过的机制

| 机制 | 表现 |
|---|---|
| 目标锁定与防遗忘 | 全程锁定 `www.jiaoyu.cn`，未向用户索要目标 |
| 幻觉工具拦截 | 模型编造工具名 `object`，被注册表拦截并回喂纠错 |
| 无工具调用催促 | 模型两次「只分析不调工具」，催促机制触发后恢复执行 |
| 风险分级 | 本轮全部为 L0 只读工具，未触发 L1/L2 闸门 |
| 增量落库 | 每步即时写库，报告中完整呈现 20 条历史步骤 |
| 报告生成 | 自动汇总多会话步骤，输出补天格式 Markdown |

---

## 四、遗留问题

1. **本地小模型决策慢**：`qwen3.5:9b` 每步决策 13–25 秒，一轮 4 步约 5 分钟。建议接 DeepSeek 作为复杂决策后端（配置 `DEEPSEEK_API_KEY` 即可启用）。
2. **模型易陷入「分析」而非「行动」**：两轮测试共触发 3 次催促。可考虑在系统提示词中进一步强化「二选一」约束。
3. **子域存活探测未闭环**：oneforall 已给出子域清单，但流水线没有自动把存活子域喂给指纹工具做批量识别。
4. **报告步骤未全局排序**：当前按会话分组展示，跨会话时间顺序是乱的。

---

## 五、复现方式

```bash
# 1. 启动服务
C:\Users\Lianaxber\.workbuddy\binaries\python\envs\src-agent\Scripts\python.exe run.py --no-browser

# 2. 跑自动化实靶测试
C:\Users\Lianaxber\.workbuddy\binaries\python\envs\src-agent\Scripts\python.exe test_jiaoyu.py
```

测试脚本策略：L1/L2 自动放行，L3 自动拒绝（验证降级路径）。日志写入 `jiaoyu_run*.out`。
