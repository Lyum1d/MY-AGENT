# 产品指纹 → 敏感路径基线（常见 CMS / 邮件 / 网盘 / 框架）

> **这个篇目解决什么**：指纹识别出产品之后，**直接知道该验证哪些路径**，而不是凭记忆猜。
> 实测背景：`kb_search("KodExplorer 未授权")` 曾零命中 → agent 只能靠记忆撞路径，
> 在 lsnu 实战中**白耗 2 次请求撞 403**。知识库过去只按「漏洞类型」组织，缺「按产品」这一维。
>
> **使用纪律（硬约束）**：本表所有路径**只做只读 GET/HEAD**；**只验证存在性**
> （状态码 + 长度 + 与基线的差分），**不下载内容、不试口令、不遍历**。
> **403 只记存在性、不上报**（除非能证明绕过）。**已公开引用的静态资源返回 200 不算命中。**

## 一、用法

1. 先用 `ehole` / `httpx` 拿到**产品指纹**；
2. 在下表找到对应产品 → 取「优先验证路径」；
3. **串行、逐点、带间隔**地打（每路径 ≤1 次，用内置小字典见 `data/wordlists/common-small.txt`）；
4. 记录「状态码 + 长度」，**用差分判存在性**（见第二节）。

## 二、动手前先建「404 差分基线」（通用，强烈建议）

很多 CMS 会返回**两套 404 页面**：**应用层 404**（框架接管）与 **Web 服务器原生 404**。
先各取一个样本、记录长度，之后任何 404 命中哪一套，就能判断**该路径是否落在应用路由内**。

> 实测（lsnu.edu.cn，TRS 站群）：`404 + 2357 字节` = 被 TRS CMS 路由接管（该命名空间**真实存在**）；
> `404 + 1627 字节` = VWebServer 原生未命中（路径**根本不存在**）。
> 这个判据比只看状态码精确得多，且**零额外成本**（反正要测路径存在性）。

## 三、按产品

### 拓尔思 TRS SiteBuilder / VWebServer（高校/政府站群常见）

| 项 | 内容 |
| --- | --- |
| **识别特征** | `Server: VWebServer` 或 `VAppServer`；页面注释 `Announced by Visual SiteBuilder 9`；资源路径含 `_sitegray/`；首页含 `CustomerNO:` 注释 |
| **优先验证** | `/system/`、`/system/resource/`、`/system/login.jsp`（后台）、`/_sitegray/`、`/system/resource/js/`（目录列表） |
| **要点** | 后台 `/system/login.jsp` **通常不公网暴露**（返回 404）；`/system/resource/js/*.js` 是**首页本就引用**的公开资源（200 **不算**命中）；**404 双模板差分**是该 CMS 的天然判据 |

### RainLoop WebMail（开源 PHP 邮件前端）

| 项 | 内容 |
| --- | --- |
| **识别特征** | `Server: RainLoop`（**响应头直接返回产品名**）；页面含 `rainloop`；默认界面为 webmail 登录 |
| **优先验证** | `/?/Admin/`（管理面板）、`/?/admin/`、`/data/`、`/version`、`/index.php` |
| **要点** | `/?/Admin/` 返回 **200 = 管理面板入口公网暴露** —— 但**可达 ≠ 可利用**：是否可登录取决于弱口令/未授权功能，**禁试口令**，只记存在性；**`/data/` 返回 403 = 有防护**（该目录历史上是可访问的高危点，被拦住说明部署有基础防护，**不要按"默认不安全"推定**） |

### KodExplorer / 可道云（网盘类）

| 项 | 内容 |
| --- | --- |
| **识别特征** | 页面标题含 `Powered by KodExplorer`；路由形态 `index.php?user/login`；ehole 常报 `Kodcloud-System` |
| **优先验证** | `/data/`（历史高频高危：用户配置与会话）、`/data/system/`、`/index.php?user/login`、`/plugins/` |
| **要点** | **`/data/` 是这类产品的核心验证点**：可访问则可能泄露用户配置 → 高危；返回 **403/404 即为有防护** |

### Spring Boot Actuator

| 项 | 内容 |
| --- | --- |
| **识别特征** | 错误页为标准 JSON（`{"timestamp":...,"status":404,"error":"Not Found","message":"No message available","path":"..."}`）；`/v3/api-docs` 返回 JSON |
| **优先验证** | `/actuator`、`/actuator/health`、`/actuator/env`、`/actuator/heapdump`、`/env`、`/health` |
| **要点** | **先只看状态码**：`/actuator/env` 若 200，说明配置可读（**高危**）——但按纪律**只记录存在性，不读取内容** |

### Swagger / Knife4j（API 文档）

| 项 | 内容 |
| --- | --- |
| **识别特征** | `/doc.html`、`/swagger-resources` 可达；根路径 302 → `/doc.html` 是典型特征 |
| **优先验证** | `/doc.html`、`/swagger-resources`、`/swagger-resources/configuration/security`、`/swagger-resources/configuration/ui`、`/v2/api-docs`、`/v3/api-docs` |
| **要点** | ⚠️ **必须区分「文档外壳可达」与「接口定义可读」**：前者只是 UI 页面（**低危**），后者才暴露全部接口与参数模型（**严重**）。实测（cread.com）：`/doc.html` 与 `/swagger-resources` 均 200，但 `/v2/api-docs` **403** —— 属于「门开着、数据源关着」，**不得写成接口泄露** |

## 四、通用敏感路径（任何目标都可小步验证）

| 类别 | 路径 |
| --- | --- |
| 备份文件 | `/backup.zip`、`/www.zip`、`/web.zip`、`/database.sql`、`/index.php.bak` |
| 编辑器残留 | `/ewebeditor/`、`/fckeditor/`、`/ueditor/`、`/.swp` |
| 配置文件 | `/.env`、`/config.php`、`/web.config`、`/.git/config`、`/.svn/entries` |
| 上传目录 | `/upload/`、`/uploads/`、`/userfiles/`、`/attachment/` |
| 接口文档 | `/api-docs`、`/swagger-ui.html`、`/doc.html` |
| 目录列表 | `/data/`、`/files/`、`/logs/`、`/temp/` |

> ⚠️ **敏感后缀必须分散**（`.zip`/`.sql`/`.env`/`.git` 不要连续请求）——实测会触发目标 IPS
> **直接封禁源 IP**。要探这类路径时，与普通路径**交错着打**、带间隔、少量。

## 五、这套基线的实际战绩（可参考的期望值）

- **cread.com**：靠 Swagger 基线判出「文档外壳 200 / 接口定义 403」，避免把低危写成高危
- **lsnu.edu.cn**：靠 404 双模板基准确认「站群后台与上传面未公网暴露」；
  RainLoop `/data/` 403 判为「有防护」而非敞口
- **反例**：lsnu 首轮**没跑目录扫描**时，这些结论一个都拿不到 —— **阴性结论也需要"扫过"才成立**
