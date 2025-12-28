# 🚀 Telegram 双向机器人 Cloudflare Worker

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-FFC425?logo=cloudflare)](https://workers.cloudflare.com/)
[![Telegram Bot API](https://img.shields.io/badge/Telegram-Bot_API-3AB3E0?logo=telegram)](https://core.telegram.org/bots/api)
[![D1 Database](https://img.shields.io/badge/D1-Database-FFC425?logo=cloudflare)](https://developers.cloudflare.com/d1)

> **企业级私聊托管与风控解决方案** - 通过 Cloudflare Worker + D1 数据库构建的高性能 Telegram 双向机器人，支持三模态验证、可视化协管系统和智能 CRM 管理

## ⚙️ 项目简介

这是一个基于 **Cloudflare Worker** 和 **D1 数据库** 构建的高性能 Telegram 双向机器人。  
**Telegram 双向机器人 Cloudflare Worker 混合验证版** 带来了质的飞跃：完美继承私聊消息转发到群组话题的 CRM 核心能力，更引入 **三模态混合验证系统**（Cloudflare/Google/关闭）与 **独立问题验证** 机制，配合全新可视化协管管理，为您提供企业级私聊托管与风控解决方案。

---

## 🌟 新增核心功能

*   **引用同步 (Quote Sync)**：
    *   当用户回复机器人发送的某条消息时，管理端话题中会同步显示对应的引用关系。
    *   当管理员在管理端回复特定消息时，用户端也会收到带有正确引用的回复消息。
*   **双向撤回 (Recall Sync)**：
    *   **指令化操作**：只需引用想要撤回的消息并发送 `/del`，即可同时删除用户端和管理端的对应消息。
    *   **权限覆盖**：用户与管理员均可使用此指令进行清理。
*   **编辑同步 (Edit Sync)**：
    *   实时监测消息状态。如果用户或管理员修改了已发送的消息内容，另一端的消息会自动同步更新。
*   **自动化就寝模式 (Sleep Mode)**：
    *   将原有的“营业状态”升级。管理员可设置特定的就寝时间段，到点后系统将自动进入休眠回复状态。

## 📄 功能列表

*   **安全验证**：支持 Cloudflare Turnstile、Google reCAPTCHA 以及自定义 Q&A 提问验证。
*   **消息过滤**：可设置屏蔽词库，并支持根据消息类型（转发、媒体、语音、贴纸等）开启或关闭转发。
*   **话题聚合**：自动在管理群创建话题，包含“🔔 未读消息”聚合话题和“🚫 黑名单”管理话题。
*   **用户资料卡**：管理员可实时查看用户 ID、加入时间，并支持添加备注信息。
*   **频率限制**：内置幂等校验与全局/用户限流，有效防止垃圾信息攻击。



## ⌨️ 常用指令

*   **用户端**：
    *   `/start`：开始验证或进入对话。
    *   `/del`：引用消息后发送，可执行双向撤回。
*   **管理员端**：
    *   `/start`：打开管理控制面板。
    *   `/help`：查看管理命令说明。
    *   `/reset <user_id>`：强制重置特定用户的验证状态。



## 🛠️ 部署指南（保姆级教程）

> **📺 视频教程**：[点击访问部署视频教程](https://t.me/yinhai_notify/371?comment=136740)

### 📋 准备工作
1. [Cloudflare 账号](https://dash.cloudflare.com/)
2. Telegram Bot Token（通过 [@BotFather](https://t.me/BotFather) 获取）
3. Telegram 管理员群组 ID（必须是**开启话题功能的超级群组**，ID 以 `-100` 开头，通过 [@raw_data_bot](https://t.me/raw_data_bot) 获取）
4. 管理员 ID（你自己的 TG ID，通过 [@raw_data_bot](https://t.me/raw_data_bot) 获取）

> 💡 **升级超级群组技巧**（不公开群组方法）：
> 1. 将群组的 **新成员是否可见消息记录** 设置为 **可见**
> 2. 在 **管理员权限** 中细分权限，关闭 bot 用不上的权限

---

### 步骤一：创建 D1 数据库
1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 导航至 **存储和数据库 → D1 数据库**
3. 点击 **创建数据库**，命名为 `tg-bot-db`（或自定义名称）
4. **无需**进行其他操作（代码会自动建表）

### 步骤二：创建 Worker
1. 进入 **Workers 和 Pages → 创建 Worker**
2. 命名 Worker（例如 `tg-contact-bot`）→ 点击 **部署**
3. 点击 **编辑代码**
4. **全量覆盖**：删除所有默认代码，将 [`worker.js`](https://github.com/your-repo/telegram-cf-worker/blob/main/worker.js) 的完整代码粘贴进去
5. **点击部署**，进行下一步配置

### 步骤三：绑定 D1 数据库
1. 在代码编辑页面左侧/上方找到 **设置 (Settings) 或 绑定 (Bindings)**
2. 添加 D1 数据库绑定：
   - **变量名称 (Variable Name)**：`TG_BOT_DB`（必须严格匹配大小写）
   - **数据库**：选择步骤一创建的数据库
3. 保存设置

### 步骤四：配置 Turnstile 验证
1. 在 Cloudflare 侧边栏选择 **Turnstile → 添加站点**
2. 填写配置：
   - **站点名称**：任意（如 `tg-bot-verification`）
   - **域**：填写 Worker 域名（例如 `your-worker.your-subdomain.workers.dev` 或 `workers.dev`）
   - **模式**：选择 **托管 (Managed)**
3. 创建后复制 **站点密钥 (Site Key)** 和 **密钥 (Secret Key)** 备用

### 步骤五：配置环境变量
在 Worker 的 **设置 → 变量** 中，添加以下 **9 个必备变量**：

| 变量名称 | 示例值 | 说明 |
|----------|--------|------|
| `BOT_TOKEN` | `12345:AAH...` | 你的 Bot Token |
| `ADMIN_IDS` | `123456,789012` | 管理员ID（多人用英文逗号分隔，**无空格**） |
| `ADMIN_GROUP_ID` | `-100123456789` | 开启话题的超级群组 ID |
| `WORKER_URL` | `https://xxx.workers.dev` | Worker 完整访问链接（**不带末尾斜杠**） |
| `TURNSTILE_SITE_KEY` | `0x4AAAA...` | 步骤四获取的 Turnstile 站点密钥 |
| `TURNSTILE_SECRET_KEY` | `0x4AAAA...` | 步骤四获取的 Turnstile 密钥 |
| `RECAPTCHA_SITE_KEY` | `6LAAAAABBCCDDBGHYDD_cDmgjUtEbpF` | [Google reCAPTCHA v2](https://www.google.com/recaptcha/admin) 站点密钥 |
| `RECAPTCHA_SECRET_KEY` | `6LAAAAABDDCCFGTTH-AIMK6z-H4aE` | [Google reCAPTCHA v2](https://www.google.com/recaptcha/admin) 密钥 |
| `TELEGRAM_WEBHOOK_SECRET` | `mRD0p7...` | 生成随机字符即可 |

> ⚠️ **重要**：  
> - Google reCAPTCHA 需自行在 [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin) 创建（选择 **v2 Checkbox** 类型）
> - 所有变量值**不要包含空格或引号**
> - 点击 **部署 (Deploy)** 使代码和配置生效

### 步骤六：设置 Webhook
在浏览器地址栏输入以下 URL 并回车（替换 `<你的BOT_TOKEN>` 和 `<你的WORKER_URL>` 和 `<你的TELEGRAM_WEBHOOK_SECRET>`）：
```bash
https://api.telegram.org/bot<你的BOT_TOKEN>/setWebhook?url=<你的WORKER_URL>/&secret_token=<你的TELEGRAM_WEBHOOK_SECRET>
```
✅ **成功响应**：
```json
{"ok":true,"result":true,"description":"Webhook was set"}
```

---

## ❓ 常见问题解答

| 问题现象 | 可能原因 | 解决方案 |
|----------|----------|----------|
| `[说明1] 系统忙，请稍后再试` | 1. 机器人未获得足够权限<br>2. 群组ID错误<br>3. 群组未升级为超级群组<br>4. 未开启话题功能 | 1. 检查群组是否为超级群组<br>2. 确认群组设置中 **开启话题**<br>3. 通过 [@raw_data_bot](https://t.me/raw_data_bot) 检查群组状态 |
| `[说明2] 私聊BOT/start无反应` | `BOT_TOKEN` 配置错误 | 1. 重新从 @BotFather 获取 Token<br>2. 检查环境变量是否有拼写错误<br>3. 重新设置 webhook |
| `[说明3] 回复消息无反应` | `ADMIN_IDS` 配置错误 | 1. 通过 [@raw_data_bot](https://t.me/raw_data_bot) 确认你的 TG ID<br>2. 检查环境变量中 ID 是否正确且无空格 |
| `[说明4] 点击配置菜单出现ERROR` | D1 数据库未绑定或变量名错误 | 1. 检查绑定变量名是否为 `TG_BOT_DB`（大小写敏感）<br>2. 确认数据库已正确创建 |
| `[说明5] 点击配置菜单无反应` | D1 数据库配置错误 | 1. 重新绑定数据库<br>2. 检查 Worker 代码是否包含最新 D1 初始化逻辑 |

---

## 📜 许可证
本项目采用 [MIT 许可证](LICENSE) - 详情请参阅 LICENSE 文件

---

> **💡 提示**：部署完成后，向机器人发送 `/start` 即可体验完整功能！  
> 开始使用后，每个话题可自行替换自己喜欢的图标。 
> 遇到问题？自行解决。 

**🌟 给项目一个 Star 吧！您的支持是我们持续更新的动力！**  
[![GitHub stars](https://img.shields.io/github/stars/your-repo/telegram-cf-worker?style=social)](https://github.com/Rude56/TG_Chat_Bot-D1)
