# Sub2API Cloudflare

<div align="center">

[![Vue](https://img.shields.io/badge/Vue-3.4+-4FC08D.svg)](https://vuejs.org/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020.svg)](https://workers.cloudflare.com/)
[![D1](https://img.shields.io/badge/Cloudflare-D1-EDB716.svg)](https://developers.cloudflare.com/d1/)
[![License](https://img.shields.io/badge/License-LGPL--3.0-green.svg)](LICENSE)

**sub2api 的 Cloudflare Workers 移植版本 — 无需 PostgreSQL / Redis / Go**

</div>

## 项目说明

本项目是 [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api) 的 **Cloudflare 全栈移植版**。

原始 sub2api 使用 Go + PostgreSQL + Redis 构建，需要自行运维数据库和缓存服务。本移植版将其完全迁移到 Cloudflare 边缘计算平台：

| | 原版 (sub2api) | 本移植版 |
|---|---|---|
| **后端** | Go + Gin + Ent ORM | Cloudflare Worker (TypeScript) |
| **数据库** | PostgreSQL 15+ | Cloudflare D1 (SQLite 边缘副本) |
| **缓存/队列** | Redis 7+ | D1 原生表 + Worker 内存 |
| **前端** | Vue 3 (嵌入 Go 二进制) | Vue 3 (Cloudflare Pages) |
| **部署** | Docker / 裸机 | Wrangler CLI / Cloudflare Dashboard |
| **运维** | 需监控服务器 | 全托管，自动扩缩容 |

### 当前功能覆盖

Worker 已将认证、用户域、API Key、管理端 CRUD、订阅、公告、渠道、运营、OAuth 暂存流程和模型网关接入 D1；测试会显式覆盖这些模块。支付订单/管理接口、Stripe/Airwallex 支付意图和签名回调已有 D1 实现与安全测试。支付宝、微信支付和 EasyPay 的真实商户签名/预支付仍需要按供应商协议配置并完成对应回调适配，不能在未配置密钥时模拟“支付成功”。


- 用户认证（邮箱 / OAuth / TOTP 2FA）
- API Key 管理与配额分发
- 多平台账号调度（OpenAI / Claude / Grok / Gemini / Antigravity）
- 订阅计划与支付订单（Stripe/Airwallex 已验证；其他供应商需配置真实签名与回调）
- 管理后台（用户管理 / 渠道监控 / 风控 / 公告 / 代理）
- 数据管理（旧 PostgreSQL/Redis/S3 管理 API 已废弃并明确返回 503）

### 声明

- **🚨 服务条款风险**：使用本项目可能违反 Anthropic 等上游提供商的服务条款。请在使用前仔细阅读相关用户协议，所有风险由用户自行承担。
- **⚖️ 合规使用**：仅在您所在国家/地区的法律法规允许的范围内使用本项目。
- **📖 免责声明**：本项目仅供技术学习和研究用途，作者不对因使用本项目导致的任何直接或间接损失承担责任。

---

## 前置条件

- [Node.js](https://nodejs.org/) 18+ (推荐 20+)
- [pnpm](https://pnpm.io/) (推荐 9+)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (Cloudflare Workers 部署工具)
- [Cloudflare 账号](https://dash.cloudflare.com/) (免费套餐即可)

---

## 本地开发调试

### 1. 克隆仓库

```bash
git clone https://github.com/your-org/sub2api-cloudflare.git
cd sub2api-cloudflare
```

### 2. 安装 Worker 依赖

```bash
cd cloudflare/worker
npm install   # 或 pnpm install
```

### 3. 运行 Worker 测试

Worker 使用 Node.js 内置 test runner + 内存 D1 模拟器，无需真实 Cloudflare 环境：

```bash
# 运行全部 Worker 测试（PowerShell）
$tests = Get-ChildItem test -Filter *.test.mjs | ForEach-Object { $_.FullName }
node --experimental-strip-types --test $tests

# 运行单个测试文件
node --experimental-strip-types --test test/admin-backups.test.mjs
```

### 4. 本地开发服务器

```bash
# 启动 Worker 本地 HTTP 服务
npx wrangler dev
```

### 5. 安装前端依赖

```bash
cd ../../frontend
pnpm install   # 必须用 pnpm，不要用 npm
```

### 6. 前端开发模式

```bash
pnpm dev
# 默认 http://localhost:3000，自动代理 /api 到后端
```

### 7. 构建前端

```bash
pnpm build
# 产物在 frontend/dist/
```

### 8. 运行前端测试

```bash
npx vitest run
# 154 个测试文件，1072 个测试
```

---

## 生产部署

### 部署架构

```
┌─────────────────────────────────────────────┐
│              Cloudflare 边缘网络              │
│                                             │
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │ Cloudflare   │    │ Cloudflare Worker    │ │
│  │ Pages        │───▶│ (sub2api-router)     │ │
│  │ (前端 SPA)   │    │                     │ │
│  └─────────────┘    │  ┌───────────────┐  │ │
│                     │  │ D1 Database    │  │ │
│                     │  │ (SQLite 边缘)  │  │ │
│                     │  └───────────────┘  │ │
│                     └─────────────────────┘ │
└─────────────────────────────────────────────┘
```

### 第一步：创建 D1 数据库

```bash
# 创建数据库
npx wrangler d1 create sub2api

# 记录输出中的 database_id
```

### 第二步：运行数据库迁移

```bash
cd cloudflare/worker

# 逐个执行迁移文件（按顺序）
npx wrangler d1 migrations apply sub2api --remote
```

迁移文件位于 `cloudflare/d1/migrations/`：

| 文件 | 用途 |
|------|------|
| `0001_ent_core.sql` | 核心表（users, accounts, api_keys, groups 等） |
| `0002_business_supplemental.sql` | 业务补充表（orders, subscriptions, affiliates 等） |
| `0003_ops_usage_supplemental.sql` | 运营与用量表 |
| `0004_runtime_state.sql` | 运行时状态表（leases, tasks, reservations 等） |
| `0005_auth_sessions.sql` | 认证会话表 |
| `0006_user_email_integrity.sql` | 用户邮箱完整性约束 |

### 第三步：配置 Worker

编辑 `cloudflare/worker/wrangler.toml`，取消注释并填入真实值：

```toml
# D1 数据库绑定
[[d1_databases]]
binding = "DB"
database_name = "sub2api"
database_id = "<你的 D1 database_id>"
migrations_dir = "../d1/migrations"

# 或者如果仍需要 Go 后端过渡，启用 Service Binding：
# [[services]]
# binding = "BACKEND"
# service = "sub2api-backend"
# environment = "production"
```

### 第四步：设置 Worker 密钥

```bash
# JWT 签名密钥（至少 32 字符）
npx wrangler secret put JWT_SECRET

# TOTP 加密密钥（64 位十六进制）
npx wrangler secret put TOTP_ENCRYPTION_KEY

# 邮件任务加密密钥（64 位十六进制）
npx wrangler secret put EMAIL_TASK_ENCRYPTION_KEY

# SMTP 密码（如需邮件功能）
npx wrangler secret put SMTP_PASSWORD
```

生成密钥：
```bash
# JWT_SECRET
openssl rand -base64 32

# TOTP_ENCRYPTION_KEY / EMAIL_TASK_ENCRYPTION_KEY
openssl rand -hex 32
```

### 第五步：设置 CORS 来源（跨域部署时必需）

当前端和 Worker 部署在不同域名时，需要配置 CORS 允许来源：

```bash
# 允许单个来源
npx wrangler secret put CORS_ALLOWED_ORIGINS
# 输入: https://yourdomain.com

# 允许多个来源（逗号分隔）
npx wrangler secret put CORS_ALLOWED_ORIGINS
# 输入: https://yourdomain.com,https://admin.yourdomain.com
```

> **注意**：如果前端和 Worker 在同一域名下（如通过 Cloudflare 路由配置），则无需设置此变量。

### 第五步：部署 Worker

```bash
cd cloudflare/worker
npx wrangler deploy
```

部署后获得 Worker URL，例如：`https://sub2api-router.your-subdomain.workers.dev`

### 第六步：部署前端到 Cloudflare Pages

```bash
cd frontend

# 设置 Worker API 地址（替换为你的实际 Worker URL）
WORKER_URL="https://sub2api-router.your-subdomain.workers.dev/api/v1"

# 构建时注入 API 地址
VITE_API_BASE_URL="$WORKER_URL"

pnpm build

# 部署到 Cloudflare Pages
npx wrangler pages deploy dist --project-name=sub2api-frontend
```

或者通过 Cloudflare Dashboard 配置：
1. 在 Pages 项目设置中添加环境变量 `VITE_API_BASE_URL`，值为 Worker URL（如 `https://sub2api-router.xxx.workers.dev/api/v1`）
2. 设置构建命令为 `cd frontend && pnpm install && pnpm build`，输出目录为 `frontend/dist`
3. 每次 Git 推送自动触发构建，环境变量自动注入

> **注意**：`VITE_API_BASE_URL` 会被 Vite 在构建时编译进静态资源。如果部署后需要更改 Worker 地址，必须重新构建前端。

### 第七步：绑定自定义域名（推荐）

1. 在 Cloudflare Dashboard 中为 Worker 添加自定义域名路由（如 `api.yourdomain.com`）
2. 在 Pages 项目中添加自定义域名（如 `yourdomain.com`）
3. 更新 Pages 环境变量 `VITE_API_BASE_URL` 为新的 Worker 域名（如 `https://api.yourdomain.com`），然后重新构建部署

### 第八步：初始化系统

访问前端页面，完成首次设置向导：
- 创建管理员账号
- 配置系统参数

---

## 项目结构

```
sub2api-cloudflare/
├── cloudflare/
│   ├── worker/                  # Cloudflare Worker 后端
│   │   ├── src/
│   │   │   ├── index.ts         # Worker 入口，路由链
│   │   │   ├── routes.ts        # 路由分类器
│   │   │   ├── middleware/      # 中间件（CORS 等）
│   │   │   ├── router/          # 各路由模块
│   │   │   ├── services/        # 业务逻辑层
│   │   │   ├── repositories/    # D1 数据访问层
│   │   │   └── types/           # TypeScript 类型定义
│   │   ├── test/                # Worker tests (760 tests)
│   │   └── wrangler.toml        # Worker 配置
│   ├── d1/
│   │   ├── migrations/          # D1 数据库迁移
│   │   └── schema/              # 表结构定义
│   └── pages/                   # Cloudflare Pages 配置
├── frontend/                    # Vue 3 前端
│   ├── src/
│   │   ├── api/                 # API 客户端
│   │   ├── views/               # 页面组件
│   │   ├── components/          # 通用组件
│   │   ├── stores/              # Pinia 状态管理
│   │   ├── router/              # Vue Router
│   │   └── i18n/                # 国际化
│   ├── dist/                    # 构建产物
│   └── wrangler.toml            # Pages 配置
└── legacy/                      # 原始 Go 后端（仅供参考）
```

---

## 测试

### Worker 测试

```bash
cd cloudflare/worker
npm test
# 760 tests, 0 failures
```

### 前端测试

```bash
cd frontend
npx vitest run
# 1072 tests, 0 failures
```

### 类型检查

```bash
cd frontend
npx vue-tsc -b
```

---

## 环境变量参考

### Worker 必需

| 变量 | 说明 |
|------|------|
| `DB` | D1 数据库绑定（通过 wrangler.toml 配置） |
| `JWT_SECRET` | JWT 签名密钥（secret，至少 32 字符） |

### Worker 可选

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `JWT_ACCESS_TOKEN_EXPIRES_SECONDS` | `86400` | Access Token 过期时间 |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `30` | Refresh Token 过期天数 |
| `TOTP_ENCRYPTION_KEY` | — | TOTP 密钥加密（64 位 hex） |
| `EMAIL_TASK_ENCRYPTION_KEY` | — | 邮件任务加密（64 位 hex） |
| `EMAIL_TASK_BATCH_SIZE` | `10` | 邮件任务批量大小 |
| `SMTP_PASSWORD` | — | SMTP 密码（覆盖 D1 设置） |
| `CORS_ALLOWED_ORIGINS` | — | CORS 允许的来源（逗号分隔），如 `https://yourdomain.com`；留空则禁用跨域 |

### 前端

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `VITE_API_BASE_URL` | `/api/v1` | API 基础 URL。部署到 Pages 时必须设为 Worker 的完整 URL（如 `https://api.xxx.workers.dev`） |
| `VITE_DEV_PORT` | `3000` | 开发服务器端口 |
| `VITE_DEV_PROXY_TARGET` | `http://localhost:8080` | 开发代理目标 |

> **Cloudflare Pages 部署**：`VITE_API_BASE_URL` 在构建时编译进静态资源。在 Pages 项目设置中配置此环境变量为 Worker URL，每次构建会自动注入。

---

## 常见问题

### Worker 部署后 503 错误

检查 D1 绑定是否正确配置，以及迁移是否已执行：
```bash
npx wrangler d1 list
npx wrangler d1 execute sub2api --command "SELECT COUNT(*) FROM users"
```

### 前端 API 请求 404

确保前端的 `VITE_API_BASE_URL` 指向正确的 Worker URL，或在生产环境中使用同源路径 `/api/v1`。

### 本地测试失败

Worker 测试使用内存 D1 模拟器，无需真实 Cloudflare 环境。如果测试失败，检查是否所有迁移文件都在 `cloudflare/d1/migrations/` 中。

---

## 许可证

本项目基于 [GNU Lesser General Public License v3.0](LICENSE) 授权。

原始项目 Copyright (c) 2026 Wesley Liddick。
移植版本保留原始许可证条款。

---

<div align="center">

**基于 [sub2api](https://github.com/Wei-Shaw/sub2api) 移植 — 由 Cloudflare 边缘计算驱动**

</div>
