# sub2api Cloudflare Worker

## 最终目标

```text
Cloudflare Pages
    ↓
Worker Router
    ↓
Services
    ↓
D1 Repositories
    ↓
Cloudflare D1
```

该目录用于逐步替代 `legacy/backend`。最终运行时只能依赖 Cloudflare Worker、Cron Trigger 和 D1，不得依赖 PostgreSQL、Redis、Durable Objects、Queues、R2、外部后端或其他状态存储。

## 当前迁移状态

当前 Worker 是公开后端入口。健康检查、setup、认证、用户域、管理 CRUD、支付订单、Stripe webhook、API Key 和模型网关已在 D1/Worker 内执行；未迁移的旧数据管理接口仍明确返回 503。部署配置不应依赖 `BACKEND` Service Binding。

Durable Object Coordinator 已移除。`src/repositories/` 现已提供 D1-only 的租约、固定窗口计数、幂等 reservation、过期 JSON 状态、任务入队与 Claim、哈希 refresh/pending OAuth session、安全写事务、完整用户创建/更新和认证邮件任务生产。Cron-triggered Worker 已能领取认证邮件任务、解密临时秘密、通过 TCP Socket SMTP 465/587 发送并在 D1 完成或退避重试。Setup 前端已删除 PostgreSQL、Redis、连接测试和重启流程，首个管理员直接写入 D1。密码登录/修改/重置、默认额度/平台额度/优惠码/邀请关系的原子注册、当前用户邮箱绑定与第三方解绑、OAuth pending/adoption、LinuxDo、OIDC、GitHub、Google、微信、DingTalk、Turnstile、TOTP、HS256 JWT、`/auth/me`、refresh rotation、logout、revoke-all 和用户安全写均由 Worker 路由执行；仅废弃的数据管理端点保留明确的 503 响应。

## 路由边界

Worker 接受下列完整路径边界，其他路径返回 JSON `404`，不会落入后端或 Pages 的 SPA fallback：

- 可包含子路径：`/api`、`/v1`、`/v1beta`、`/backend-api`、`/antigravity`、`/setup`、`/responses`、`/images`、`/videos`
- 仅精确匹配：`/health`、`/alpha/search`、`/chat/completions`、`/embeddings`

`GET /health`、`HEAD /health`、`GET /api/v1/settings/public`、`GET /setup/status` 和 `POST /setup/install` 由 Worker 本地执行。setup 状态与单次安装直接以 D1 `users` 为权威；不读取文件锁、PostgreSQL 连接、Redis 或服务重启状态。尚未迁移的请求保持 method、body stream、headers、查询参数和 WebSocket Upgrade；临时后端响应原样返回，因此 SSE、下载与 WebSocket 不会在路由层被缓冲。

## 目标源代码分层

```text
src/
├── router/
├── middleware/
├── services/
├── repositories/
├── types/
├── utils/
├── index.ts
└── routes.ts
```

迁移规则：

1. 结构调整期间保持现有路由基线可测试。
2. 业务逻辑逐模块进入 `services/`。
3. 所有持久化与协调状态进入 `repositories/` 并只访问 D1。
4. 不复制 Go 运行时代码，不新增外部存储依赖。
5. 模块完成 D1-only 实现和契约测试后，才能删除对应旧转发路径。

## 本地开发与验证

```bash
cd cloudflare/worker
npm install
npm run typecheck
npm test
npm run check:wrangler
```

需要同时启动前端时，在另一个终端执行：

```powershell
Set-Location ../../frontend
corepack pnpm@9.15.9 install
corepack pnpm@9.15.9 run dev
```

前端 Vite 的 `/api`、`/v1`、`/responses` 等请求应代理到 Wrangler 本地地址；不要把生产 Worker URL 写入源码。

生产初始化顺序：创建 D1 → 应用 `cloudflare/d1/migrations` → 设置 JWT/TOTP/邮件密钥 → `wrangler deploy` → 部署 Pages → 访问 `/setup` 创建首个管理员。支付启用后，在管理端保存供应商配置；Stripe 的 webhook 指向 `/api/v1/payment/webhook/stripe`，Airwallex 指向 `/api/v1/payment/webhook/airwallex`。Stripe 事件必须包含 `metadata.order_id`，Airwallex 事件必须包含 `merchant_order_id` 或 `metadata.order_id`；Worker 会校验时间窗、签名和订单金额。

当前测试覆盖路由边界、Service Binding 透传、SSE body stream、WebSocket Upgrade、防回环、缺失绑定行为、Go 路由契约、D1 运行时状态、公共设置与 setup status，以及暂存认证/用户域的 JWT BigInt claim、旧 token-version 指纹、原子 refresh rotation、Token Family 重放撤销、标准化邮箱唯一性、管理员创建/完整更新、默认订阅与分组关系、注册验证码和邀请码原子消费、加密邮件任务、邮件一次性消费/过期跳过/退避重试/秘密不落库、Worker SMTP STARTTLS/隐式 TLS、密码修改与一次性重置、API Key/身份清理、内部恢复、Go AES-GCM TOTP 互操作、设置/启停、失败锁定、setup 单次创建、logout 和 revoke-all。

## 邮件任务部署

`wrangler.toml` 每分钟触发一次邮件消费，单批默认最多 10 条。启用真实 D1 binding 后配置：

```bash
npx wrangler secret put EMAIL_TASK_ENCRYPTION_KEY
npx wrangler secret put SMTP_PASSWORD
```

## LinuxDo OAuth staging

LinuxDo start, authenticated bind-start, code exchange, userinfo validation, callback-to-D1-pending, generic completion, Worker-SMTP verification, atomic create/bind/adoption, and TOTP continuation are implemented in `src/router/staged-linuxdo-oauth.ts` and `src/router/staged-pending-oauth.ts`. They remain outside `src/index.ts` until the remaining OAuth providers can be activated with the same D1 identity authority.

For a confidential LinuxDo client, configure the secret with:

```bash
npx wrangler secret put LINUXDO_CLIENT_SECRET
```

The D1 settings `linuxdo_connect_enabled`, `linuxdo_connect_client_id`, and `linuxdo_connect_redirect_url` remain authoritative when present. Worker variables may override provider endpoints, scopes, PKCE, frontend callback, and token authentication method. See `cloudflare/docs/operations/LINUXDO_OAUTH_STAGING_AUDIT.md` for the complete variable and activation boundary.

## OIDC OAuth staging

Generic OIDC discovery or explicit endpoints, authenticated bind-start, browser-bound D1 PKCE/nonce state, token and userinfo exchange, RS256/PS256/ES256 JWKS validation, stable issuer/subject identity, verified-email fast registration, choice/create/bind completion, and TOTP continuation are implemented in `src/router/staged-oidc-oauth.ts` and the shared pending finalizer. They remain outside `src/index.ts` until every authentication provider can switch to D1 together.

Configure confidential-client credentials with `npx wrangler secret put OIDC_CLIENT_SECRET`. D1 OIDC settings remain authoritative when present; Worker variables support deployment-level endpoint and policy fallbacks. See `cloudflare/docs/operations/OIDC_OAUTH_STAGING_AUDIT.md`.

## GitHub and Google OAuth staging

Verified-email GitHub and Google start/callback/password-completion flows are implemented in `src/router/staged-email-oauth.ts`, `src/services/email-oauth.ts`, and the shared pending finalizer. Configure secrets with `npx wrangler secret put GITHUB_OAUTH_CLIENT_SECRET` and `npx wrangler secret put GOOGLE_OAUTH_CLIENT_SECRET`. See `cloudflare/docs/operations/EMAIL_OAUTH_STAGING_AUDIT.md`.

## WeChat OAuth staging

微信 Open/MP 登录、绑定、unionid 主身份、openid 渠道归属、旧 `wechat` 身份升级，以及支付 OAuth 均已在 `src/router/staged-wechat-oauth.ts` 中完成 D1 暂存迁移。支付上下文只写入浏览器绑定的一次性 D1 状态，回调签发 15 分钟 HMAC-SHA256 `wechat_resume_token`，不依赖 Redis。生产应配置 `npx wrangler secret put PAYMENT_RESUME_SIGNING_KEY`；迁移期可使用显式配置的 64 位十六进制 `TOTP_ENCRYPTION_KEY` 兼容旧令牌。完整边界见 `cloudflare/docs/operations/WECHAT_OAUTH_STAGING_AUDIT.md`。

`EMAIL_TASK_ENCRYPTION_KEY` 必须是 64 个十六进制字符，并与认证任务生产端一致。生产环境优先用 `SMTP_PASSWORD` Secret 覆盖 D1 中的过渡密码配置；其余 SMTP 设置继续读取 D1。Cloudflare Worker 禁止连接 SMTP 25 端口，应使用 465 隐式 TLS 或支持 STARTTLS 的 587 端口。
