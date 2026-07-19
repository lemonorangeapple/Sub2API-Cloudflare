# Cloudflare Pages

前端 Vue 3 SPA 部署到 Cloudflare Pages。

## 配置

- 根目录：`frontend`
- 构建命令：`pnpm install && pnpm build`
- 输出目录：`dist`
- Wrangler 配置：`frontend/wrangler.toml`

## 部署

```bash
cd frontend
pnpm install && pnpm build
npx wrangler pages deploy dist --project-name=sub2api-frontend
```

Pages 提供静态托管和 SPA 回退。所有 API 请求由 Worker 处理，不使用 Pages Functions。
