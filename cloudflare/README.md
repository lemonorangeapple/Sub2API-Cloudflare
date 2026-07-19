# Sub2API on Cloudflare

## 架构

```
浏览器
  ├─ 前端静态资源 → Cloudflare Pages
  └─ API 请求    → Cloudflare Worker → Cloudflare D1
```

- **前端**：Vue 3 SPA，部署到 Cloudflare Pages
- **后端**：Cloudflare Worker (TypeScript)，处理所有 API 路由
- **数据库**：Cloudflare D1 (SQLite 边缘副本)，唯一持久化存储

无 PostgreSQL、Redis、Docker、外部数据库依赖。

## 目录结构

| 目录 | 说明 |
|------|------|
| `worker/` | Worker 后端源码、路由、服务、D1 仓库 |
| `d1/migrations/` | D1 数据库迁移文件（按顺序执行） |
| `pages/` | Pages 部署配置 |
| `scripts/` | 构建验证脚本 |
| `../frontend/` | Vue 3 前端（构建产物部署到 Pages） |
| `../legacy/` | 原始 Go 后端（仅供参考，运行时不使用） |

## 本地测试

```bash
cd worker
npm install
npx tsx --test test/*.test.mjs   # 740 tests
```

## 部署

详见根目录 [README.md](../README.md) 的「生产部署」章节。

```bash
# 1. 创建 D1 数据库
npx wrangler d1 create sub2api

# 2. 执行迁移
cd worker
npx wrangler d1 migrations apply sub2api --remote

# 3. 配置 wrangler.toml 中的 database_id

# 4. 部署 Worker
npx wrangler deploy

# 5. 部署前端
cd ../../frontend
pnpm install && pnpm build
npx wrangler pages deploy dist --project-name=sub2api-frontend
```
