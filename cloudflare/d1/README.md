# Cloudflare D1 数据库

## 迁移文件

`migrations/` 目录包含按顺序执行的 D1 SQL 迁移：

| 文件 | 说明 |
|------|------|
| `0001_ent_core.sql` | 核心表（users, accounts, api_keys, groups 等 38 张表） |
| `0002_business_supplemental.sql` | 业务补充表（orders, subscriptions, affiliates 等） |
| `0003_ops_usage_supplemental.sql` | 运营与用量统计表 |
| `0004_runtime_state.sql` | 运行时状态表（leases, counters, reservations 等） |
| `0005_auth_sessions.sql` | 认证会话表 |
| `0006_user_email_integrity.sql` | 用户邮箱唯一性约束 |

## 执行迁移

```bash
npx wrangler d1 migrations apply sub2api --remote
```

## 查看数据

```bash
npx wrangler d1 execute sub2api --remote --command "SELECT COUNT(*) FROM users"
```
