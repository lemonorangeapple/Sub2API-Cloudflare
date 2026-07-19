import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement, runBatchTransaction, type D1BatchStatement } from "./d1.ts";

export interface UserDetail {
    id: number;
    email: string;
    username: string;
    role: string;
    status: string;
    balance: number;
    frozenBalance: number;
    concurrency: number;
    rpmLimit: number;
    notes: string;
    allowedGroups: number[];
    groupRates: Record<string, number>;
    createdAt: string;
    updatedAt: string;
    lastActiveAt: string | null;
    totalRecharged: number;
}

export interface BalanceHistoryItem {
    id: number;
    code: string;
    type: string;
    value: number;
    status: string;
    notes: string | null;
    usedAt: string | null;
    createdAt: string;
}

export interface PlatformQuota {
    platform: string;
    dailyLimitUsd: number | null;
    weeklyLimitUsd: number | null;
    monthlyLimitUsd: number | null;
    dailyUsageUsd: number;
    weeklyUsageUsd: number;
    monthlyUsageUsd: number;
    dailyWindowStart: string | null;
    weeklyWindowStart: string | null;
    monthlyWindowStart: string | null;
}

export interface APIKeyItem {
    id: number;
    key: string;
    name: string;
    status: string;
    groupId: number | null;
    createdAt: string;
    updatedAt: string;
    lastUsedAt: string | null;
    expiresAt: string | null;
}

export interface AuthIdentityItem {
    id: number;
    userId: number;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    verifiedAt: string | null;
    issuer: string | null;
    metadata: string;
    createdAt: string;
    updatedAt: string;
    channel: AuthIdentityChannelItem | null;
}

export interface AuthIdentityChannelItem {
    channel: string;
    channelAppId: string;
    channelSubject: string;
    metadata: string;
    createdAt: string;
    updatedAt: string;
}

export interface UserListFilter {
    page: number;
    pageSize: number;
    search?: string;
    status?: string;
    role?: string;
    groupName?: string;
    apiKeyGroupId?: number;
    sortBy?: string;
    sortOrder?: "asc" | "desc";
    includeSubscriptions?: boolean;
}

export interface UserListItem {
    id: number;
    email: string;
    username: string;
    role: string;
    status: string;
    balance: number;
    frozenBalance: number;
    concurrency: number;
    rpmLimit: number;
    notes: string;
    allowedGroups: number[];
    groupRates: Record<string, number>;
    createdAt: string;
    updatedAt: string;
    lastActiveAt: string | null;
}

export interface UserListResult {
    items: UserListItem[];
    total: number;
}

export interface ReplaceGroupResult {
    migratedKeys: number;
}const ALLOWED_PLATFORMS = ["openai", "anthropic", "gemini", "grok"];

export class D1AdminUserRoutesRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async findUserById(id: number, includeDeleted = false): Promise<UserDetail | null> {
        const where = includeDeleted ? "id = ?" : "id = ? AND deleted_at IS NULL";
        const row = await firstRow<{
            id: number; email: string; username: string; role: string; status: string;
            balance: number; frozen_balance: number; concurrency: number; rpm_limit: number;
            notes: string | null; created_at: string; updated_at: string; last_active_at: string | null;
        }>(this.#db, `SELECT * FROM users WHERE ${where} LIMIT 1`, [id]);
        if (row === null) return null;

        const groupRows = await allRows<{ group_id: number }>(
            this.#db, "SELECT group_id FROM user_allowed_groups WHERE user_id = ?", [id]
        );
        const allowedGroups = groupRows.map((r) => r.group_id);

        const rateRows = await allRows<{ group_id: number; rate_multiplier: number }>(
            this.#db, "SELECT group_id, rate_multiplier FROM user_group_rate_multipliers WHERE user_id = ?", [id]
        );
        const groupRates: Record<string, number> = {};
        for (const r of rateRows) groupRates[String(r.group_id)] = r.rate_multiplier;

        const rechargeRow = await firstRow<{ total: number }>(
            this.#db, "SELECT COALESCE(SUM(value), 0) as total FROM redeem_codes WHERE used_by = ? AND value > 0", [id]
        );

        return {
            id: row.id, email: row.email, username: row.username, role: row.role, status: row.status,
            balance: row.balance, frozenBalance: row.frozen_balance, concurrency: row.concurrency,
            rpmLimit: row.rpm_limit, notes: row.notes ?? "", allowedGroups, groupRates,
            createdAt: row.created_at, updatedAt: row.updated_at, lastActiveAt: row.last_active_at,
            totalRecharged: rechargeRow?.total ?? 0,
        };
    }

    async updateUserBalance(id: number, newBalance: number, code: string, notes: string, now: string): Promise<boolean> {
        const result = await runStatement(
            this.#db,
            `UPDATE users SET balance = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
            [newBalance, now, id]
        );
        if ((result.meta?.changes ?? 0) === 0) return false;
        await runStatement(
            this.#db,
            `INSERT INTO redeem_codes (code, type, value, status, notes, used_by, created_at) VALUES (?, 'admin_balance', ?, 'used', ?, ?, ?)`,
            [code, newBalance > 0 ? 0 : 0, notes, id, now]
        );
        return true;
    }

    async batchSetConcurrency(userIds: number[], value: number): Promise<number> {
        if (userIds.length === 0) return 0;
        const ps = userIds.map(() => "?").join(",");
        const result = await runStatement(
            this.#db,
            `UPDATE users SET concurrency = ?, updated_at = datetime('now') WHERE id IN (${ps}) AND deleted_at IS NULL`,
            [value, ...userIds]
        );
        return result.meta?.changes ?? 0;
    }

    async batchAddConcurrency(userIds: number[], delta: number): Promise<number> {
        if (userIds.length === 0) return 0;
        const ps = userIds.map(() => "?").join(",");
        const result = await runStatement(
            this.#db,
            `UPDATE users SET concurrency = MAX(0, concurrency + ?), updated_at = datetime('now') WHERE id IN (${ps}) AND deleted_at IS NULL`,
            [delta, ...userIds]
        );
        return result.meta?.changes ?? 0;
    }

    async getAllUserIds(): Promise<number[]> {
        const rows = await allRows<{ id: number }>(this.#db, "SELECT id FROM users WHERE deleted_at IS NULL", []);
        return rows.map((r) => r.id);
    }

    async listUsers(filter: UserListFilter): Promise<UserListResult> {
        const whereClauses: string[] = ["deleted_at IS NULL"];
        const params: D1Value[] = [];

        if (filter.search) {
            whereClauses.push("(email LIKE ? OR username LIKE ?)");
            const pattern = `%${filter.search}%`;
            params.push(pattern, pattern);
        }
        if (filter.status) {
            whereClauses.push("status = ?");
            params.push(filter.status);
        }
        if (filter.role) {
            whereClauses.push("role = ?");
            params.push(filter.role);
        }

        const where = whereClauses.length > 0 ? `WHERE ${whereClauses.join(" AND ")}` : "";

        const countRow = await firstRow<{ cnt: number }>(
            this.#db, `SELECT COUNT(*) as cnt FROM users ${where}`, params
        );
        const total = countRow?.cnt ?? 0;

        const allowedSortBy = new Set(["created_at", "updated_at", "email", "username", "role", "status", "balance", "last_active_at"]);
        const sortBy = filter.sortBy && allowedSortBy.has(filter.sortBy) ? filter.sortBy : "created_at";
        const sortOrder = filter.sortOrder === "asc" ? "ASC" : "DESC";
        const p = Math.max(1, filter.page);
        const ps = Math.min(100, Math.max(1, filter.pageSize));
        const offset = (p - 1) * ps;

        const rows = await allRows<{
            id: number; email: string; username: string; role: string; status: string;
            balance: number; frozen_balance: number; concurrency: number; rpm_limit: number;
            notes: string | null; created_at: string; updated_at: string; last_active_at: string | null;
        }>(this.#db, `SELECT id, email, username, role, status, balance, frozen_balance, concurrency, rpm_limit, notes, created_at, updated_at, last_active_at FROM users ${where} ORDER BY ${sortBy} ${sortOrder} LIMIT ? OFFSET ?`, [...params, ps, offset]);

        const items: UserListItem[] = [];
        for (const row of rows) {
            const groupRows = await allRows<{ group_id: number }>(
                this.#db, "SELECT group_id FROM user_allowed_groups WHERE user_id = ?", [row.id]
            );
            const allowedGroups = groupRows.map((r) => r.group_id);

            const rateRows = await allRows<{ group_id: number; rate_multiplier: number }>(
                this.#db, "SELECT group_id, rate_multiplier FROM user_group_rate_multipliers WHERE user_id = ?", [row.id]
            );
            const groupRates: Record<string, number> = {};
            for (const r of rateRows) groupRates[String(r.group_id)] = r.rate_multiplier;

            items.push({
                id: row.id, email: row.email, username: row.username, role: row.role, status: row.status,
                balance: row.balance, frozenBalance: row.frozen_balance, concurrency: row.concurrency,
                rpmLimit: row.rpm_limit, notes: row.notes ?? "", allowedGroups, groupRates,
                createdAt: row.created_at, updatedAt: row.updated_at, lastActiveAt: row.last_active_at,
            });
        }

        return { items, total };
    }

    async listBalanceHistory(userId: number, page: number, pageSize: number, type?: string): Promise<{ items: BalanceHistoryItem[]; total: number }> {
        const offset = (page - 1) * pageSize;
        const values: D1Value[] = [userId];
        let where = "used_by = ?";
        if (type) { where += " AND type = ?"; values.push(type); }

        const countRow = await firstRow<{ cnt: number }>(this.#db, `SELECT COUNT(*) as cnt FROM redeem_codes WHERE ${where}`, values);
        const total = countRow?.cnt ?? 0;

        const rows = await allRows<{
            id: number; code: string; type: string; value: number; status: string;
            notes: string | null; used_at: string | null; created_at: string;
        }>(this.#db, `SELECT * FROM redeem_codes WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...values, pageSize, offset]);

        return {
            items: rows.map((r) => ({
                id: r.id, code: r.code, type: r.type, value: r.value, status: r.status,
                notes: r.notes, usedAt: r.used_at, createdAt: r.created_at,
            })),
            total,
        };
    }

    async getAffiliateBalanceHistory(userId: number, page: number, pageSize: number): Promise<{ items: BalanceHistoryItem[]; total: number }> {
        const offset = (page - 1) * pageSize;
        const countRow = await firstRow<{ cnt: number }>(
            this.#db, "SELECT COUNT(*) as cnt FROM user_affiliate_ledger WHERE user_id = ? AND action = 'transfer'", [userId]
        );
        const total = countRow?.cnt ?? 0;

        const rows = await allRows<{
            id: number; amount: number; created_at: string;
        }>(this.#db, `SELECT id, amount, created_at FROM user_affiliate_ledger WHERE user_id = ? AND action = 'transfer' ORDER BY created_at DESC LIMIT ? OFFSET ?`, [userId, pageSize, offset]);

        return {
            items: rows.map((r) => ({
                id: r.id, code: `aff_transfer_${r.id}`, type: "affiliate_balance", value: r.amount, status: "used",
                notes: null, usedAt: r.created_at, createdAt: r.created_at,
            })),
            total,
        };
    }

    async getTotalRecharged(userId: number): Promise<number> {
        const row = await firstRow<{ total: number }>(this.#db, "SELECT COALESCE(SUM(value), 0) as total FROM redeem_codes WHERE used_by = ? AND value > 0", [userId]);
        return row?.total ?? 0;
    }

    async listPlatformQuotas(userId: number): Promise<PlatformQuota[]> {
        const rows = await allRows<{
            platform: string; daily_limit_usd: number | null; weekly_limit_usd: number | null; monthly_limit_usd: number | null;
            daily_usage_usd: number; weekly_usage_usd: number; monthly_usage_usd: number;
            daily_window_start: string | null; weekly_window_start: string | null; monthly_window_start: string | null;
        }>(this.#db, `SELECT * FROM user_platform_quotas WHERE user_id = ? AND deleted_at IS NULL`, [userId]);

        const now = new Date();
        return rows.map((r) => ({
            platform: r.platform,
            dailyLimitUsd: r.daily_limit_usd, weeklyLimitUsd: r.weekly_limit_usd, monthlyLimitUsd: r.monthly_limit_usd,
            dailyUsageUsd: (r.daily_window_start && now.getTime() > new Date(r.daily_window_start + "+00:00").getTime() + 86400000) ? 0 : r.daily_usage_usd,
            weeklyUsageUsd: r.weekly_usage_usd, monthlyUsageUsd: r.monthly_usage_usd,
            dailyWindowStart: r.daily_window_start, weeklyWindowStart: r.weekly_window_start, monthlyWindowStart: r.monthly_window_start,
        }));
    }

    async upsertPlatformQuotas(userId: number, quotas: { platform: string; dailyLimitUsd: number | null; weeklyLimitUsd: number | null; monthlyLimitUsd: number | null }[]): Promise<void> {
        const now = new Date().toISOString();
        for (const q of quotas) {
            const existing = await firstRow<{ id: number }>(
                this.#db,
                "SELECT id FROM user_platform_quotas WHERE user_id = ? AND platform = ? AND deleted_at IS NULL LIMIT 1",
                [userId, q.platform]
            );
            if (existing !== null) {
                await runStatement(
                    this.#db,
                    "UPDATE user_platform_quotas SET daily_limit_usd = ?, weekly_limit_usd = ?, monthly_limit_usd = ?, updated_at = ? WHERE id = ?",
                    [q.dailyLimitUsd, q.weeklyLimitUsd, q.monthlyLimitUsd, now, existing.id]
                );
            } else {
                await runStatement(
                    this.#db,
                    `INSERT INTO user_platform_quotas (user_id, platform, daily_limit_usd, weekly_limit_usd, monthly_limit_usd, daily_usage_usd, weekly_usage_usd, monthly_usage_usd, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?, ?)`,
                    [userId, q.platform, q.dailyLimitUsd, q.weeklyLimitUsd, q.monthlyLimitUsd, now, now]
                );
            }
        }
    }

    async resetPlatformQuotaWindow(userId: number, platform: string, window: string): Promise<boolean> {
        const now = new Date().toISOString();
        const col = `${window}_usage_usd`;
        const winCol = `${window}_window_start`;
        const result = await runStatement(
            this.#db,
            `UPDATE user_platform_quotas SET ${col} = 0, ${winCol} = ?, updated_at = ? WHERE user_id = ? AND platform = ? AND deleted_at IS NULL`,
            [now, now, userId, platform]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async createUser(input: {
        email: string; passwordHash: string; username: string; notes: string; role: string;
        balance: number; concurrency: number; rpmLimit: number; allowedGroups: number[];
    }): Promise<number> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `INSERT INTO users (email, password_hash, username, notes, role, balance, concurrency, rpm_limit, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
            [input.email, input.passwordHash, input.username, input.notes, input.role,
             input.balance, input.concurrency, input.rpmLimit, now, now]
        );
        const userId = result.meta?.last_row_id as number ?? 0;
        if (userId <= 0) throw new Error("failed to create user");

        for (const gid of input.allowedGroups) {
            await runStatement(
                this.#db,
                "INSERT INTO user_allowed_groups (user_id, group_id, created_at) VALUES (?, ?, ?)",
                [userId, gid, now]
            );
        }
        return userId;
    }

    async updateUser(id: number, input: {
        email?: string; passwordHash?: string; username?: string; notes?: string;
        role?: string; status?: string; balance?: number; concurrency?: number;
        rpmLimit?: number; allowedGroups?: number[]; groupRates?: Record<string, number | null>;
    }): Promise<boolean> {
        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.email !== undefined) { sets.push("email = ?"); values.push(input.email); }
        if (input.passwordHash !== undefined) { sets.push("password_hash = ?"); values.push(input.passwordHash); }
        if (input.username !== undefined) { sets.push("username = ?"); values.push(input.username); }
        if (input.notes !== undefined) { sets.push("notes = ?"); values.push(input.notes); }
        if (input.role !== undefined) { sets.push("role = ?"); values.push(input.role); }
        if (input.status !== undefined) { sets.push("status = ?"); values.push(input.status); }
        if (input.balance !== undefined) { sets.push("balance = ?"); values.push(input.balance); }
        if (input.concurrency !== undefined) { sets.push("concurrency = ?"); values.push(input.concurrency); }
        if (input.rpmLimit !== undefined) { sets.push("rpm_limit = ?"); values.push(input.rpmLimit); }

        values.push(id);
        const result = await runStatement(
            this.#db,
            `UPDATE users SET ${sets.join(", ")} WHERE id = ? AND deleted_at IS NULL`,
            values
        );
        const changed = (result.meta?.changes ?? 0) > 0;

        if (changed && input.allowedGroups !== undefined) {
            await this.#db.prepare("DELETE FROM user_allowed_groups WHERE user_id = ?").bind(id).run();
            for (const gid of input.allowedGroups) {
                await runStatement(
                    this.#db,
                    "INSERT INTO user_allowed_groups (user_id, group_id, created_at) VALUES (?, ?, ?)",
                    [id, gid, now]
                );
            }
        }

        if (changed && input.groupRates !== undefined) {
            for (const [gid, rate] of Object.entries(input.groupRates)) {
                const groupId = Number(gid);
                if (rate === null) {
                    await runStatement(
                        this.#db,
                        "DELETE FROM user_group_rate_multipliers WHERE user_id = ? AND group_id = ?",
                        [id, groupId]
                    );
                } else {
                    const existing = await firstRow<{ id: number }>(
                        this.#db,
                        "SELECT id FROM user_group_rate_multipliers WHERE user_id = ? AND group_id = ? LIMIT 1",
                        [id, groupId]
                    );
                    if (existing !== null) {
                        await runStatement(
                            this.#db,
                            "UPDATE user_group_rate_multipliers SET rate_multiplier = ?, updated_at = ? WHERE id = ?",
                            [rate, now, existing.id]
                        );
                    } else {
                        await runStatement(
                            this.#db,
                            "INSERT INTO user_group_rate_multipliers (user_id, group_id, rate_multiplier, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                            [id, groupId, rate, now, now]
                        );
                    }
                }
            }
        }

        return changed;
    }

    async deleteUser(id: number): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            "UPDATE users SET deleted_at = ?, updated_at = ?, status = 'disabled' WHERE id = ? AND deleted_at IS NULL",
            [now, now, id]
        );
        if ((result.meta?.changes ?? 0) === 0) return false;
        await runStatement(
            this.#db,
            "UPDATE api_keys SET deleted_at = ?, status = 'disabled' WHERE user_id = ? AND deleted_at IS NULL",
            [now, id]
        );
        return true;
    }

    async bindAuthIdentity(userId: number, input: {
        providerType: string; providerKey: string; providerSubject: string;
        issuer: string | null; metadata: Record<string, unknown>;
        channel: { channel: string; channelAppId: string; channelSubject: string; metadata: Record<string, unknown> } | null;
    }): Promise<AuthIdentityItem> {
        const now = new Date().toISOString();
        const metaStr = JSON.stringify(input.metadata ?? {});
        const result = await runStatement(
            this.#db,
            `INSERT INTO auth_identities (user_id, provider_type, provider_key, provider_subject, issuer, metadata, verified_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [userId, input.providerType, input.providerKey, input.providerSubject,
             input.issuer, metaStr, now, now, now]
        );
        const identityId = result.meta?.last_row_id as number ?? 0;

        let channel: AuthIdentityChannelItem | null = null;
        if (input.channel !== null) {
            const chMetaStr = JSON.stringify(input.channel.metadata ?? {});
            await runStatement(
                this.#db,
                `INSERT INTO auth_identity_channels (identity_id, provider_type, provider_key, channel, channel_app_id, channel_subject, metadata, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [identityId, input.providerType, input.providerKey, input.channel.channel,
                 input.channel.channelAppId, input.channel.channelSubject, chMetaStr, now, now]
            );
            channel = {
                channel: input.channel.channel, channelAppId: input.channel.channelAppId,
                channelSubject: input.channel.channelSubject, metadata: chMetaStr,
                createdAt: now, updatedAt: now,
            };
        }

        return {
            id: identityId, userId, providerType: input.providerType,
            providerKey: input.providerKey, providerSubject: input.providerSubject,
            verifiedAt: now, issuer: input.issuer, metadata: metaStr,
            createdAt: now, updatedAt: now, channel,
        };
    }

    async listUserAPIKeys(userId: number, page: number, pageSize: number, sortBy: string, sortOrder: string): Promise<{ items: APIKeyItem[]; total: number }> {
        const offset = (page - 1) * pageSize;
        const allowedSortBy = ["created_at", "updated_at", "name", "status", "last_used_at"].includes(sortBy) ? sortBy : "created_at";
        const order = sortOrder === "asc" ? "ASC" : "DESC";
        const countRow = await firstRow<{ cnt: number }>(
            this.#db, "SELECT COUNT(*) as cnt FROM api_keys WHERE user_id = ? AND deleted_at IS NULL", [userId]
        );
        const total = countRow?.cnt ?? 0;
        const rows = await allRows<{
            id: number; key: string; name: string; status: string; group_id: number | null;
            created_at: string; updated_at: string; last_used_at: string | null; expires_at: string | null;
        }>(
            this.#db,
            `SELECT id, key, name, status, group_id, created_at, updated_at, last_used_at, expires_at
             FROM api_keys WHERE user_id = ? AND deleted_at IS NULL ORDER BY ${allowedSortBy} ${order} LIMIT ? OFFSET ?`,
            [userId, pageSize, offset]
        );
        return {
            items: rows.map((r) => ({
                id: r.id, key: r.key, name: r.name, status: r.status, groupId: r.group_id,
                createdAt: r.created_at, updatedAt: r.updated_at, lastUsedAt: r.last_used_at, expiresAt: r.expires_at,
            })),
            total,
        };
    }

    async replaceUserGroup(userId: number, oldGroupId: number, newGroupId: number): Promise<number> {
        const now = new Date().toISOString();
        const stmts: D1BatchStatement[] = [
            { sql: "INSERT OR IGNORE INTO user_allowed_groups (user_id, group_id, created_at) VALUES (?, ?, ?)", values: [userId, newGroupId, now] },
            { sql: "UPDATE api_keys SET group_id = ?, updated_at = ? WHERE user_id = ? AND group_id = ? AND deleted_at IS NULL", values: [newGroupId, now, userId, oldGroupId] },
            { sql: "DELETE FROM user_allowed_groups WHERE user_id = ? AND group_id = ?", values: [userId, oldGroupId] },
        ];
        const results = await runBatchTransaction(this.#db, stmts);
        const migrated = (results[1]?.meta?.changes as number) ?? 0;
        return migrated;
    }

    async isLastAdmin(userId: number): Promise<boolean> {
        const row = await firstRow<{ cnt: number }>(
            this.#db,
            "SELECT COUNT(*) as cnt FROM users WHERE role = 'admin' AND deleted_at IS NULL",
            []
        );
        const totalAdmins = row?.cnt ?? 0;
        if (totalAdmins > 1) return false;
        const self = await firstRow<{ role: string }>(
            this.#db, "SELECT role FROM users WHERE id = ? AND deleted_at IS NULL", [userId]
        );
        return self?.role === "admin";
    }

    async findGroupById(groupId: number): Promise<{ id: number; status: string; isExclusive: number } | null> {
        const row = await firstRow<{ id: number; status: string; is_exclusive: number }>(
            this.#db, "SELECT id, status, is_exclusive FROM groups WHERE id = ? AND deleted_at IS NULL LIMIT 1", [groupId]
        );
        if (row === null) return null;
        return { id: row.id, status: row.status, isExclusive: row.is_exclusive };
    }
}
