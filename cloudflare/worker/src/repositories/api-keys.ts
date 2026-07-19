import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement, runBatchTransaction, requireSuccess } from "./d1.ts";

export interface ApiKeyRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    deletedAt: string | null;
    key: string;
    name: string;
    status: string;
    lastUsedAt: string | null;
    ipWhitelist: string[];
    ipBlacklist: string[];
    quota: number;
    quotaUsed: number;
    expiresAt: string | null;
    rateLimit5h: number;
    rateLimit1d: number;
    rateLimit7d: number;
    usage5h: number;
    usage1d: number;
    usage7d: number;
    window5hStart: string | null;
    window1dStart: string | null;
    window7dStart: string | null;
    groupId: number | null;
    userId: number;
}

interface ApiKeyRow {
    id: number;
    created_at: string;
    updated_at: string;
    deleted_at: string | null;
    key: string;
    name: string;
    status: string;
    last_used_at: string | null;
    ip_whitelist: string | null;
    ip_blacklist: string | null;
    quota: number;
    quota_used: number;
    expires_at: string | null;
    rate_limit_5h: number;
    rate_limit_1d: number;
    rate_limit_7d: number;
    usage_5h: number;
    usage_1d: number;
    usage_7d: number;
    window_5h_start: string | null;
    window_1d_start: string | null;
    window_7d_start: string | null;
    group_id: number | null;
    user_id: number;
}

function parseJsonArray(raw: string | null): string[] {
    if (raw === null || raw === undefined) return [];
    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
    } catch {
        return [];
    }
}

function rowToRecord(row: ApiKeyRow): ApiKeyRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        deletedAt: row.deleted_at,
        key: row.key,
        name: row.name,
        status: row.status,
        lastUsedAt: row.last_used_at,
        ipWhitelist: parseJsonArray(row.ip_whitelist),
        ipBlacklist: parseJsonArray(row.ip_blacklist),
        quota: row.quota,
        quotaUsed: row.quota_used,
        expiresAt: row.expires_at,
        rateLimit5h: row.rate_limit_5h,
        rateLimit1d: row.rate_limit_1d,
        rateLimit7d: row.rate_limit_7d,
        usage5h: row.usage_5h,
        usage1d: row.usage_1d,
        usage7d: row.usage_7d,
        window5hStart: row.window_5h_start,
        window1dStart: row.window_1d_start,
        window7dStart: row.window_7d_start,
        groupId: row.group_id,
        userId: row.user_id
    };
}

export interface CreateApiKeyInput {
    key: string;
    name: string;
    userId: number;
    groupId?: number | null;
    ipWhitelist?: string[];
    ipBlacklist?: string[];
    quota?: number;
    expiresAt?: string | null;
    rateLimit5h?: number;
    rateLimit1d?: number;
    rateLimit7d?: number;
}

export interface UpdateApiKeyInput {
    name?: string;
    groupId?: number | null;
    status?: string;
    ipWhitelist?: string[];
    ipBlacklist?: string[];
    quota?: number;
    expiresAt?: string | null;
    rateLimit5h?: number;
    rateLimit1d?: number;
    rateLimit7d?: number;
    resetQuota?: boolean;
    resetRateLimits?: boolean;
}

export interface ListApiKeysOptions {
    userId: number;
    page?: number;
    pageSize?: number;
    search?: string;
    status?: string;
    groupId?: number;
    orderBy?: string;
    orderDir?: "asc" | "desc";
}

export class D1ApiKeyRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async findById(id: number, userId?: number): Promise<ApiKeyRecord | null> {
        if (!Number.isSafeInteger(id) || id <= 0) return null;
        const where = userId !== undefined
            ? "id = ? AND user_id = ? AND deleted_at IS NULL"
            : "id = ? AND deleted_at IS NULL";
        const values: D1Value[] = userId !== undefined ? [id, userId] : [id];
        const row = await firstRow<ApiKeyRow>(this.#db, `SELECT * FROM api_keys WHERE ${where}`, values);
        return row ? rowToRecord(row) : null;
    }

    async findByKey(keyValue: string): Promise<ApiKeyRecord | null> {
        const key = keyValue.trim();
        if (key.length === 0) return null;
        const row = await firstRow<ApiKeyRow>(
            this.#db,
            "SELECT * FROM api_keys WHERE key = ? AND deleted_at IS NULL",
            [key]
        );
        return row === null ? null : rowToRecord(row);
    }

    async list(options: ListApiKeysOptions): Promise<{ items: ApiKeyRecord[]; total: number }> {
        const { userId, page = 1, pageSize = 20, search, status, groupId, orderBy = "id", orderDir = "desc" } = options;
        const conditions: string[] = ["user_id = ?", "deleted_at IS NULL"];
        const values: D1Value[] = [userId];

        if (search !== undefined && search.trim() !== "") {
            conditions.push("(name LIKE ? OR key LIKE ?)");
            const pattern = `%${search.trim()}%`;
            values.push(pattern, pattern);
        }

        if (status !== undefined && status.trim() !== "") {
            conditions.push("status = ?");
            values.push(status.trim());
        }

        if (groupId !== undefined && groupId !== null) {
            conditions.push("group_id = ?");
            values.push(groupId);
        }

        const where = conditions.join(" AND ");
        const allowedOrderColumns = new Set(["id", "name", "status", "created_at", "updated_at", "last_used_at", "quota_used"]);
        const safeOrder = allowedOrderColumns.has(orderBy) ? orderBy : "id";
        const safeDir = orderDir === "asc" ? "ASC" : "DESC";

        const countRow = await firstRow<{ count: number }>(
            this.#db,
            `SELECT COUNT(*) AS count FROM api_keys WHERE ${where}`,
            values
        );
        const total = countRow?.count ?? 0;

        const offset = Math.max(0, (page - 1) * pageSize);
        const rows = await allRows<ApiKeyRow>(
            this.#db,
            `SELECT * FROM api_keys WHERE ${where} ORDER BY ${safeOrder} ${safeDir} LIMIT ? OFFSET ?`,
            [...values, pageSize, offset]
        );

        return { items: rows.map(rowToRecord), total };
    }

    async create(input: CreateApiKeyInput): Promise<ApiKeyRecord> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `INSERT INTO api_keys (
                created_at, updated_at, key, name, status, user_id, group_id,
                ip_whitelist, ip_blacklist, quota, quota_used, expires_at,
                rate_limit_5h, rate_limit_1d, rate_limit_7d,
                usage_5h, usage_1d, usage_7d
            ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 0, 0, 0)`,
            [
                now, now,
                input.key,
                input.name,
                input.userId,
                input.groupId ?? null,
                JSON.stringify(input.ipWhitelist ?? []),
                JSON.stringify(input.ipBlacklist ?? []),
                input.quota ?? 0,
                input.expiresAt ?? null,
                input.rateLimit5h ?? 0,
                input.rateLimit1d ?? 0,
                input.rateLimit7d ?? 0
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findById(id))!;
    }

    async update(id: number, userId: number, input: UpdateApiKeyInput): Promise<ApiKeyRecord | null> {
        const existing = await this.findById(id, userId);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.name !== undefined) {
            sets.push("name = ?");
            values.push(input.name);
        }

        if (input.groupId !== undefined) {
            sets.push("group_id = ?");
            values.push(input.groupId);
        }

        if (input.status !== undefined) {
            sets.push("status = ?");
            values.push(input.status);
        }

        if (input.ipWhitelist !== undefined) {
            sets.push("ip_whitelist = ?");
            values.push(JSON.stringify(input.ipWhitelist));
        }

        if (input.ipBlacklist !== undefined) {
            sets.push("ip_blacklist = ?");
            values.push(JSON.stringify(input.ipBlacklist));
        }

        if (input.quota !== undefined) {
            sets.push("quota = ?");
            values.push(input.quota);
        }

        if (input.expiresAt !== undefined) {
            sets.push("expires_at = ?");
            values.push(input.expiresAt);
        }

        if (input.rateLimit5h !== undefined) {
            sets.push("rate_limit_5h = ?");
            values.push(input.rateLimit5h);
        }

        if (input.rateLimit1d !== undefined) {
            sets.push("rate_limit_1d = ?");
            values.push(input.rateLimit1d);
        }

        if (input.rateLimit7d !== undefined) {
            sets.push("rate_limit_7d = ?");
            values.push(input.rateLimit7d);
        }

        if (input.resetQuota) {
            sets.push("quota_used = 0");
        }

        if (input.resetRateLimits) {
            sets.push("usage_5h = 0", "usage_1d = 0", "usage_7d = 0");
            sets.push("window_5h_start = NULL", "window_1d_start = NULL", "window_7d_start = NULL");
        }

        if (sets.length === 1) return existing;

        values.push(id, userId);
        await runStatement(
            this.#db,
            `UPDATE api_keys SET ${sets.join(", ")} WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number, userId: number): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `UPDATE api_keys SET deleted_at = ?, updated_at = ?, status = 'disabled'
             WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
            [now, now, id, userId]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async deleteWithAudit(id: number, userId: number): Promise<boolean> {
        const existing = await this.findById(id, userId);
        if (existing === null) return false;

        const now = new Date().toISOString();
        await runBatchTransaction(this.#db, [
            {
                sql: `INSERT INTO deleted_api_key_audits (key, api_key_id, user_id, key_name, deleted_at, created_at)
                      VALUES (?, ?, ?, ?, ?, ?)`,
                values: [existing.key, existing.id, userId, existing.name, now, now]
            },
            {
                sql: `UPDATE api_keys SET deleted_at = ?, updated_at = ?, status = 'disabled'
                      WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
                values: [now, now, id, userId]
            }
        ]);

        return true;
    }

    async touchLastUsed(id: number, now: string): Promise<void> {
        await runStatement(
            this.#db,
            `UPDATE api_keys SET last_used_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
            [now, now, id]
        );
    }

    async countByUserId(userId: number): Promise<number> {
        const row = await firstRow<{ count: number }>(
            this.#db,
            "SELECT COUNT(*) AS count FROM api_keys WHERE user_id = ? AND deleted_at IS NULL",
            [userId]
        );
        return row?.count ?? 0;
    }

    async searchByUserId(userId: number, query: string, limit = 30): Promise<{ id: number; name: string; userId: number }[]> {
        const pattern = `%${query.trim()}%`;
        const rows = await allRows<{ id: number; name: string; user_id: number }>(
            this.#db,
            `SELECT id, name, user_id FROM api_keys
             WHERE user_id = ? AND deleted_at IS NULL AND (name LIKE ? OR key LIKE ?)
             LIMIT ?`,
            [userId, pattern, pattern, limit]
        );
        return rows.map((row) => ({ id: row.id, name: row.name, userId: row.user_id }));
    }
}
