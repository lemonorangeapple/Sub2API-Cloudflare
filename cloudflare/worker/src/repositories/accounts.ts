import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface AccountRecord {
    id: number;
    name: string;
    notes: string;
    platform: string;
    type: string;
    credentials: string;
    extra: string;
    proxyFallbackOriginId: number | null;
    concurrency: number;
    loadFactor: number | null;
    priority: number;
    rateMultiplier: number;
    status: string;
    errorMessage: string | null;
    lastUsedAt: string | null;
    expiresAt: string | null;
    autoPauseOnExpired: boolean;
    schedulable: boolean;
    rateLimitedAt: string | null;
    rateLimitResetAt: string | null;
    overloadUntil: string | null;
    tempUnschedulableUntil: string | null;
    tempUnschedulableReason: string | null;
    sessionWindowStart: string | null;
    sessionWindowEnd: string | null;
    sessionWindowStatus: string | null;
    quotaDimension: string;
    proxyId: number | null;
    parentAccountId: number | null;
    createdAt: string;
    updatedAt: string;
    deletedAt: string | null;
}

export interface AccountGroupRecord {
    accountId: number;
    groupId: number;
    priority: number;
    createdAt: string;
}

export interface MixedChannelRiskRecord {
    groupId: number;
    groupName: string;
    currentPlatform: string;
    otherPlatform: string;
}

export interface AccountWindowStatsRecord {
    requests: number;
    tokens: number;
    standardCost: number;
    accountCost: number;
    userCost: number;
}

export interface AccountDailyStatsRecord extends AccountWindowStatsRecord {
    date: string;
    durationMs: number;
}

export interface AccountDimensionStatsRecord extends AccountWindowStatsRecord {
    key: string;
}

interface AccountRow {
    id: number;
    name: string;
    notes: string;
    platform: string;
    type: string;
    credentials: string;
    extra: string;
    proxy_fallback_origin_id: number | null;
    concurrency: number;
    load_factor: number | null;
    priority: number;
    rate_multiplier: number;
    status: string;
    error_message: string | null;
    last_used_at: string | null;
    expires_at: string | null;
    auto_pause_on_expired: number;
    schedulable: number;
    rate_limited_at: string | null;
    rate_limit_reset_at: string | null;
    overload_until: string | null;
    temp_unschedulable_until: string | null;
    temp_unschedulable_reason: string | null;
    session_window_start: string | null;
    session_window_end: string | null;
    session_window_status: string | null;
    quota_dimension: string;
    proxy_id: number | null;
    parent_account_id: number | null;
    created_at: string;
    updated_at: string;
    deleted_at: string | null;
}

interface AccountGroupRow {
    account_id: number;
    group_id: number;
    priority: number;
    created_at: string;
}

function rowToRecord(row: AccountRow): AccountRecord {
    return {
        id: row.id,
        name: row.name,
        notes: row.notes,
        platform: row.platform,
        type: row.type,
        credentials: row.credentials,
        extra: row.extra,
        proxyFallbackOriginId: row.proxy_fallback_origin_id,
        concurrency: row.concurrency,
        loadFactor: row.load_factor,
        priority: row.priority,
        rateMultiplier: row.rate_multiplier,
        status: row.status,
        errorMessage: row.error_message,
        lastUsedAt: row.last_used_at,
        expiresAt: row.expires_at,
        autoPauseOnExpired: row.auto_pause_on_expired !== 0,
        schedulable: row.schedulable !== 0,
        rateLimitedAt: row.rate_limited_at,
        rateLimitResetAt: row.rate_limit_reset_at,
        overloadUntil: row.overload_until,
        tempUnschedulableUntil: row.temp_unschedulable_until,
        tempUnschedulableReason: row.temp_unschedulable_reason,
        sessionWindowStart: row.session_window_start,
        sessionWindowEnd: row.session_window_end,
        sessionWindowStatus: row.session_window_status,
        quotaDimension: row.quota_dimension,
        proxyId: row.proxy_id,
        parentAccountId: row.parent_account_id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        deletedAt: row.deleted_at
    };
}

function groupRowToRecord(row: AccountGroupRow): AccountGroupRecord {
    return {
        accountId: row.account_id,
        groupId: row.group_id,
        priority: row.priority,
        createdAt: row.created_at
    };
}

function nowISO(): string {
    return new Date().toISOString();
}

export function buildAccountInsertValues(input: Record<string, D1Value>, ts: string): D1Value[] {
    return [
        input.name ?? "",
        input.notes ?? "",
        input.platform ?? "openai",
        input.type ?? "apikey",
        input.credentials ?? "{}",
        input.extra ?? "{}",
        input.proxy_fallback_origin_id ?? null,
        input.concurrency ?? 3,
        input.load_factor ?? null,
        input.priority ?? 50,
        input.rate_multiplier ?? 1.0,
        input.status ?? "active",
        input.error_message ?? null,
        input.last_used_at ?? null,
        input.expires_at ?? null,
        input.auto_pause_on_expired ?? 1,
        input.schedulable ?? 1,
        input.rate_limited_at ?? null,
        input.rate_limit_reset_at ?? null,
        input.overload_until ?? null,
        input.temp_unschedulable_until ?? null,
        input.temp_unschedulable_reason ?? null,
        input.session_window_start ?? null,
        input.session_window_end ?? null,
        input.session_window_status ?? null,
        input.quota_dimension ?? "global",
        input.proxy_id ?? null,
        input.parent_account_id ?? null,
        ts,
        ts
    ];
}

const ACCOUNT_INSERT_COLS = `(
    name, notes, platform, type,
    credentials, extra, proxy_fallback_origin_id,
    concurrency, load_factor, priority, rate_multiplier,
    status, error_message, last_used_at, expires_at,
    auto_pause_on_expired, schedulable,
    rate_limited_at, rate_limit_reset_at,
    overload_until, temp_unschedulable_until, temp_unschedulable_reason,
    session_window_start, session_window_end, session_window_status,
    quota_dimension,
    proxy_id, parent_account_id,
    created_at, updated_at
)`;

const ACCOUNT_INSERT_VALS = `VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

export class D1AccountRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: Record<string, D1Value>): Promise<AccountRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO accounts ${ACCOUNT_INSERT_COLS} ${ACCOUNT_INSERT_VALS} RETURNING *`;
        const vals = buildAccountInsertValues(input, ts);
        const row = await firstRow<AccountRow>(this.db, sql, vals);
        return rowToRecord(row!);
    }

    async batchCreate(inputs: Record<string, D1Value>[]): Promise<AccountRecord[]> {
        const ts = nowISO();
        const results: AccountRecord[] = [];
        for (const input of inputs) {
            const sql = `INSERT INTO accounts ${ACCOUNT_INSERT_COLS} ${ACCOUNT_INSERT_VALS} RETURNING *`;
            const vals = buildAccountInsertValues(input, ts);
            const row = await firstRow<AccountRow>(this.db, sql, vals);
            results.push(rowToRecord(row!));
        }
        return results;
    }

    async getById(id: number): Promise<AccountRecord | null> {
        const row = await firstRow<AccountRow>(this.db, `SELECT * FROM accounts WHERE id = ? AND deleted_at IS NULL`, [id]);
        return row ? rowToRecord(row) : null;
    }

    async getByIdRaw(id: number): Promise<AccountRow | null> {
        return firstRow<AccountRow>(this.db, `SELECT * FROM accounts WHERE id = ?`, [id]);
    }

    async update(id: number, input: Record<string, D1Value>): Promise<AccountRecord | null> {
        const ts = nowISO();
        const setClauses: string[] = [];
        const values: D1Value[] = [];
        for (const [key, value] of Object.entries(input)) {
            setClauses.push(`${key} = ?`);
            values.push(value ?? null);
        }
        setClauses.push("updated_at = ?");
        values.push(ts);
        values.push(id);
        const sql = `UPDATE accounts SET ${setClauses.join(", ")} WHERE id = ? AND deleted_at IS NULL RETURNING *`;
        const row = await firstRow<AccountRow>(this.db, sql, values);
        return row ? rowToRecord(row) : null;
    }

    async delete(id: number): Promise<boolean> {
        const ts = nowISO();
        const result = await runStatement(this.db, `UPDATE accounts SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, [ts, ts, id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }

    async existsByName(name: string): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM accounts WHERE name = ? AND deleted_at IS NULL`, [name]);
        return row !== null && row.c > 0;
    }

    async list(params: {
        page: number; pageSize: number; platform?: string; type?: string; status?: string;
        search?: string; groupId?: number; groupUngrouped?: boolean; privacyMode?: string;
        sortBy?: string; sortOrder?: string
    }): Promise<{ items: AccountRecord[]; total: number }> {
        const where: string[] = ["deleted_at IS NULL"];
        const values: D1Value[] = [];

        if (params.platform) { where.push("platform = ?"); values.push(params.platform); }
        if (params.type) { where.push("type = ?"); values.push(params.type); }
        if (params.status) { where.push("status = ?"); values.push(params.status); }
        if (params.search) { where.push("name LIKE ?"); values.push(`%${params.search}%`); }
        if (params.groupId !== undefined) {
            if (params.groupUngrouped) {
                where.push(`id NOT IN (SELECT account_id FROM account_groups WHERE group_id = ?)`);
                values.push(params.groupId);
            } else {
                where.push(`id IN (SELECT account_id FROM account_groups WHERE group_id = ?)`);
                values.push(params.groupId);
            }
        }

        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
        const sortBy = params.sortBy ?? "name";
        const sortOrder = params.sortOrder ?? "asc";
        const safeSortBy = ["name", "created_at", "updated_at", "platform", "type", "status", "priority", "rate_multiplier", "concurrency"].includes(sortBy) ? sortBy : "name";
        const safeSortOrder = sortOrder === "desc" ? "DESC" : "ASC";

        const countRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM accounts ${whereClause}`, values);
        const total = countRow?.c ?? 0;

        const offset = (params.page - 1) * params.pageSize;
        const rows = await allRows<AccountRow>(this.db, `SELECT * FROM accounts ${whereClause} ORDER BY ${safeSortBy} ${safeSortOrder} LIMIT ? OFFSET ?`, [...values, params.pageSize, offset]);

        return { items: rows.map(rowToRecord), total };
    }

    async listAll(): Promise<AccountRecord[]> {
        const rows = await allRows<AccountRow>(this.db, `SELECT * FROM accounts WHERE deleted_at IS NULL ORDER BY name ASC`);
        return rows.map(rowToRecord);
    }

    async setGroups(accountId: number, groupIds: number[]): Promise<void> {
        const ts = nowISO();
        await runStatement(this.db, `DELETE FROM account_groups WHERE account_id = ?`, [accountId]);
        for (const groupId of groupIds) {
            await runStatement(this.db, `INSERT INTO account_groups (account_id, group_id, priority, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(account_id, group_id) DO UPDATE SET priority = ?`, [accountId, groupId, 50, ts, 50]);
        }
    }

    async getGroups(accountId: number): Promise<AccountGroupRecord[]> {
        const rows = await allRows<AccountGroupRow>(this.db, `
            SELECT ag.account_id, ag.group_id, ag.priority, ag.created_at, g.name as group_name
            FROM account_groups ag
            JOIN groups g ON g.id = ag.group_id AND g.deleted_at IS NULL
            WHERE ag.account_id = ?
            ORDER BY ag.priority ASC
        `, [accountId]);
        return rows.map(groupRowToRecord);
    }

    async batchUpdateCredentials(accountIds: number[], credentials: string, extra?: string): Promise<number> {
        const ts = nowISO();
        let updated = 0;
        for (const accountId of accountIds) {
            const updates: Record<string, D1Value> = { credentials };
            if (extra !== undefined) updates.extra = extra;
            const result = await runStatement(this.db, `UPDATE accounts SET credentials = ?, extra = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, [credentials, extra ?? "{}", ts, accountId]);
            if (result.success && (result.meta?.changes ?? 0) > 0) updated++;
        }
        return updated;
    }

    async updateStatusFields(
        id: number,
        fields: Record<string, D1Value>
    ): Promise<AccountRecord | null> {
        if (Object.keys(fields).length === 0) return this.getById(id);
        return this.update(id, fields);
    }

    async clearRateLimit(id: number): Promise<AccountRecord | null> {
        return this.update(id, {
            rate_limited_at: null,
            rate_limit_reset_at: null,
            overload_until: null
        });
    }

    async resetQuota(id: number): Promise<AccountRecord | null> {
        return this.update(id, {
            rate_limited_at: null,
            rate_limit_reset_at: null,
            overload_until: null,
            temp_unschedulable_until: null,
            temp_unschedulable_reason: null,
            error_message: null
        });
    }

    async setSchedulable(id: number, schedulable: boolean): Promise<AccountRecord | null> {
        return this.update(id, { schedulable: schedulable ? 1 : 0 });
    }

    async setTempUnschedulable(id: number, until: string | null, reason: string | null): Promise<AccountRecord | null> {
        return this.update(id, {
            temp_unschedulable_until: until,
            temp_unschedulable_reason: reason
        });
    }

    async checkMixedChannelRisk(params: {
        accountId?: number;
        platform: string;
        groupIds: number[];
    }): Promise<MixedChannelRiskRecord | null> {
        if (params.groupIds.length === 0) return null;

        const placeholders = params.groupIds.map(() => "?").join(", ");
        const values: D1Value[] = [...params.groupIds, params.platform];
        const accountClause = params.accountId !== undefined ? " AND a.id != ?" : "";
        if (params.accountId !== undefined) values.push(params.accountId);

        const row = await firstRow<{ group_id: number; group_name: string; other_platform: string }>(
            this.db,
            `SELECT ag.group_id, g.name AS group_name, a.platform AS other_platform
             FROM account_groups ag
             JOIN groups g ON g.id = ag.group_id AND g.deleted_at IS NULL
             JOIN accounts a ON a.id = ag.account_id AND a.deleted_at IS NULL
             WHERE ag.group_id IN (${placeholders})
               AND a.platform != ?${accountClause}
             LIMIT 1`,
            values
        );

        return row ? {
            groupId: row.group_id,
            groupName: row.group_name,
            currentPlatform: params.platform,
            otherPlatform: row.other_platform
        } : null;
    }

    async getWindowStats(accountId: number, startAt: string): Promise<AccountWindowStatsRecord> {
        const row = await firstRow<{
            requests: number;
            tokens: number;
            standard_cost: number;
            account_cost: number;
            user_cost: number;
        }>(this.db, `
            SELECT
                COUNT(*) AS requests,
                COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens), 0) AS tokens,
                COALESCE(SUM(total_cost), 0) AS standard_cost,
                COALESCE(SUM(COALESCE(account_stats_cost, total_cost * COALESCE(account_rate_multiplier, 1))), 0) AS account_cost,
                COALESCE(SUM(actual_cost), 0) AS user_cost
            FROM usage_logs
            WHERE account_id = ? AND created_at >= ?
        `, [accountId, startAt]);
        return {
            requests: row?.requests ?? 0,
            tokens: row?.tokens ?? 0,
            standardCost: row?.standard_cost ?? 0,
            accountCost: row?.account_cost ?? 0,
            userCost: row?.user_cost ?? 0
        };
    }

    async getDailyStats(accountId: number, startAt: string): Promise<AccountDailyStatsRecord[]> {
        const rows = await allRows<{
            date: string;
            requests: number;
            tokens: number;
            standard_cost: number;
            account_cost: number;
            user_cost: number;
            duration_ms: number;
        }>(this.db, `
            SELECT
                substr(created_at, 1, 10) AS date,
                COUNT(*) AS requests,
                COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens), 0) AS tokens,
                COALESCE(SUM(total_cost), 0) AS standard_cost,
                COALESCE(SUM(COALESCE(account_stats_cost, total_cost * COALESCE(account_rate_multiplier, 1))), 0) AS account_cost,
                COALESCE(SUM(actual_cost), 0) AS user_cost,
                COALESCE(AVG(duration_ms), 0) AS duration_ms
            FROM usage_logs
            WHERE account_id = ? AND created_at >= ?
            GROUP BY substr(created_at, 1, 10)
            ORDER BY date ASC
        `, [accountId, startAt]);
        return rows.map((row) => ({
            date: row.date,
            requests: row.requests,
            tokens: row.tokens,
            standardCost: row.standard_cost,
            accountCost: row.account_cost,
            userCost: row.user_cost,
            durationMs: row.duration_ms
        }));
    }

    async getDimensionStats(accountId: number, startAt: string, column: "model" | "upstream_endpoint" | "inbound_endpoint"): Promise<AccountDimensionStatsRecord[]> {
        const rows = await allRows<{
            key: string;
            requests: number;
            tokens: number;
            standard_cost: number;
            account_cost: number;
            user_cost: number;
        }>(this.db, `
            SELECT
                COALESCE(${column}, '') AS key,
                COUNT(*) AS requests,
                COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens), 0) AS tokens,
                COALESCE(SUM(total_cost), 0) AS standard_cost,
                COALESCE(SUM(COALESCE(account_stats_cost, total_cost * COALESCE(account_rate_multiplier, 1))), 0) AS account_cost,
                COALESCE(SUM(actual_cost), 0) AS user_cost
            FROM usage_logs
            WHERE account_id = ? AND created_at >= ?
            GROUP BY ${column}
            ORDER BY requests DESC
        `, [accountId, startAt]);
        return rows.map((row) => ({
            key: row.key,
            requests: row.requests,
            tokens: row.tokens,
            standardCost: row.standard_cost,
            accountCost: row.account_cost,
            userCost: row.user_cost
        }));
    }
}
