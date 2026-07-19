import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface SubscriptionRecord {
    id: number;
    userId: number;
    groupId: number;
    startsAt: string;
    expiresAt: string;
    status: string;
    dailyWindowStart: string | null;
    weeklyWindowStart: string | null;
    monthlyWindowStart: string | null;
    dailyUsageUsd: number;
    weeklyUsageUsd: number;
    monthlyUsageUsd: number;
    assignedAt: string;
    assignedBy: number | null;
    notes: string | null;
    createdAt: string;
    updatedAt: string;
    deletedAt: string | null;
}

interface SubscriptionRow {
    id: number;
    user_id: number;
    group_id: number;
    starts_at: string;
    expires_at: string;
    status: string;
    daily_window_start: string | null;
    weekly_window_start: string | null;
    monthly_window_start: string | null;
    daily_usage_usd: number;
    weekly_usage_usd: number;
    monthly_usage_usd: number;
    assigned_at: string;
    assigned_by: number | null;
    notes: string | null;
    created_at: string;
    updated_at: string;
    deleted_at: string | null;
}

export interface SubscriptionWithUserRecord extends SubscriptionRecord {
    userName: string;
    userEmail: string;
    groupName: string;
    groupPlatform: string;
    assignedByName: string | null;
}

interface SubscriptionWithUserRow extends SubscriptionRow {
    user_name: string;
    user_email: string;
    group_name: string;
    group_platform: string;
    assigned_by_name: string | null;
}

function rowToRecord(row: SubscriptionRow): SubscriptionRecord {
    return {
        id: row.id,
        userId: row.user_id,
        groupId: row.group_id,
        startsAt: row.starts_at,
        expiresAt: row.expires_at,
        status: row.status,
        dailyWindowStart: row.daily_window_start,
        weeklyWindowStart: row.weekly_window_start,
        monthlyWindowStart: row.monthly_window_start,
        dailyUsageUsd: row.daily_usage_usd,
        weeklyUsageUsd: row.weekly_usage_usd,
        monthlyUsageUsd: row.monthly_usage_usd,
        assignedAt: row.assigned_at,
        assignedBy: row.assigned_by,
        notes: row.notes,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        deletedAt: row.deleted_at,
    };
}

function rowToRecordWithUser(row: SubscriptionWithUserRow): SubscriptionWithUserRecord {
    return {
        ...rowToRecord(row),
        userName: row.user_name,
        userEmail: row.user_email,
        groupName: row.group_name,
        groupPlatform: row.group_platform,
        assignedByName: row.assigned_by_name,
    };
}

function nowISO(): string {
    return new Date().toISOString();
}

const SUBSCRIPTION_COLS = `
    us.id, us.user_id, us.group_id, us.starts_at, us.expires_at, us.status,
    us.daily_window_start, us.weekly_window_start, us.monthly_window_start,
    us.daily_usage_usd, us.weekly_usage_usd, us.monthly_usage_usd,
    us.assigned_at, us.assigned_by, us.notes,
    us.created_at, us.updated_at, us.deleted_at
`;

const USER_GROUP_JOIN = `
    LEFT JOIN users u ON u.id = us.user_id
    LEFT JOIN groups g ON g.id = us.group_id
    LEFT JOIN users ab ON ab.id = us.assigned_by
`;

const WITH_USER_SELECT = `
    ${SUBSCRIPTION_COLS},
    COALESCE(u.username, '') as user_name,
    COALESCE(u.email, '') as user_email,
    COALESCE(g.name, '') as group_name,
    COALESCE(g.platform, '') as group_platform,
    ab.username as assigned_by_name
`;

const INSERT_COLS = `(
    user_id, group_id, starts_at, expires_at, status,
    daily_window_start, weekly_window_start, monthly_window_start,
    daily_usage_usd, weekly_usage_usd, monthly_usage_usd,
    assigned_at, assigned_by, notes,
    created_at, updated_at
)`;

const INSERT_VALS = `VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

export class D1SubscriptionRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: Record<string, D1Value>): Promise<SubscriptionRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO user_subscriptions ${INSERT_COLS} ${INSERT_VALS} RETURNING *`;
        const vals = [
            input.user_id, input.group_id, input.starts_at, input.expires_at, input.status ?? "active",
            input.daily_window_start ?? null, input.weekly_window_start ?? null, input.monthly_window_start ?? null,
            0, 0, 0,
            ts, input.assigned_by ?? null, input.notes ?? null,
            ts, ts,
        ];
        const row = await firstRow<SubscriptionRow>(this.db, sql, vals);
        return rowToRecord(row!);
    }

    async batchCreate(inputs: Record<string, D1Value>[]): Promise<SubscriptionRecord[]> {
        const ts = nowISO();
        const results: SubscriptionRecord[] = [];
        for (const input of inputs) {
            const sql = `INSERT INTO user_subscriptions ${INSERT_COLS} ${INSERT_VALS} RETURNING *`;
            const vals = [
                input.user_id, input.group_id, input.starts_at, input.expires_at, input.status ?? "active",
                input.daily_window_start ?? null, input.weekly_window_start ?? null, input.monthly_window_start ?? null,
                0, 0, 0,
                ts, input.assigned_by ?? null, input.notes ?? null,
                ts, ts,
            ];
            const row = await firstRow<SubscriptionRow>(this.db, sql, vals);
            results.push(rowToRecord(row!));
        }
        return results;
    }

    async getById(id: number): Promise<SubscriptionWithUserRecord | null> {
        const sql = `SELECT ${WITH_USER_SELECT} FROM user_subscriptions us ${USER_GROUP_JOIN} WHERE us.id = ? AND us.deleted_at IS NULL`;
        const row = await firstRow<SubscriptionWithUserRow>(this.db, sql, [id]);
        return row ? rowToRecordWithUser(row) : null;
    }

    async update(id: number, input: Record<string, D1Value>): Promise<SubscriptionRecord | null> {
        const ts = nowISO();
        const setClauses: string[] = [];
        const values: D1Value[] = [];
        for (const [key, value] of Object.entries(input)) {
            if (key === "id" || key === "created_at") continue;
            setClauses.push(`${key} = ?`);
            values.push(value ?? null);
        }
        setClauses.push("updated_at = ?");
        values.push(ts);
        values.push(id);
        const sql = `UPDATE user_subscriptions SET ${setClauses.join(", ")} WHERE id = ? AND deleted_at IS NULL RETURNING *`;
        const row = await firstRow<SubscriptionRow>(this.db, sql, values);
        return row ? rowToRecord(row) : null;
    }

    async delete(id: number): Promise<boolean> {
        const ts = nowISO();
        const result = await runStatement(this.db, `UPDATE user_subscriptions SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, [ts, ts, id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }

    async restore(id: number): Promise<SubscriptionRecord | null> {
        const sql = `UPDATE user_subscriptions SET deleted_at = NULL, updated_at = ? WHERE id = ? AND deleted_at IS NOT NULL RETURNING *`;
        const row = await firstRow<SubscriptionRow>(this.db, sql, [nowISO(), id]);
        return row ? rowToRecord(row) : null;
    }

    async list(params: {
        page: number; pageSize: number; userId?: number; groupId?: number;
        status?: string; platform?: string; sortBy?: string; sortOrder?: string;
    }): Promise<{ items: SubscriptionWithUserRecord[]; total: number }> {
        const where: string[] = ["us.deleted_at IS NULL"];
        const values: D1Value[] = [];

        if (params.userId !== undefined) { where.push("us.user_id = ?"); values.push(params.userId); }
        if (params.groupId !== undefined) { where.push("us.group_id = ?"); values.push(params.groupId); }
        if (params.status) { where.push("us.status = ?"); values.push(params.status); }
        if (params.platform) { where.push("g.platform = ?"); values.push(params.platform); }

        const whereClause = `WHERE ${where.join(" AND ")}`;
        const sortBy = params.sortBy ?? "created_at";
        const sortOrder = params.sortOrder ?? "desc";
        const safeSortBy = ["created_at", "updated_at", "expires_at", "starts_at", "status", "daily_usage_usd", "weekly_usage_usd", "monthly_usage_usd"].includes(sortBy) ? `us.${sortBy}` : "us.created_at";
        const safeSortOrder = sortOrder === "asc" ? "ASC" : "DESC";

        const countRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM user_subscriptions us LEFT JOIN groups g ON g.id = us.group_id ${whereClause}`, values);
        const total = countRow?.c ?? 0;

        const offset = (params.page - 1) * params.pageSize;
        const rows = await allRows<SubscriptionWithUserRow>(this.db, `
            SELECT ${WITH_USER_SELECT} FROM user_subscriptions us
            ${USER_GROUP_JOIN}
            ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `, [...values, params.pageSize, offset]);

        return { items: rows.map(rowToRecordWithUser), total };
    }

    async listByGroup(groupId: number, page: number, pageSize: number): Promise<{ items: SubscriptionWithUserRecord[]; total: number }> {
        return this.list({ page, pageSize, groupId });
    }

    async listByUser(userId: number): Promise<SubscriptionWithUserRecord[]> {
        const sql = `
            SELECT ${WITH_USER_SELECT} FROM user_subscriptions us
            ${USER_GROUP_JOIN}
            WHERE us.user_id = ? AND us.deleted_at IS NULL
            ORDER BY us.created_at DESC
        `;
        const rows = await allRows<SubscriptionWithUserRow>(this.db, sql, [userId]);
        return rows.map(rowToRecordWithUser);
    }

    async listActiveByUser(userId: number): Promise<SubscriptionRecord[]> {
        const rows = await allRows<SubscriptionRow>(this.db, `
            SELECT * FROM user_subscriptions
            WHERE user_id = ? AND deleted_at IS NULL AND status = 'active' AND expires_at > ?
            ORDER BY created_at DESC
        `, [userId, nowISO()]);
        return rows.map(rowToRecord);
    }

    async userExists(id: number): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM users WHERE id = ?`, [id]);
        return row !== null && row.c > 0;
    }

    async groupExists(id: number): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM groups WHERE id = ? AND deleted_at IS NULL`, [id]);
        return row !== null && row.c > 0;
    }

    async hasActiveSubscription(userId: number, groupId: number): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `
            SELECT COUNT(*) as c FROM user_subscriptions
            WHERE user_id = ? AND group_id = ? AND deleted_at IS NULL AND status = 'active' AND expires_at > ?
        `, [userId, groupId, nowISO()]);
        return row !== null && row.c > 0;
    }
}
