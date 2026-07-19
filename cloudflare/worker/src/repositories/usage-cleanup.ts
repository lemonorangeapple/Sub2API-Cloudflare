import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface CleanupTaskRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    status: string;
    filters: Record<string, unknown>;
    createdBy: number;
    deletedRows: number;
    errorMessage: string | null;
    canceledBy: number | null;
    canceledAt: string | null;
    startedAt: string | null;
    finishedAt: string | null;
}

interface CleanupTaskRow {
    id: number;
    created_at: string;
    updated_at: string;
    status: string;
    filters: string;
    created_by: number;
    deleted_rows: number;
    error_message: string | null;
    canceled_by: number | null;
    canceled_at: string | null;
    started_at: string | null;
    finished_at: string | null;
}

function rowToRecord(row: CleanupTaskRow): CleanupTaskRecord {
    let filters: Record<string, unknown> = {};
    try { filters = JSON.parse(row.filters); } catch { /* ignore */ }
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        status: row.status,
        filters,
        createdBy: row.created_by,
        deletedRows: row.deleted_rows,
        errorMessage: row.error_message,
        canceledBy: row.canceled_by,
        canceledAt: row.canceled_at,
        startedAt: row.started_at,
        finishedAt: row.finished_at,
    };
}

export interface SearchUserResult {
    id: number;
    email: string;
    deleted: boolean;
}

export interface SearchApiKeyResult {
    id: number;
    name: string;
    userId: number;
}

export class D1UsageCleanupRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async listTasks(page: number, pageSize: number): Promise<{ items: CleanupTaskRecord[]; total: number }> {
        const offset = (Math.max(1, page) - 1) * pageSize;
        const countRow = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(*) as cnt FROM usage_cleanup_tasks", []);
        const total = countRow?.cnt ?? 0;
        const rows = await allRows<CleanupTaskRow>(
            this.#db,
            "SELECT * FROM usage_cleanup_tasks ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [pageSize, offset]
        );
        return { items: rows.map(rowToRecord), total };
    }

    async getTask(id: number): Promise<CleanupTaskRecord | null> {
        const row = await firstRow<CleanupTaskRow>(this.#db, "SELECT * FROM usage_cleanup_tasks WHERE id = ?", [id]);
        return row ? rowToRecord(row) : null;
    }

    async createTask(filters: Record<string, unknown>, createdBy: number): Promise<CleanupTaskRecord> {
        const now = new Date().toISOString();
        await runStatement(
            this.#db,
            "INSERT INTO usage_cleanup_tasks (created_at, updated_at, status, filters, created_by, deleted_rows) VALUES (?, ?, 'pending', ?, ?, 0)",
            [now, now, JSON.stringify(filters), createdBy]
        );
        const id = Number((await firstRow<{ id: number }>(this.#db, "SELECT id FROM usage_cleanup_tasks ORDER BY id DESC LIMIT 1", []))?.id ?? 0);
        return (await this.getTask(id))!;
    }

    async cancelTask(id: number, canceledBy: number): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            "UPDATE usage_cleanup_tasks SET status = 'canceled', canceled_by = ?, canceled_at = ?, updated_at = ? WHERE id = ? AND status IN ('pending', 'running')",
            [canceledBy, now, now, id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async searchUsers(keyword: string): Promise<SearchUserResult[]> {
        if (!keyword || !keyword.trim()) return [];
        const search = keyword.trim();
        const rows = await allRows<{ id: number; email: string; deleted_at: string | null }>(
            this.#db,
            "SELECT id, COALESCE(email, '') as email, deleted_at FROM users WHERE email LIKE ? OR username LIKE ? LIMIT 30",
            [`%${search}%`, `%${search}%`]
        );
        return rows.map((r) => ({ id: r.id, email: r.email, deleted: r.deleted_at !== null }));
    }

    async searchApiKeys(userId: number | null, keyword: string): Promise<SearchApiKeyResult[]> {
        if (!keyword || !keyword.trim()) return [];
        const search = keyword.trim();
        const values: D1Value[] = [`%${search}%`];
        let where = "name LIKE ?";
        if (userId !== null && userId > 0) {
            where += " AND user_id = ?";
            values.push(userId);
        }
        values.push(30);
        const rows = await allRows<{ id: number; name: string; user_id: number }>(
            this.#db,
            `SELECT id, name, user_id FROM api_keys WHERE ${where} LIMIT ?`,
            values
        );
        return rows.map((row) => ({ id: row.id, name: row.name, userId: row.user_id }));
    }
}
