import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, requireSuccess, runStatement } from "./d1.ts";

export interface ContentModerationConfigRow {
    config: string;
}

export interface ContentModerationLogRow {
    id: number;
    request_id: string;
    user_id: number | null;
    user_email: string;
    api_key_id: number | null;
    api_key_name: string;
    group_id: number | null;
    group_name: string;
    endpoint: string;
    provider: string;
    model: string;
    mode: string;
    action: string;
    flagged: number;
    highest_category: string;
    highest_score: number;
    category_scores: string;
    threshold_snapshot: string;
    input_excerpt: string;
    upstream_latency_ms: number | null;
    error: string;
    violation_count: number;
    auto_banned: number;
    email_sent: number;
    queue_delay_ms: number | null;
    matched_keyword: string;
    created_at: string;
}

export interface LogFilter {
    result?: string;
    groupId?: number;
    endpoint?: string;
    search?: string;
    from?: string;
    to?: string;
    page: number;
    pageSize: number;
}

export class D1RiskControlRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async getConfig(): Promise<string | null> {
        const row = await firstRow<{ value: string }>(
            this.#db, "SELECT value FROM settings WHERE key = ?", ["content_moderation_config"]
        );
        return row?.value ?? null;
    }

    async saveConfig(configJson: string): Promise<void> {
        const now = new Date().toISOString();
        await runStatement(
            this.#db,
            `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
            ["content_moderation_config", configJson, now]
        );
    }

    async getRiskControlEnabled(): Promise<boolean> {
        const row = await firstRow<{ value: string }>(
            this.#db, "SELECT value FROM settings WHERE key = ?", ["risk_control_enabled"]
        );
        return row?.value === "true";
    }

    async setRiskControlEnabled(enabled: boolean): Promise<void> {
        const now = new Date().toISOString();
        await runStatement(
            this.#db,
            `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
            ["risk_control_enabled", enabled ? "true" : "false", now]
        );
    }

    async listLogs(filter: LogFilter): Promise<{ items: ContentModerationLogRow[]; total: number }> {
        const conditions: string[] = [];
        const values: D1Value[] = [];

        if (filter.result) {
            const r = filter.result.toLowerCase();
            if (r === "hit" || r === "flagged") {
                conditions.push("flagged = 1");
            } else if (r === "blocked" || r === "block") {
                conditions.push("action IN ('keyword_block','hash_block','pre_block')");
            } else if (r === "pass" || r === "allow") {
                conditions.push("flagged = 0 AND action != 'error'");
            } else if (r === "error") {
                conditions.push("action = 'error'");
            }
        }
        if (filter.groupId !== undefined && filter.groupId > 0) {
            conditions.push("group_id = ?");
            values.push(filter.groupId);
        }
        if (filter.endpoint) {
            conditions.push("endpoint = ?");
            values.push(filter.endpoint);
        }
        if (filter.search) {
            conditions.push("(request_id LIKE ? OR user_email LIKE ? OR api_key_name LIKE ? OR model LIKE ? OR input_excerpt LIKE ?)");
            const p = `%${filter.search}%`;
            values.push(p, p, p, p, p);
        }
        if (filter.from) {
            conditions.push("created_at >= ?");
            values.push(filter.from);
        }
        if (filter.to) {
            conditions.push("created_at <= ?");
            values.push(filter.to);
        }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
        const offset = (filter.page - 1) * filter.pageSize;

        const countRow = await firstRow<{ cnt: number }>(
            this.#db, `SELECT COUNT(*) as cnt FROM content_moderation_logs ${where}`, values
        );

        const rows = await allRows<ContentModerationLogRow>(
            this.#db,
            `SELECT * FROM content_moderation_logs ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
            [...values, filter.pageSize, offset]
        );

        return { items: rows, total: countRow?.cnt ?? 0 };
    }

    async unbanUser(userId: number): Promise<void> {
        const now = new Date().toISOString();
        await runStatement(this.#db, "UPDATE users SET status = 'active', updated_at = ? WHERE id = ? AND status != 'active'", [now, userId]);
    }

    async getUserStatus(userId: number): Promise<string | null> {
        const row = await firstRow<{ status: string }>(
            this.#db, "SELECT status FROM users WHERE id = ?", [userId]
        );
        return row?.status ?? null;
    }
}
