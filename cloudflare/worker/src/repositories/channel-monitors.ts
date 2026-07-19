import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface ChannelMonitorRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    name: string;
    provider: string;
    apiMode: string;
    endpoint: string;
    apiKeyEncrypted: string;
    primaryModel: string;
    extraModels: string[];
    groupName: string;
    enabled: boolean;
    intervalSeconds: number;
    jitterSeconds: number;
    lastCheckedAt: string | null;
    createdBy: number;
    extraHeaders: Record<string, string>;
    bodyOverrideMode: string;
    bodyOverride: Record<string, unknown> | null;
    templateId: number | null;
}

export interface ChannelMonitorHistoryRecord {
    id: number;
    model: string;
    status: string;
    latencyMs: number | null;
    pingLatencyMs: number | null;
    message: string;
    checkedAt: string;
    monitorId: number;
}

interface MonitorRow {
    id: number;
    created_at: string;
    updated_at: string;
    name: string;
    provider: string;
    api_mode: string;
    endpoint: string;
    api_key_encrypted: string;
    primary_model: string;
    extra_models: string;
    group_name: string;
    enabled: number;
    interval_seconds: number;
    jitter_seconds: number;
    last_checked_at: string | null;
    created_by: number;
    extra_headers: string;
    body_override_mode: string;
    body_override: string | null;
    template_id: number | null;
}

interface HistoryRow {
    id: number;
    model: string;
    status: string;
    latency_ms: number | null;
    ping_latency_ms: number | null;
    message: string;
    checked_at: string;
    monitor_id: number;
}

function parseJsonStringArray(raw: string | null): string[] {
    if (!raw) return [];
    try {
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter((s: unknown): s is string => typeof s === "string") : [];
    } catch { return []; }
}

function parseJsonObject(raw: string | null): Record<string, string> {
    if (!raw) return {};
    try {
        const obj = JSON.parse(raw);
        return (obj && typeof obj === "object" && !Array.isArray(obj)) ? obj : {};
    } catch { return {}
    }
}

function parseJsonObjectNullable(raw: string | null): Record<string, unknown> | null {
    if (!raw) return null;
    try {
        const obj = JSON.parse(raw);
        return (obj && typeof obj === "object") ? obj : null;
    } catch { return null; }
}

function monitorRowToRecord(row: MonitorRow): ChannelMonitorRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        name: row.name,
        provider: row.provider,
        apiMode: row.api_mode,
        endpoint: row.endpoint,
        apiKeyEncrypted: row.api_key_encrypted,
        primaryModel: row.primary_model,
        extraModels: parseJsonStringArray(row.extra_models),
        groupName: row.group_name,
        enabled: row.enabled === 1,
        intervalSeconds: row.interval_seconds,
        jitterSeconds: row.jitter_seconds,
        lastCheckedAt: row.last_checked_at,
        createdBy: row.created_by,
        extraHeaders: parseJsonObject(row.extra_headers),
        bodyOverrideMode: row.body_override_mode,
        bodyOverride: parseJsonObjectNullable(row.body_override),
        templateId: row.template_id,
    };
}

function historyRowToRecord(row: HistoryRow): ChannelMonitorHistoryRecord {
    return {
        id: row.id,
        model: row.model,
        status: row.status,
        latencyMs: row.latency_ms,
        pingLatencyMs: row.ping_latency_ms,
        message: row.message,
        checkedAt: row.checked_at,
        monitorId: row.monitor_id,
    };
}

export interface CreateMonitorInput {
    name: string;
    provider: string;
    apiMode: string;
    endpoint: string;
    apiKeyEncrypted: string;
    primaryModel: string;
    extraModels: string[];
    groupName: string;
    enabled: boolean;
    intervalSeconds: number;
    jitterSeconds: number;
    createdBy: number;
    extraHeaders: Record<string, string>;
    bodyOverrideMode: string;
    bodyOverride: Record<string, unknown> | null;
    templateId: number | null;
}

export interface UpdateMonitorInput {
    name?: string;
    provider?: string;
    apiMode?: string;
    endpoint?: string;
    apiKeyEncrypted?: string;
    primaryModel?: string;
    extraModels?: string[];
    groupName?: string;
    enabled?: boolean;
    intervalSeconds?: number;
    jitterSeconds?: number;
    templateId?: number | null;
    extraHeaders?: Record<string, string>;
    bodyOverrideMode?: string;
    bodyOverride?: Record<string, unknown> | null;
}

export interface ListMonitorsOptions {
    page: number;
    pageSize: number;
    provider?: string;
    enabled?: boolean;
    search?: string;
}

export class D1ChannelMonitorRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async list(opts: ListMonitorsOptions): Promise<{ items: ChannelMonitorRecord[]; total: number }> {
        const where: string[] = [];
        const values: D1Value[] = [];

        if (opts.provider) { where.push("provider = ?"); values.push(opts.provider); }
        if (opts.enabled !== undefined) { where.push("enabled = ?"); values.push(opts.enabled ? 1 : 0); }
        if (opts.search) {
            where.push("(name LIKE ? OR group_name LIKE ? OR primary_model LIKE ?)");
            const like = `%${opts.search}%`;
            values.push(like, like, like);
        }

        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

        const countResult = await firstRow<{ cnt: number }>(
            this.#db,
            `SELECT COUNT(*) as cnt FROM channel_monitors ${whereClause}`,
            values
        );
        const total = countResult?.cnt ?? 0;

        const limit = Math.min(opts.pageSize, 100);
        const offset = (opts.page - 1) * limit;

        const rows = await allRows<MonitorRow>(
            this.#db,
            `SELECT * FROM channel_monitors ${whereClause} ORDER BY id DESC LIMIT ? OFFSET ?`,
            [...values, limit, offset]
        );

        return { items: rows.map(monitorRowToRecord), total };
    }

    async findById(id: number): Promise<ChannelMonitorRecord | null> {
        const row = await firstRow<MonitorRow>(
            this.#db,
            "SELECT * FROM channel_monitors WHERE id = ?",
            [id]
        );
        return row === null ? null : monitorRowToRecord(row);
    }

    async create(input: CreateMonitorInput): Promise<ChannelMonitorRecord> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `INSERT INTO channel_monitors (
                created_at, updated_at, name, provider, api_mode, endpoint,
                api_key_encrypted, primary_model, extra_models, group_name,
                enabled, interval_seconds, jitter_seconds, created_by,
                extra_headers, body_override_mode, body_override, template_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                now, now, input.name, input.provider, input.apiMode, input.endpoint,
                input.apiKeyEncrypted, input.primaryModel,
                JSON.stringify(input.extraModels), input.groupName,
                input.enabled ? 1 : 0, input.intervalSeconds, input.jitterSeconds,
                input.createdBy,
                JSON.stringify(input.extraHeaders), input.bodyOverrideMode,
                input.bodyOverride ? JSON.stringify(input.bodyOverride) : null,
                input.templateId,
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findById(id))!;
    }

    async update(id: number, input: UpdateMonitorInput): Promise<ChannelMonitorRecord | null> {
        const existing = await this.findById(id);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.name !== undefined) { sets.push("name = ?"); values.push(input.name); }
        if (input.provider !== undefined) { sets.push("provider = ?"); values.push(input.provider); }
        if (input.apiMode !== undefined) { sets.push("api_mode = ?"); values.push(input.apiMode); }
        if (input.endpoint !== undefined) { sets.push("endpoint = ?"); values.push(input.endpoint); }
        if (input.apiKeyEncrypted !== undefined) { sets.push("api_key_encrypted = ?"); values.push(input.apiKeyEncrypted); }
        if (input.primaryModel !== undefined) { sets.push("primary_model = ?"); values.push(input.primaryModel); }
        if (input.extraModels !== undefined) { sets.push("extra_models = ?"); values.push(JSON.stringify(input.extraModels)); }
        if (input.groupName !== undefined) { sets.push("group_name = ?"); values.push(input.groupName); }
        if (input.enabled !== undefined) { sets.push("enabled = ?"); values.push(input.enabled ? 1 : 0); }
        if (input.intervalSeconds !== undefined) { sets.push("interval_seconds = ?"); values.push(input.intervalSeconds); }
        if (input.jitterSeconds !== undefined) { sets.push("jitter_seconds = ?"); values.push(input.jitterSeconds); }
        if (input.templateId !== undefined) { sets.push("template_id = ?"); values.push(input.templateId); }
        if (input.extraHeaders !== undefined) { sets.push("extra_headers = ?"); values.push(JSON.stringify(input.extraHeaders)); }
        if (input.bodyOverrideMode !== undefined) { sets.push("body_override_mode = ?"); values.push(input.bodyOverrideMode); }
        if (input.bodyOverride !== undefined) { sets.push("body_override = ?"); values.push(input.bodyOverride ? JSON.stringify(input.bodyOverride) : null); }

        if (sets.length === 1) return existing;

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE channel_monitors SET ${sets.join(", ")} WHERE id = ?`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(
            this.#db,
            "DELETE FROM channel_monitors WHERE id = ?",
            [id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async listEnabledMonitors(): Promise<ChannelMonitorRecord[]> {
        const rows = await allRows<MonitorRow>(
            this.#db,
            "SELECT * FROM channel_monitors WHERE enabled = 1 ORDER BY name ASC",
        );
        return rows.map(monitorRowToRecord);
    }

    async getLatestHistory(monitorId: number, model: string): Promise<ChannelMonitorHistoryRecord | null> {
        const row = await firstRow<HistoryRow>(
            this.#db,
            "SELECT * FROM channel_monitor_histories WHERE monitor_id = ? AND model = ? ORDER BY checked_at DESC LIMIT 1",
            [monitorId, model]
        );
        return row === null ? null : historyRowToRecord(row);
    }

    async getAvailability7d(monitorId: number, model: string): Promise<number> {
        const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const row = await firstRow<{ ok_count: number; total: number }>(
            this.#db,
            `SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status IN ('operational','ok') THEN 1 ELSE 0 END) as ok_count
             FROM channel_monitor_histories
             WHERE monitor_id = ? AND model = ? AND checked_at >= ?`,
            [monitorId, model, since]
        );
        if (!row || row.total === 0) return 0;
        return Math.round((row.ok_count / row.total) * 10000) / 100;
    }

    async getTimeline(monitorId: number, model: string, limit: number): Promise<ChannelMonitorHistoryRecord[]> {
        return this.listHistory(monitorId, limit, model);
    }

    async getMultiModelAvailability(monitorId: number, model: string, days: number): Promise<number> {
        const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
        const row = await firstRow<{ ok_count: number; total: number }>(
            this.#db,
            `SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status IN ('operational','ok') THEN 1 ELSE 0 END) as ok_count
             FROM channel_monitor_histories
             WHERE monitor_id = ? AND model = ? AND checked_at >= ?`,
            [monitorId, model, since]
        );
        if (!row || row.total === 0) return 0;
        return Math.round((row.ok_count / row.total) * 10000) / 100;
    }

    async getAvgLatency7d(monitorId: number, model: string): Promise<number | null> {
        const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const row = await firstRow<{ avg: number | null }>(
            this.#db,
            "SELECT AVG(latency_ms) as avg FROM channel_monitor_histories WHERE monitor_id = ? AND model = ? AND checked_at >= ? AND latency_ms IS NOT NULL",
            [monitorId, model, since]
        );
        return row?.avg ?? null;
    }

    async listHistory(monitorId: number, limit: number, model?: string): Promise<ChannelMonitorHistoryRecord[]> {
        const where = ["monitor_id = ?"];
        const values: D1Value[] = [monitorId];
        if (model) { where.push("model = ?"); values.push(model); }

        const clampedLimit = Math.max(1, Math.min(limit, 1000));
        const rows = await allRows<HistoryRow>(
            this.#db,
            `SELECT * FROM channel_monitor_histories WHERE ${where.join(" AND ")} ORDER BY checked_at DESC LIMIT ?`,
            [...values, clampedLimit]
        );
        return rows.map(historyRowToRecord);
    }
}
