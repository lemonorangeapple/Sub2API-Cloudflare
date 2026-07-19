import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface ChannelMonitorTemplateRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    name: string;
    provider: string;
    apiMode: string;
    description: string;
    extraHeaders: Record<string, string>;
    bodyOverrideMode: string;
    bodyOverride: Record<string, unknown> | null;
    associatedMonitors: number;
}

export interface TemplateMonitorSummary {
    id: number;
    name: string;
    provider: string;
    apiMode: string;
    enabled: boolean;
}

interface TemplateRow {
    id: number;
    created_at: string;
    updated_at: string;
    name: string;
    provider: string;
    api_mode: string;
    description: string | null;
    extra_headers: string;
    body_override_mode: string;
    body_override: string | null;
}

function parseJsonObject(raw: string | null): Record<string, string> {
    if (!raw) return {};
    try {
        const obj = JSON.parse(raw);
        return (obj && typeof obj === "object" && !Array.isArray(obj)) ? obj : {};
    } catch { return {}; }
}

function parseJsonObjectNullable(raw: string | null): Record<string, unknown> | null {
    if (!raw) return null;
    try {
        const obj = JSON.parse(raw);
        return (obj && typeof obj === "object") ? obj : null;
    } catch { return null; }
}

function rowToRecord(row: TemplateRow, associatedMonitors: number): ChannelMonitorTemplateRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        name: row.name,
        provider: row.provider,
        apiMode: row.api_mode,
        description: row.description ?? "",
        extraHeaders: parseJsonObject(row.extra_headers),
        bodyOverrideMode: row.body_override_mode,
        bodyOverride: parseJsonObjectNullable(row.body_override),
        associatedMonitors,
    };
}

export interface CreateTemplateInput {
    name: string;
    provider: string;
    apiMode?: string;
    description?: string;
    extraHeaders?: Record<string, string>;
    bodyOverrideMode?: string;
    bodyOverride?: Record<string, unknown> | null;
}

export interface UpdateTemplateInput {
    name?: string;
    apiMode?: string;
    description?: string;
    extraHeaders?: Record<string, string>;
    bodyOverrideMode?: string;
    bodyOverride?: Record<string, unknown> | null;
}

export class D1ChannelMonitorTemplateRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async list(filters?: { provider?: string; apiMode?: string }): Promise<ChannelMonitorTemplateRecord[]> {
        const where: string[] = [];
        const values: D1Value[] = [];
        if (filters?.provider) { where.push("provider = ?"); values.push(filters.provider); }
        if (filters?.apiMode) { where.push("api_mode = ?"); values.push(filters.apiMode); }
        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

        const rows = await allRows<TemplateRow>(
            this.#db,
            `SELECT * FROM channel_monitor_request_templates ${whereClause} ORDER BY provider, api_mode, name`,
            values
        );

        return Promise.all(rows.map(async (row) => {
            const countRow = await firstRow<{ cnt: number }>(
                this.#db,
                "SELECT COUNT(*) as cnt FROM channel_monitors WHERE template_id = ?",
                [row.id]
            );
            return rowToRecord(row, countRow?.cnt ?? 0);
        }));
    }

    async findById(id: number): Promise<ChannelMonitorTemplateRecord | null> {
        const row = await firstRow<TemplateRow>(
            this.#db,
            "SELECT * FROM channel_monitor_request_templates WHERE id = ?",
            [id]
        );
        if (row === null) return null;
        const countRow = await firstRow<{ cnt: number }>(
            this.#db,
            "SELECT COUNT(*) as cnt FROM channel_monitors WHERE template_id = ?",
            [id]
        );
        return rowToRecord(row, countRow?.cnt ?? 0);
    }

    async findByNameAndProvider(name: string, provider: string): Promise<ChannelMonitorTemplateRecord | null> {
        const row = await firstRow<TemplateRow>(
            this.#db,
            "SELECT * FROM channel_monitor_request_templates WHERE provider = ? AND name = ?",
            [provider, name]
        );
        if (row === null) return null;
        return rowToRecord(row, 0);
    }

    async create(input: CreateTemplateInput): Promise<ChannelMonitorTemplateRecord> {
        const now = new Date().toISOString();
        const apiMode = input.apiMode ?? "chat_completions";
        const bodyOverrideMode = input.bodyOverrideMode ?? "off";

        await runStatement(
            this.#db,
            `INSERT INTO channel_monitor_request_templates (
                created_at, updated_at, name, provider, api_mode,
                description, extra_headers, body_override_mode, body_override
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                now, now, input.name, input.provider, apiMode,
                input.description ?? "",
                JSON.stringify(input.extraHeaders ?? {}),
                bodyOverrideMode,
                input.bodyOverride ? JSON.stringify(input.bodyOverride) : null,
            ]
        );
        const id = Number((await firstRow<{ id: number }>(
            this.#db,
            "SELECT id FROM channel_monitor_request_templates WHERE provider = ? AND name = ? ORDER BY id DESC LIMIT 1",
            [input.provider, input.name]
        ))?.id ?? 0);
        return (await this.findById(id))!;
    }

    async update(id: number, input: UpdateTemplateInput): Promise<ChannelMonitorTemplateRecord | null> {
        const existing = await firstRow<TemplateRow>(
            this.#db,
            "SELECT * FROM channel_monitor_request_templates WHERE id = ?",
            [id]
        );
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.name !== undefined) { sets.push("name = ?"); values.push(input.name); }
        if (input.apiMode !== undefined) { sets.push("api_mode = ?"); values.push(input.apiMode); }
        if (input.description !== undefined) { sets.push("description = ?"); values.push(input.description); }
        if (input.extraHeaders !== undefined) { sets.push("extra_headers = ?"); values.push(JSON.stringify(input.extraHeaders)); }
        if (input.bodyOverrideMode !== undefined) { sets.push("body_override_mode = ?"); values.push(input.bodyOverrideMode); }
        if (input.bodyOverride !== undefined) { sets.push("body_override = ?"); values.push(input.bodyOverride ? JSON.stringify(input.bodyOverride) : null); }

        if (sets.length === 1) return this.findById(id);

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE channel_monitor_request_templates SET ${sets.join(", ")} WHERE id = ?`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(
            this.#db,
            "DELETE FROM channel_monitor_request_templates WHERE id = ?",
            [id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async listAssociatedMonitors(templateId: number): Promise<TemplateMonitorSummary[]> {
        const rows = await allRows<{ id: number; name: string; provider: string; api_mode: string; enabled: number }>(
            this.#db,
            "SELECT id, name, provider, api_mode, enabled FROM channel_monitors WHERE template_id = ? ORDER BY name",
            [templateId]
        );
        return rows.map((r) => ({ id: r.id, name: r.name, provider: r.provider, apiMode: r.api_mode, enabled: r.enabled === 1 }));
    }

    async applyToMonitors(templateId: number, monitorIds: number[], template: { apiMode: string; extraHeaders: Record<string, string>; bodyOverrideMode: string; bodyOverride: Record<string, unknown> | null }): Promise<number> {
        if (monitorIds.length === 0) return 0;
        const now = new Date().toISOString();
        const placeholders = monitorIds.map(() => "?").join(",");
        const result = await runStatement(
            this.#db,
            `UPDATE channel_monitors SET
                updated_at = ?, api_mode = ?, extra_headers = ?,
                body_override_mode = ?, body_override = ?
            WHERE template_id = ? AND id IN (${placeholders})`,
            [
                now, template.apiMode, JSON.stringify(template.extraHeaders),
                template.bodyOverrideMode, template.bodyOverride ? JSON.stringify(template.bodyOverride) : null,
                templateId, ...monitorIds,
            ]
        );
        return result.meta?.changes ?? 0;
    }
}
