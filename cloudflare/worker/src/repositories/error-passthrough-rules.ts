import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface ErrorPassthroughRuleRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    name: string;
    enabled: boolean;
    priority: number;
    errorCodes: number[];
    keywords: string[];
    matchMode: string;
    platforms: string[];
    passthroughCode: boolean;
    responseCode: number | null;
    passthroughBody: boolean;
    customMessage: string | null;
    skipMonitoring: boolean;
    description: string | null;
}

interface RuleRow {
    id: number;
    created_at: string;
    updated_at: string;
    name: string;
    enabled: number;
    priority: number;
    error_codes: string | null;
    keywords: string | null;
    match_mode: string;
    platforms: string | null;
    passthrough_code: number;
    response_code: number | null;
    passthrough_body: number;
    custom_message: string | null;
    skip_monitoring: number;
    description: string | null;
}

function parseJsonNumberArray(raw: string | null): number[] {
    if (!raw) return [];
    try {
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter((n: unknown): n is number => typeof n === "number") : [];
    } catch { return []; }
}

function parseJsonStringArray(raw: string | null): string[] {
    if (!raw) return [];
    try {
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter((s: unknown): s is string => typeof s === "string") : [];
    } catch { return []; }
}

function rowToRecord(row: RuleRow): ErrorPassthroughRuleRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        name: row.name,
        enabled: row.enabled === 1,
        priority: row.priority,
        errorCodes: parseJsonNumberArray(row.error_codes),
        keywords: parseJsonStringArray(row.keywords),
        matchMode: row.match_mode,
        platforms: parseJsonStringArray(row.platforms),
        passthroughCode: row.passthrough_code === 1,
        responseCode: row.response_code,
        passthroughBody: row.passthrough_body === 1,
        customMessage: row.custom_message,
        skipMonitoring: row.skip_monitoring === 1,
        description: row.description,
    };
}

export interface CreateRuleInput {
    name: string;
    enabled?: boolean;
    priority?: number;
    errorCodes?: number[];
    keywords?: string[];
    matchMode?: string;
    platforms?: string[];
    passthroughCode?: boolean;
    responseCode?: number | null;
    passthroughBody?: boolean;
    customMessage?: string | null;
    skipMonitoring?: boolean;
    description?: string | null;
}

export interface UpdateRuleInput {
    name?: string;
    enabled?: boolean;
    priority?: number;
    errorCodes?: number[];
    keywords?: string[];
    matchMode?: string;
    platforms?: string[];
    passthroughCode?: boolean;
    responseCode?: number | null;
    passthroughBody?: boolean;
    customMessage?: string | null;
    skipMonitoring?: boolean;
    description?: string | null;
}

export class D1ErrorPassthroughRuleRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async list(): Promise<ErrorPassthroughRuleRecord[]> {
        const rows = await allRows<RuleRow>(
            this.#db,
            "SELECT * FROM error_passthrough_rules ORDER BY priority ASC"
        );
        return rows.map(rowToRecord);
    }

    async findById(id: number): Promise<ErrorPassthroughRuleRecord | null> {
        const row = await firstRow<RuleRow>(
            this.#db,
            "SELECT * FROM error_passthrough_rules WHERE id = ?",
            [id]
        );
        return row === null ? null : rowToRecord(row);
    }

    async create(input: CreateRuleInput): Promise<ErrorPassthroughRuleRecord> {
        const now = new Date().toISOString();
        const enabled = input.enabled ?? true;
        const priority = input.priority ?? 0;
        const errorCodes = input.errorCodes ?? [];
        const keywords = input.keywords ?? [];
        const matchMode = input.matchMode ?? "any";
        const platforms = input.platforms ?? [];
        const passthroughCode = input.passthroughCode ?? true;
        const passthroughBody = input.passthroughBody ?? true;
        const skipMonitoring = input.skipMonitoring ?? false;

        const result = await runStatement(
            this.#db,
            `INSERT INTO error_passthrough_rules (
                created_at, updated_at, name, enabled, priority, error_codes,
                keywords, match_mode, platforms, passthrough_code, response_code,
                passthrough_body, custom_message, skip_monitoring, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                now, now, input.name,
                enabled ? 1 : 0, priority,
                errorCodes.length > 0 ? JSON.stringify(errorCodes) : null,
                keywords.length > 0 ? JSON.stringify(keywords) : null,
                matchMode,
                platforms.length > 0 ? JSON.stringify(platforms) : null,
                passthroughCode ? 1 : 0,
                input.responseCode ?? null,
                passthroughBody ? 1 : 0,
                input.customMessage ?? null,
                skipMonitoring ? 1 : 0,
                input.description ?? null,
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findById(id))!;
    }

    async update(id: number, input: UpdateRuleInput): Promise<ErrorPassthroughRuleRecord | null> {
        const existing = await this.findById(id);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.name !== undefined) { sets.push("name = ?"); values.push(input.name); }
        if (input.enabled !== undefined) { sets.push("enabled = ?"); values.push(input.enabled ? 1 : 0); }
        if (input.priority !== undefined) { sets.push("priority = ?"); values.push(input.priority); }
        if (input.errorCodes !== undefined) {
            sets.push("error_codes = ?");
            values.push(input.errorCodes.length > 0 ? JSON.stringify(input.errorCodes) : null);
        }
        if (input.keywords !== undefined) {
            sets.push("keywords = ?");
            values.push(input.keywords.length > 0 ? JSON.stringify(input.keywords) : null);
        }
        if (input.matchMode !== undefined) { sets.push("match_mode = ?"); values.push(input.matchMode); }
        if (input.platforms !== undefined) {
            sets.push("platforms = ?");
            values.push(input.platforms.length > 0 ? JSON.stringify(input.platforms) : null);
        }
        if (input.passthroughCode !== undefined) { sets.push("passthrough_code = ?"); values.push(input.passthroughCode ? 1 : 0); }
        if (input.responseCode !== undefined) { sets.push("response_code = ?"); values.push(input.responseCode); }
        if (input.passthroughBody !== undefined) { sets.push("passthrough_body = ?"); values.push(input.passthroughBody ? 1 : 0); }
        if (input.customMessage !== undefined) { sets.push("custom_message = ?"); values.push(input.customMessage); }
        if (input.skipMonitoring !== undefined) { sets.push("skip_monitoring = ?"); values.push(input.skipMonitoring ? 1 : 0); }
        if (input.description !== undefined) { sets.push("description = ?"); values.push(input.description); }

        if (sets.length === 1) return existing;

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE error_passthrough_rules SET ${sets.join(", ")} WHERE id = ?`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(
            this.#db,
            "DELETE FROM error_passthrough_rules WHERE id = ?",
            [id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }
}
