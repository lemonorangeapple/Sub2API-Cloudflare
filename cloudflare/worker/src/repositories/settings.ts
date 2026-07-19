import type { D1Database } from "../types/d1.ts";
import { requireSuccess, runBatchTransaction } from "./d1.ts";

interface SettingRow {
    key: string;
    value: string;
}

export interface SettingsReader {
    getMany(keys: readonly string[]): Promise<Record<string, string>>;
    getAll(): Promise<Record<string, string>>;
}

export interface SettingsWriter {
    upsertMany(values: Readonly<Record<string, string>>, updatedAt: string): Promise<void>;
    delete(key: string): Promise<void>;
}

export class D1SettingsRepository implements SettingsReader, SettingsWriter {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async getMany(keys: readonly string[]): Promise<Record<string, string>> {
        const uniqueKeys = [...new Set(keys)];
        if (uniqueKeys.length === 0) {
            return {};
        }

        const placeholders = uniqueKeys.map(() => "?").join(", ");
        const result = await this.#db
            .prepare(`SELECT key, value FROM settings WHERE key IN (${placeholders})`)
            .bind(...uniqueKeys)
            .all<SettingRow>();
        requireSuccess(result, "read settings");

        const values: Record<string, string> = {};
        for (const row of result.results ?? []) {
            if (typeof row.key !== "string" || typeof row.value !== "string") {
                throw new TypeError("settings table contains an invalid row");
            }
            values[row.key] = row.value;
        }
        return values;
    }

    async upsertMany(values: Readonly<Record<string, string>>, updatedAt: string): Promise<void> {
        const entries = Object.entries(values);
        await runBatchTransaction(this.#db, entries.map(([key, value]) => ({
            sql: `
                INSERT INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
            `,
            values: [key, value, updatedAt]
        })));
    }

    async getAll(): Promise<Record<string, string>> {
        const result = await this.#db.prepare("SELECT key, value FROM settings").all<SettingRow>();
        requireSuccess(result, "read all settings");

        const values: Record<string, string> = {};
        for (const row of result.results ?? []) {
            if (typeof row.key !== "string" || typeof row.value !== "string") {
                throw new TypeError("settings table contains an invalid row");
            }
            values[row.key] = row.value;
        }
        return values;
    }

    async delete(key: string): Promise<void> {
        await this.#db.prepare("DELETE FROM settings WHERE key = ?").bind(key).run();
    }
}
