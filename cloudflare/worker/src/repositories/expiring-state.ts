import type { D1Database } from "../types/d1.ts";
import {
    currentTime,
    identifier,
    jsonText,
    parseJson,
    positiveInteger,
    systemClock,
    type Clock
} from "../utils/runtime-validation.ts";
import { firstRow, runStatement } from "./d1.ts";

const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000;

interface ExpiringStateOptions {
    clock?: Clock;
}

interface StateRow {
    valueJson: string;
    expiresAt: number;
}

export interface ExpiringStateValue<T> {
    value: T;
    expiresAt: number;
}

export class D1ExpiringStateRepository {
    readonly #db: D1Database;
    readonly #clock: Clock;

    constructor(db: D1Database, options: ExpiringStateOptions = {}) {
        this.#db = db;
        this.#clock = options.clock ?? systemClock;
    }

    async put<T>(keyValue: string, value: T, ttlMsValue: number): Promise<ExpiringStateValue<T>> {
        const key = identifier(keyValue, "state key");
        const ttlMs = positiveInteger(ttlMsValue, "state ttlMs", MAX_TTL_MS);
        const now = currentTime(this.#clock);
        const expiresAt = now + ttlMs;
        const valueJson = jsonText(value, "state value");

        await runStatement(this.#db, `
            INSERT INTO runtime_expiring_values (
                state_key, value_json, expires_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(state_key) DO UPDATE SET
                value_json = excluded.value_json,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
        `, [key, valueJson, expiresAt, now, now]);

        return { value, expiresAt };
    }

    async get<T>(keyValue: string): Promise<ExpiringStateValue<T> | null> {
        const key = identifier(keyValue, "state key");
        const now = currentTime(this.#clock);
        const row = await firstRow<StateRow>(this.#db, `
            SELECT value_json AS valueJson, expires_at AS expiresAt
            FROM runtime_expiring_values
            WHERE state_key = ? AND expires_at > ?
        `, [key, now]);

        if (row === null) {
            return null;
        }
        return {
            value: parseJson<T>(row.valueJson, "stored state value"),
            expiresAt: row.expiresAt
        };
    }

    async take<T>(keyValue: string): Promise<ExpiringStateValue<T> | null> {
        const key = identifier(keyValue, "state key");
        const now = currentTime(this.#clock);
        const row = await firstRow<StateRow>(this.#db, `
            DELETE FROM runtime_expiring_values
            WHERE state_key = ? AND expires_at > ?
            RETURNING value_json AS valueJson, expires_at AS expiresAt
        `, [key, now]);

        if (row === null) {
            return null;
        }
        return {
            value: parseJson<T>(row.valueJson, "stored state value"),
            expiresAt: row.expiresAt
        };
    }

    async compareAndSwap<T>(keyValue: string, expectedValue: T, nextValue: T): Promise<boolean> {
        const key = identifier(keyValue, "state key");
        const now = currentTime(this.#clock);
        const expectedJson = jsonText(expectedValue, "expected state value");
        const nextJson = jsonText(nextValue, "next state value");
        const result = await runStatement(this.#db, `
            UPDATE runtime_expiring_values
            SET value_json = ?, updated_at = ?
            WHERE state_key = ?
                AND value_json = ?
                AND expires_at > ?
        `, [nextJson, now, key, expectedJson, now]);
        return (result.meta?.changes ?? 0) === 1;
    }

    async delete(keyValue: string): Promise<boolean> {
        const key = identifier(keyValue, "state key");
        const result = await runStatement(this.#db, `
            DELETE FROM runtime_expiring_values WHERE state_key = ?
        `, [key]);
        return (result.meta?.changes ?? 0) > 0;
    }

    async purgeExpired(limitValue = 100): Promise<number> {
        const limit = positiveInteger(limitValue, "purge limit", 1000);
        const now = currentTime(this.#clock);
        const result = await runStatement(this.#db, `
            DELETE FROM runtime_expiring_values
            WHERE state_key IN (
                SELECT state_key
                FROM runtime_expiring_values
                WHERE expires_at <= ?
                ORDER BY expires_at
                LIMIT ?
            )
        `, [now, limit]);
        return result.meta?.changes ?? 0;
    }
}
