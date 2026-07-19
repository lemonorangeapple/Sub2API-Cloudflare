import type { D1Database } from "../types/d1.ts";
import {
    currentTime,
    identifier,
    positiveInteger,
    randomToken,
    systemClock,
    type Clock,
    type TokenFactory
} from "../utils/runtime-validation.ts";
import { firstRow, runBatchTransaction } from "./d1.ts";

const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface LeaseInput {
    key: string;
    owner: string;
    ttlMs: number;
}

export interface LeaseResult {
    acquired: boolean;
    replayed: boolean;
    expiresAt: number | null;
    fencingToken: number | null;
}

export interface RenewLeaseInput extends LeaseInput {
    fencingToken: number;
}

export interface RenewLeaseResult {
    renewed: boolean;
    expiresAt: number | null;
    fencingToken: number | null;
}

export interface FixedWindowInput {
    key: string;
    limit: number;
    windowMs: number;
    amount?: number;
}

export interface FixedWindowResult {
    allowed: boolean;
    count: number;
    remaining: number;
    resetAt: number;
}

export interface ReservationInput {
    key: string;
    reservationId: string;
    ttlMs: number;
}

export interface ReservationResult {
    reserved: boolean;
    replayed: boolean;
    expiresAt: number | null;
}

interface CoordinationOptions {
    clock?: Clock;
    tokenFactory?: TokenFactory;
}

interface LeaseRow {
    owner: string;
    expiresAt: number;
    acquireNonce: string;
    fencingToken: number;
}

interface LeaseStateRow {
    expiresAt: number;
    fencingToken: number;
}

interface ExpiryRow {
    expiresAt: number;
}

interface CounterRow {
    count: number;
    resetAt: number;
}

interface ReservationRow {
    reservationId: string;
    expiresAt: number;
    reservationNonce: string;
}

export class D1CoordinationRepository {
    readonly #db: D1Database;
    readonly #clock: Clock;
    readonly #tokenFactory: TokenFactory;

    constructor(db: D1Database, options: CoordinationOptions = {}) {
        this.#db = db;
        this.#clock = options.clock ?? systemClock;
        this.#tokenFactory = options.tokenFactory ?? randomToken;
    }

    async acquireLease(input: LeaseInput): Promise<LeaseResult> {
        const key = identifier(input.key, "lease key");
        const owner = identifier(input.owner, "lease owner", 256);
        const ttlMs = positiveInteger(input.ttlMs, "lease ttlMs", MAX_TTL_MS);
        const now = currentTime(this.#clock);
        const expiresAt = now + ttlMs;
        const nonce = identifier(this.#tokenFactory(), "lease nonce", 256);

        const row = await firstRow<LeaseRow>(this.#db, `
            INSERT INTO runtime_leases (
                lease_key,
                owner,
                acquire_nonce,
                fencing_token,
                expires_at,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(lease_key) DO UPDATE SET
                owner = CASE
                    WHEN runtime_leases.expires_at <= ? THEN excluded.owner
                    ELSE runtime_leases.owner
                END,
                acquire_nonce = CASE
                    WHEN runtime_leases.expires_at <= ? THEN excluded.acquire_nonce
                    ELSE runtime_leases.acquire_nonce
                END,
                fencing_token = CASE
                    WHEN runtime_leases.expires_at <= ? THEN runtime_leases.fencing_token + 1
                    ELSE runtime_leases.fencing_token
                END,
                expires_at = CASE
                    WHEN runtime_leases.expires_at <= ? THEN excluded.expires_at
                    ELSE runtime_leases.expires_at
                END,
                updated_at = CASE
                    WHEN runtime_leases.expires_at <= ? THEN excluded.updated_at
                    ELSE runtime_leases.updated_at
                END
            WHERE runtime_leases.expires_at <= ? OR runtime_leases.owner = excluded.owner
            RETURNING
                owner,
                expires_at AS expiresAt,
                acquire_nonce AS acquireNonce,
                fencing_token AS fencingToken
        `, [key, owner, nonce, expiresAt, now, now, now, now, now, now, now, now]);

        if (row !== null) {
            this.#assertLeaseState(row);
            return {
                acquired: true,
                replayed: row.acquireNonce !== nonce,
                expiresAt: row.expiresAt,
                fencingToken: row.fencingToken
            };
        }

        const current = await firstRow<LeaseStateRow>(this.#db, `
            SELECT expires_at AS expiresAt, fencing_token AS fencingToken
            FROM runtime_leases
            WHERE lease_key = ? AND expires_at > ?
        `, [key, now]);

        return {
            acquired: false,
            replayed: false,
            expiresAt: current?.expiresAt ?? null,
            fencingToken: current?.fencingToken ?? null
        };
    }

    async renewLease(input: RenewLeaseInput): Promise<RenewLeaseResult> {
        const key = identifier(input.key, "lease key");
        const owner = identifier(input.owner, "lease owner", 256);
        const ttlMs = positiveInteger(input.ttlMs, "lease ttlMs", MAX_TTL_MS);
        const fencingToken = positiveInteger(input.fencingToken, "lease fencingToken");
        const now = currentTime(this.#clock);
        const expiresAt = now + ttlMs;

        const row = await firstRow<LeaseStateRow>(this.#db, `
            UPDATE runtime_leases
            SET expires_at = ?, updated_at = ?
            WHERE lease_key = ?
                AND owner = ?
                AND fencing_token = ?
                AND expires_at > ?
            RETURNING expires_at AS expiresAt, fencing_token AS fencingToken
        `, [expiresAt, now, key, owner, fencingToken, now]);

        if (row !== null) {
            return { renewed: true, expiresAt: row.expiresAt, fencingToken: row.fencingToken };
        }

        const current = await firstRow<LeaseStateRow>(this.#db, `
            SELECT expires_at AS expiresAt, fencing_token AS fencingToken
            FROM runtime_leases
            WHERE lease_key = ? AND expires_at > ?
        `, [key, now]);
        return {
            renewed: false,
            expiresAt: current?.expiresAt ?? null,
            fencingToken: current?.fencingToken ?? null
        };
    }

    async releaseLease(keyValue: string, ownerValue: string, fencingTokenValue: number): Promise<boolean> {
        const key = identifier(keyValue, "lease key");
        const owner = identifier(ownerValue, "lease owner", 256);
        const fencingToken = positiveInteger(fencingTokenValue, "lease fencingToken");
        const now = currentTime(this.#clock);
        const row = await firstRow<{ released: number }>(this.#db, `
            DELETE FROM runtime_leases
            WHERE lease_key = ?
                AND owner = ?
                AND fencing_token = ?
                AND expires_at > ?
            RETURNING 1 AS released
        `, [key, owner, fencingToken, now]);
        return row !== null;
    }

    async consumeFixedWindow(input: FixedWindowInput): Promise<FixedWindowResult> {
        const key = identifier(input.key, "counter key");
        const limit = positiveInteger(input.limit, "counter limit");
        const windowMs = positiveInteger(input.windowMs, "counter windowMs", MAX_TTL_MS);
        const amount = positiveInteger(input.amount ?? 1, "counter amount");
        const now = currentTime(this.#clock);
        const windowStart = Math.floor(now / windowMs) * windowMs;
        const resetAt = windowStart + windowMs;

        if (amount > limit) {
            const current = await this.#currentCounter(key, windowStart, windowMs, now);
            const count = current?.count ?? 0;
            return { allowed: false, count, remaining: Math.max(0, limit - count), resetAt };
        }

        const row = await firstRow<CounterRow>(this.#db, `
            INSERT INTO runtime_fixed_windows (
                counter_key, window_start, window_ms, count, reset_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(counter_key) DO UPDATE SET
                window_start = excluded.window_start,
                window_ms = excluded.window_ms,
                count = CASE
                    WHEN runtime_fixed_windows.reset_at <= ?
                        OR runtime_fixed_windows.window_start <> excluded.window_start
                        OR runtime_fixed_windows.window_ms <> excluded.window_ms
                    THEN excluded.count
                    ELSE runtime_fixed_windows.count + excluded.count
                END,
                reset_at = excluded.reset_at,
                updated_at = excluded.updated_at
            WHERE runtime_fixed_windows.reset_at <= ?
                OR runtime_fixed_windows.window_start <> excluded.window_start
                OR runtime_fixed_windows.window_ms <> excluded.window_ms
                OR runtime_fixed_windows.count <= ? - excluded.count
            RETURNING count, reset_at AS resetAt
        `, [key, windowStart, windowMs, amount, resetAt, now, now, now, limit]);

        if (row !== null) {
            return {
                allowed: true,
                count: row.count,
                remaining: Math.max(0, limit - row.count),
                resetAt: row.resetAt
            };
        }

        const current = await this.#currentCounter(key, windowStart, windowMs, now);
        const count = current?.count ?? 0;
        return { allowed: false, count, remaining: Math.max(0, limit - count), resetAt };
    }

    async getFixedWindow(
        keyValue: string,
        windowMsValue: number
    ): Promise<{ count: number; resetAt: number } | null> {
        const key = identifier(keyValue, "counter key");
        const windowMs = positiveInteger(windowMsValue, "counter windowMs", MAX_TTL_MS);
        const now = currentTime(this.#clock);
        const windowStart = Math.floor(now / windowMs) * windowMs;
        return this.#currentCounter(key, windowStart, windowMs, now);
    }

    async clearFixedWindow(keyValue: string): Promise<boolean> {
        const key = identifier(keyValue, "counter key");
        const row = await firstRow<{ cleared: number }>(this.#db, `
            DELETE FROM runtime_fixed_windows
            WHERE counter_key = ?
            RETURNING 1 AS cleared
        `, [key]);
        return row !== null;
    }

    async reserve(input: ReservationInput): Promise<ReservationResult> {
        const key = identifier(input.key, "reservation key");
        const reservationId = identifier(input.reservationId, "reservation id", 256);
        const ttlMs = positiveInteger(input.ttlMs, "reservation ttlMs", MAX_TTL_MS);
        const now = currentTime(this.#clock);
        const expiresAt = now + ttlMs;
        const nonce = identifier(this.#tokenFactory(), "reservation nonce", 256);

        const row = await firstRow<ReservationRow>(this.#db, `
            INSERT INTO runtime_reservations (
                reservation_key, reservation_id, reservation_nonce, expires_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(reservation_key) DO UPDATE SET
                reservation_id = CASE
                    WHEN runtime_reservations.expires_at <= ? THEN excluded.reservation_id
                    ELSE runtime_reservations.reservation_id
                END,
                reservation_nonce = CASE
                    WHEN runtime_reservations.expires_at <= ? THEN excluded.reservation_nonce
                    ELSE runtime_reservations.reservation_nonce
                END,
                expires_at = CASE
                    WHEN runtime_reservations.expires_at <= ? THEN excluded.expires_at
                    ELSE runtime_reservations.expires_at
                END,
                updated_at = CASE
                    WHEN runtime_reservations.expires_at <= ? THEN excluded.updated_at
                    ELSE runtime_reservations.updated_at
                END
            WHERE runtime_reservations.expires_at <= ?
                OR runtime_reservations.reservation_id = excluded.reservation_id
            RETURNING
                reservation_id AS reservationId,
                expires_at AS expiresAt,
                reservation_nonce AS reservationNonce
        `, [key, reservationId, nonce, expiresAt, now, now, now, now, now, now, now]);

        if (row !== null) {
            return {
                reserved: true,
                replayed: row.reservationNonce !== nonce,
                expiresAt: row.expiresAt
            };
        }

        const current = await firstRow<ExpiryRow>(this.#db, `
            SELECT expires_at AS expiresAt
            FROM runtime_reservations
            WHERE reservation_key = ? AND expires_at > ?
        `, [key, now]);
        return { reserved: false, replayed: false, expiresAt: current?.expiresAt ?? null };
    }

    async purgeExpired(limitValue = 100): Promise<number> {
        const limit = positiveInteger(limitValue, "purge limit", 1000);
        const now = currentTime(this.#clock);
        const results = await runBatchTransaction(this.#db, [
            {
                sql: `
                    DELETE FROM runtime_leases
                    WHERE lease_key IN (
                        SELECT lease_key FROM runtime_leases WHERE expires_at <= ? LIMIT ?
                    )
                `,
                values: [now, limit]
            },
            {
                sql: `
                    DELETE FROM runtime_fixed_windows
                    WHERE counter_key IN (
                        SELECT counter_key FROM runtime_fixed_windows WHERE reset_at <= ? LIMIT ?
                    )
                `,
                values: [now, limit]
            },
            {
                sql: `
                    DELETE FROM runtime_reservations
                    WHERE reservation_key IN (
                        SELECT reservation_key FROM runtime_reservations WHERE expires_at <= ? LIMIT ?
                    )
                `,
                values: [now, limit]
            }
        ]);
        return results.reduce((sum, result) => sum + (result.meta?.changes ?? 0), 0);
    }

    async #currentCounter(
        key: string,
        windowStart: number,
        windowMs: number,
        now: number
    ): Promise<CounterRow | null> {
        return firstRow<CounterRow>(this.#db, `
            SELECT count, reset_at AS resetAt
            FROM runtime_fixed_windows
            WHERE counter_key = ?
                AND window_start = ?
                AND window_ms = ?
                AND reset_at > ?
        `, [key, windowStart, windowMs, now]);
    }

    #assertLeaseState(row: LeaseStateRow): void {
        if (!Number.isSafeInteger(row.expiresAt) || row.expiresAt < 0) {
            throw new TypeError("runtime lease contains an invalid expiry");
        }
        if (!Number.isSafeInteger(row.fencingToken) || row.fencingToken <= 0) {
            throw new TypeError("runtime lease contains an invalid fencing token");
        }
    }
}
