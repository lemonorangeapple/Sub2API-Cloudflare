import type { D1Database } from "../types/d1.ts";
import { firstRow, prepareStatement, requireSuccess, runStatement } from "./d1.ts";

export interface CreateRefreshSessionInput {
    tokenHash: string;
    userId: number;
    tokenVersion: bigint;
    familyId: string;
    createdAt: number;
    expiresAt: number;
}

export interface RotateRefreshSessionInput extends CreateRefreshSessionInput {
    sourceHash: string;
    rotatedAt: number;
}

export interface StoredRefreshSession {
    tokenHash: string;
    userId: number;
    tokenVersion: bigint;
    familyId: string;
    createdAt: number;
    expiresAt: number;
    rotatedAt: number | null;
    revokedAt: number | null;
    replacedByHash: string | null;
}

interface RefreshSessionRow {
    tokenHash: string;
    userId: number;
    tokenVersion: string;
    familyId: string;
    createdAt: number;
    expiresAt: number;
    rotatedAt: number | null;
    revokedAt: number | null;
    replacedByHash: string | null;
}

export class D1AuthSessionRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async create(input: CreateRefreshSessionInput): Promise<void> {
        await runStatement(this.#db, `
            INSERT INTO auth_refresh_sessions (
                token_hash,
                user_id,
                token_version,
                family_id,
                created_at,
                expires_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        `, [
            input.tokenHash,
            input.userId,
            input.tokenVersion.toString(),
            input.familyId,
            input.createdAt,
            input.expiresAt
        ]);
    }

    async get(tokenHash: string): Promise<StoredRefreshSession | null> {
        const row = await firstRow<RefreshSessionRow>(this.#db, `
            SELECT
                token_hash AS tokenHash,
                user_id AS userId,
                token_version AS tokenVersion,
                family_id AS familyId,
                created_at AS createdAt,
                expires_at AS expiresAt,
                rotated_at AS rotatedAt,
                revoked_at AS revokedAt,
                replaced_by_hash AS replacedByHash
            FROM auth_refresh_sessions
            WHERE token_hash = ?
        `, [tokenHash]);
        return row === null ? null : mapSession(row);
    }

    async rotateActive(input: RotateRefreshSessionInput): Promise<boolean> {
        const insert = prepareStatement(this.#db, `
            INSERT INTO auth_refresh_sessions (
                token_hash,
                user_id,
                token_version,
                family_id,
                created_at,
                expires_at
            )
            SELECT ?, source.user_id, ?, source.family_id, ?, ?
            FROM auth_refresh_sessions AS source
            WHERE source.token_hash = ?
                AND source.user_id = ?
                AND source.family_id = ?
                AND source.expires_at > ?
                AND source.rotated_at IS NULL
                AND source.revoked_at IS NULL
        `, [
            input.tokenHash,
            input.tokenVersion.toString(),
            input.createdAt,
            input.expiresAt,
            input.sourceHash,
            input.userId,
            input.familyId,
            input.rotatedAt
        ]);
        const markRotated = prepareStatement(this.#db, `
            UPDATE auth_refresh_sessions
            SET rotated_at = ?, replaced_by_hash = ?
            WHERE token_hash = ?
                AND user_id = ?
                AND family_id = ?
                AND expires_at > ?
                AND rotated_at IS NULL
                AND revoked_at IS NULL
                AND EXISTS (
                    SELECT 1
                    FROM auth_refresh_sessions AS replacement
                    WHERE replacement.token_hash = ?
                        AND replacement.user_id = auth_refresh_sessions.user_id
                        AND replacement.family_id = auth_refresh_sessions.family_id
                )
        `, [
            input.rotatedAt,
            input.tokenHash,
            input.sourceHash,
            input.userId,
            input.familyId,
            input.rotatedAt,
            input.tokenHash
        ]);

        const results = await this.#db.batch([insert, markRotated]);
        results.forEach((result, index) => requireSuccess(result, `refresh rotation statement ${index + 1} failed`));
        const inserted = results[0].meta?.changes ?? 0;
        const rotated = results[1].meta?.changes ?? 0;
        if (inserted === 0 && rotated === 0) {
            return false;
        }
        if (inserted !== 1 || rotated !== 1) {
            throw new Error(`inconsistent refresh rotation result: inserted=${inserted}, rotated=${rotated}`);
        }
        return true;
    }

    async revokeToken(tokenHash: string, now: number): Promise<boolean> {
        const result = await runStatement(this.#db, `
            UPDATE auth_refresh_sessions
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE token_hash = ?
        `, [now, tokenHash]);
        return (result.meta?.changes ?? 0) > 0;
    }

    async revokeFamily(familyId: string, now: number): Promise<number> {
        const result = await runStatement(this.#db, `
            UPDATE auth_refresh_sessions
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE family_id = ? AND revoked_at IS NULL
        `, [now, familyId]);
        return result.meta?.changes ?? 0;
    }

    async revokeUser(userId: number, now: number): Promise<number> {
        const result = await runStatement(this.#db, `
            UPDATE auth_refresh_sessions
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE user_id = ? AND revoked_at IS NULL
        `, [now, userId]);
        return result.meta?.changes ?? 0;
    }

    async purgeExpired(before: number, limit = 500): Promise<number> {
        const result = await runStatement(this.#db, `
            DELETE FROM auth_refresh_sessions
            WHERE id IN (
                SELECT id
                FROM auth_refresh_sessions
                WHERE expires_at <= ?
                ORDER BY expires_at, id
                LIMIT ?
            )
        `, [before, limit]);
        return result.meta?.changes ?? 0;
    }
}

function mapSession(row: RefreshSessionRow): StoredRefreshSession {
    return {
        tokenHash: row.tokenHash,
        userId: row.userId,
        tokenVersion: BigInt(row.tokenVersion),
        familyId: row.familyId,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
        rotatedAt: row.rotatedAt,
        revokedAt: row.revokedAt,
        replacedByHash: row.replacedByHash
    };
}
