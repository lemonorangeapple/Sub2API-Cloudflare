import type { D1Database, D1Result } from "../types/d1.ts";
import { prepareStatement, requireSuccess } from "./d1.ts";

export interface AuthEmailStateMutation {
    stateKey: string;
    stateJson: string;
    expiresAt: number;
    now: number;
    cooldownBefore: number;
    idempotencyKey: string;
    payloadJson: string;
    priority?: number;
    maxAttempts?: number;
}

export class EmailCooldownError extends Error {
    constructor() {
        super("email request is still in its cooldown window");
        this.name = "EmailCooldownError";
    }
}

export class D1AuthEmailRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async createTask(input: AuthEmailStateMutation): Promise<number> {
        const priority = input.priority ?? 0;
        const maxAttempts = input.maxAttempts ?? 3;
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                INSERT INTO runtime_expiring_values (
                    state_key, value_json, expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(state_key) DO UPDATE SET
                    value_json = excluded.value_json,
                    expires_at = excluded.expires_at,
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at
                WHERE runtime_expiring_values.expires_at <= ?
                    OR runtime_expiring_values.updated_at <= ?
                RETURNING state_key
            `, [
                input.stateKey,
                input.stateJson,
                input.expiresAt,
                input.now,
                input.now,
                input.now,
                input.cooldownBefore
            ]),
            prepareStatement(this.#db, `
                INSERT INTO runtime_tasks (
                    queue_name,
                    idempotency_key,
                    payload_json,
                    result_json,
                    status,
                    priority,
                    available_at,
                    claim_owner,
                    claim_token,
                    claim_expires_at,
                    attempts,
                    max_attempts,
                    last_error,
                    created_at,
                    updated_at,
                    completed_at
                )
                SELECT
                    'email', ?, ?, NULL, 'pending', ?, ?, NULL, NULL, NULL, 0, ?, NULL, ?, ?, NULL
                WHERE EXISTS (
                    SELECT 1
                    FROM runtime_expiring_values
                    WHERE state_key = ?
                        AND value_json = ?
                        AND updated_at = ?
                        AND expires_at = ?
                )
                RETURNING id
            `, [
                input.idempotencyKey,
                input.payloadJson,
                priority,
                input.now,
                maxAttempts,
                input.now,
                input.now,
                input.stateKey,
                input.stateJson,
                input.now,
                input.expiresAt
            ])
        ]);
        requireBatchSuccess(results, "create authentication email task");
        const stateChanged = results[0]?.results?.length ?? 0;
        const task = results[1]?.results?.[0] as { id?: number } | undefined;
        if (stateChanged === 0 && task === undefined) {
            throw new EmailCooldownError();
        }
        if (stateChanged !== 1 || !Number.isSafeInteger(task?.id) || (task?.id ?? 0) <= 0) {
            throw new Error("authentication email state and task were not created atomically");
        }
        return task?.id as number;
    }
}

function requireBatchSuccess(results: D1Result[], operation: string): void {
    results.forEach((result, index) => {
        requireSuccess(result, `${operation} statement ${index + 1} failed`);
    });
}
