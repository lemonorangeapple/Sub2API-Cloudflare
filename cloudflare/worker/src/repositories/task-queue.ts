import type { D1Database } from "../types/d1.ts";
import {
    boundedInteger,
    boundedText,
    currentTime,
    identifier,
    jsonText,
    nonNegativeInteger,
    parseJson,
    positiveInteger,
    randomToken,
    systemClock,
    type Clock,
    type TokenFactory
} from "../utils/runtime-validation.ts";
import { firstRow, runBatchTransaction, runStatement } from "./d1.ts";

const MAX_CLAIM_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_RETRY_DELAY_MS = 30 * 24 * 60 * 60 * 1000;

type TaskStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

interface TaskQueueOptions {
    clock?: Clock;
    tokenFactory?: TokenFactory;
}

export interface EnqueueTaskInput<T> {
    queueName: string;
    payload: T;
    idempotencyKey?: string;
    priority?: number;
    availableAt?: number;
    maxAttempts?: number;
}

export interface ClaimTaskInput {
    queueName: string;
    owner: string;
    ttlMs: number;
}

export interface FailTaskInput {
    taskId: number;
    owner: string;
    claimToken: string;
    error: string;
    retryDelayMs?: number;
}

export interface FailTaskPermanentlyInput {
    taskId: number;
    owner: string;
    claimToken: string;
    error: string;
}

export interface CompleteTaskInput<T> {
    taskId: number;
    owner: string;
    claimToken: string;
    result?: T;
}

export interface RuntimeTask<T = unknown, R = unknown> {
    id: number;
    queueName: string;
    idempotencyKey: string | null;
    payload: T;
    result: R | null;
    status: TaskStatus;
    priority: number;
    availableAt: number;
    claimOwner: string | null;
    claimToken: string | null;
    claimExpiresAt: number | null;
    attempts: number;
    maxAttempts: number;
    lastError: string | null;
    createdAt: number;
    updatedAt: number;
    completedAt: number | null;
}

export interface EnqueueTaskResult<T> {
    task: RuntimeTask<T>;
    replayed: boolean;
}

export class TaskIdempotencyConflictError extends Error {
    constructor() {
        super("task idempotency key was reused with different task parameters");
        this.name = "TaskIdempotencyConflictError";
    }
}

interface TaskRow {
    id: number;
    queueName: string;
    idempotencyKey: string | null;
    payloadJson: string;
    resultJson: string | null;
    status: TaskStatus;
    priority: number;
    availableAt: number;
    claimOwner: string | null;
    claimToken: string | null;
    claimExpiresAt: number | null;
    attempts: number;
    maxAttempts: number;
    lastError: string | null;
    createdAt: number;
    updatedAt: number;
    completedAt: number | null;
}

const TASK_COLUMNS = `
    id,
    queue_name AS queueName,
    idempotency_key AS idempotencyKey,
    payload_json AS payloadJson,
    result_json AS resultJson,
    status,
    priority,
    available_at AS availableAt,
    claim_owner AS claimOwner,
    claim_token AS claimToken,
    claim_expires_at AS claimExpiresAt,
    attempts,
    max_attempts AS maxAttempts,
    last_error AS lastError,
    created_at AS createdAt,
    updated_at AS updatedAt,
    completed_at AS completedAt
`;

export class D1TaskQueueRepository {
    readonly #db: D1Database;
    readonly #clock: Clock;
    readonly #tokenFactory: TokenFactory;

    constructor(db: D1Database, options: TaskQueueOptions = {}) {
        this.#db = db;
        this.#clock = options.clock ?? systemClock;
        this.#tokenFactory = options.tokenFactory ?? randomToken;
    }

    async enqueue<T>(input: EnqueueTaskInput<T>): Promise<EnqueueTaskResult<T>> {
        const queueName = identifier(input.queueName, "queue name", 128);
        const idempotencyKey = input.idempotencyKey === undefined
            ? null
            : identifier(input.idempotencyKey, "task idempotency key");
        const payloadJson = jsonText(input.payload, "task payload");
        const priority = boundedInteger(input.priority ?? 0, "task priority");
        const maxAttempts = positiveInteger(input.maxAttempts ?? 3, "task maxAttempts", 100);
        const now = currentTime(this.#clock);
        const availableAt = input.availableAt === undefined
            ? now
            : nonNegativeInteger(input.availableAt, "task availableAt");

        const row = await firstRow<TaskRow>(this.#db, `
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
            ) VALUES (?, ?, ?, NULL, 'pending', ?, ?, NULL, NULL, NULL, 0, ?, NULL, ?, ?, NULL)
            ON CONFLICT(queue_name, idempotency_key)
                WHERE idempotency_key IS NOT NULL
                DO NOTHING
            RETURNING ${TASK_COLUMNS}
        `, [queueName, idempotencyKey, payloadJson, priority, availableAt, maxAttempts, now, now]);

        if (row !== null) {
            return { task: this.#mapTask<T>(row), replayed: false };
        }

        const existing = await firstRow<TaskRow>(this.#db, `
            SELECT ${TASK_COLUMNS}
            FROM runtime_tasks
            WHERE queue_name = ? AND idempotency_key = ?
        `, [queueName, idempotencyKey]);
        if (existing === null) {
            throw new Error("idempotent task insert lost its existing row");
        }
        if (
            existing.payloadJson !== payloadJson
            || existing.priority !== priority
            || existing.maxAttempts !== maxAttempts
        ) {
            throw new TaskIdempotencyConflictError();
        }
        return { task: this.#mapTask<T>(existing), replayed: true };
    }

    async claimNext<T>(input: ClaimTaskInput): Promise<RuntimeTask<T> | null> {
        const queueName = identifier(input.queueName, "queue name", 128);
        const owner = identifier(input.owner, "claim owner", 256);
        const ttlMs = positiveInteger(input.ttlMs, "claim ttlMs", MAX_CLAIM_TTL_MS);
        const now = currentTime(this.#clock);
        const claimExpiresAt = now + ttlMs;
        const claimToken = identifier(this.#tokenFactory(), "claim token", 256);

        const results = await runBatchTransaction(this.#db, [
            {
                sql: `
                    UPDATE runtime_tasks
                    SET
                        status = 'failed',
                        claim_owner = NULL,
                        claim_token = NULL,
                        claim_expires_at = NULL,
                        last_error = COALESCE(last_error, 'claim expired after maximum attempts'),
                        updated_at = ?,
                        completed_at = ?
                    WHERE queue_name = ?
                        AND status = 'running'
                        AND claim_expires_at <= ?
                        AND attempts >= max_attempts
                `,
                values: [now, now, queueName, now]
            },
            {
                sql: `
                    UPDATE runtime_tasks
                    SET
                        status = 'running',
                        claim_owner = ?,
                        claim_token = ?,
                        claim_expires_at = ?,
                        attempts = attempts + 1,
                        updated_at = ?
                    WHERE id = (
                        SELECT id
                        FROM runtime_tasks
                        WHERE queue_name = ?
                            AND available_at <= ?
                            AND attempts < max_attempts
                            AND (
                                status = 'pending'
                                OR (status = 'running' AND claim_expires_at <= ?)
                            )
                        ORDER BY priority DESC, available_at, id
                        LIMIT 1
                    )
                    RETURNING ${TASK_COLUMNS}
                `,
                values: [owner, claimToken, claimExpiresAt, now, queueName, now, now]
            }
        ]);
        const row = (results[1]?.results?.[0] ?? null) as TaskRow | null;
        return row === null ? null : this.#mapTask<T>(row);
    }

    async complete<T>(input: CompleteTaskInput<T>): Promise<boolean> {
        const taskId = positiveInteger(input.taskId, "task id");
        const owner = identifier(input.owner, "claim owner", 256);
        const claimToken = identifier(input.claimToken, "claim token", 256);
        const resultJson = input.result === undefined ? null : jsonText(input.result, "task result");
        const now = currentTime(this.#clock);

        const row = await firstRow<{ id: number }>(this.#db, `
            UPDATE runtime_tasks
            SET
                status = 'completed',
                result_json = ?,
                claim_owner = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                updated_at = ?,
                completed_at = ?
            WHERE id = ?
                AND status = 'running'
                AND claim_owner = ?
                AND claim_token = ?
                AND claim_expires_at > ?
            RETURNING id
        `, [resultJson, now, now, taskId, owner, claimToken, now]);
        return row !== null;
    }

    async fail(input: FailTaskInput): Promise<TaskStatus | null> {
        const taskId = positiveInteger(input.taskId, "task id");
        const owner = identifier(input.owner, "claim owner", 256);
        const claimToken = identifier(input.claimToken, "claim token", 256);
        const error = boundedText(input.error, "task error");
        const retryDelayMs = nonNegativeInteger(input.retryDelayMs ?? 0, "task retryDelayMs");
        if (retryDelayMs > MAX_RETRY_DELAY_MS) {
            throw new RangeError(`task retryDelayMs must be no greater than ${MAX_RETRY_DELAY_MS}`);
        }
        const now = currentTime(this.#clock);
        const retryAt = now + retryDelayMs;

        const row = await firstRow<{ status: TaskStatus }>(this.#db, `
            UPDATE runtime_tasks
            SET
                status = CASE WHEN attempts < max_attempts THEN 'pending' ELSE 'failed' END,
                available_at = CASE WHEN attempts < max_attempts THEN ? ELSE available_at END,
                claim_owner = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                last_error = ?,
                updated_at = ?,
                completed_at = CASE WHEN attempts < max_attempts THEN NULL ELSE ? END
            WHERE id = ?
                AND status = 'running'
                AND claim_owner = ?
                AND claim_token = ?
                AND claim_expires_at > ?
            RETURNING status
        `, [retryAt, error, now, now, taskId, owner, claimToken, now]);
        return row?.status ?? null;
    }

    async failPermanently(input: FailTaskPermanentlyInput): Promise<boolean> {
        const taskId = positiveInteger(input.taskId, "task id");
        const owner = identifier(input.owner, "claim owner", 256);
        const claimToken = identifier(input.claimToken, "claim token", 256);
        const error = boundedText(input.error, "task error");
        const now = currentTime(this.#clock);

        const row = await firstRow<{ id: number }>(this.#db, `
            UPDATE runtime_tasks
            SET
                status = 'failed',
                claim_owner = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                last_error = ?,
                updated_at = ?,
                completed_at = ?
            WHERE id = ?
                AND status = 'running'
                AND claim_owner = ?
                AND claim_token = ?
                AND claim_expires_at > ?
            RETURNING id
        `, [error, now, now, taskId, owner, claimToken, now]);
        return row !== null;
    }

    async cancel(taskIdValue: number): Promise<boolean> {
        const taskId = positiveInteger(taskIdValue, "task id");
        const now = currentTime(this.#clock);
        const row = await firstRow<{ id: number }>(this.#db, `
            UPDATE runtime_tasks
            SET
                status = 'cancelled',
                claim_owner = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                updated_at = ?,
                completed_at = ?
            WHERE id = ? AND status IN ('pending', 'running')
            RETURNING id
        `, [now, now, taskId]);
        return row !== null;
    }

    async get<T, R = unknown>(taskIdValue: number): Promise<RuntimeTask<T, R> | null> {
        const taskId = positiveInteger(taskIdValue, "task id");
        const row = await firstRow<TaskRow>(this.#db, `
            SELECT ${TASK_COLUMNS}
            FROM runtime_tasks
            WHERE id = ?
        `, [taskId]);
        return row === null ? null : this.#mapTask<T, R>(row);
    }

    async purgeTerminal(beforeValue: number, limitValue = 100): Promise<number> {
        const before = nonNegativeInteger(beforeValue, "purge before");
        const limit = positiveInteger(limitValue, "purge limit", 1000);
        const result = await runStatement(this.#db, `
            DELETE FROM runtime_tasks
            WHERE id IN (
                SELECT id
                FROM runtime_tasks
                WHERE status IN ('completed', 'failed', 'cancelled')
                    AND updated_at <= ?
                ORDER BY updated_at, id
                LIMIT ?
            )
        `, [before, limit]);
        return result.meta?.changes ?? 0;
    }

    #mapTask<T, R = unknown>(row: TaskRow): RuntimeTask<T, R> {
        return {
            id: row.id,
            queueName: row.queueName,
            idempotencyKey: row.idempotencyKey,
            payload: parseJson<T>(row.payloadJson, "task payload"),
            result: row.resultJson === null ? null : parseJson<R>(row.resultJson, "task result"),
            status: row.status,
            priority: row.priority,
            availableAt: row.availableAt,
            claimOwner: row.claimOwner,
            claimToken: row.claimToken,
            claimExpiresAt: row.claimExpiresAt,
            attempts: row.attempts,
            maxAttempts: row.maxAttempts,
            lastError: row.lastError,
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
            completedAt: row.completedAt
        };
    }
}
