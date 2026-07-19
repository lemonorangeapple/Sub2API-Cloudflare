import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface ScheduledTestPlanRecord {
    id: number;
    accountId: number;
    modelId: string;
    cronExpression: string;
    enabled: boolean;
    maxResults: number;
    autoRecover: boolean;
    lastRunAt: string | null;
    nextRunAt: string | null;
    createdAt: string;
    updatedAt: string;
}

export interface ScheduledTestResultRecord {
    id: number;
    planId: number;
    status: string;
    responseText: string;
    errorMessage: string;
    latencyMs: number;
    startedAt: string;
    finishedAt: string;
    createdAt: string;
}

interface PlanRow {
    id: number;
    account_id: number;
    model_id: string;
    cron_expression: string;
    enabled: number;
    max_results: number;
    auto_recover: number;
    last_run_at: string | null;
    next_run_at: string | null;
    created_at: string;
    updated_at: string;
}

interface ResultRow {
    id: number;
    plan_id: number;
    status: string;
    response_text: string;
    error_message: string;
    latency_ms: number;
    started_at: string;
    finished_at: string;
    created_at: string;
}

function planRowToRecord(row: PlanRow): ScheduledTestPlanRecord {
    return {
        id: row.id,
        accountId: row.account_id,
        modelId: row.model_id,
        cronExpression: row.cron_expression,
        enabled: row.enabled === 1,
        maxResults: row.max_results,
        autoRecover: row.auto_recover === 1,
        lastRunAt: row.last_run_at,
        nextRunAt: row.next_run_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

function resultRowToRecord(row: ResultRow): ScheduledTestResultRecord {
    return {
        id: row.id,
        planId: row.plan_id,
        status: row.status,
        responseText: row.response_text,
        errorMessage: row.error_message,
        latencyMs: row.latency_ms,
        startedAt: row.started_at,
        finishedAt: row.finished_at,
        createdAt: row.created_at,
    };
}

export interface CreatePlanInput {
    accountId: number;
    modelId?: string;
    cronExpression: string;
    enabled?: boolean;
    maxResults?: number;
    autoRecover?: boolean;
}

export interface UpdatePlanInput {
    modelId?: string;
    cronExpression?: string;
    enabled?: boolean;
    maxResults?: number;
    autoRecover?: boolean;
}

export class D1ScheduledTestPlanRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async findById(id: number): Promise<ScheduledTestPlanRecord | null> {
        const row = await firstRow<PlanRow>(
            this.#db,
            "SELECT * FROM scheduled_test_plans WHERE id = ?",
            [id]
        );
        return row === null ? null : planRowToRecord(row);
    }

    async listByAccountId(accountId: number): Promise<ScheduledTestPlanRecord[]> {
        const rows = await allRows<PlanRow>(
            this.#db,
            "SELECT * FROM scheduled_test_plans WHERE account_id = ? ORDER BY created_at DESC",
            [accountId]
        );
        return rows.map(planRowToRecord);
    }

    async create(input: CreatePlanInput, nextRunAt: string | null): Promise<ScheduledTestPlanRecord> {
        const now = new Date().toISOString();
        const enabled = input.enabled ?? true;
        const maxResults = input.maxResults ?? 50;
        const autoRecover = input.autoRecover ?? false;

        const result = await runStatement(
            this.#db,
            `INSERT INTO scheduled_test_plans (
                account_id, model_id, cron_expression, enabled, max_results,
                auto_recover, next_run_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                input.accountId,
                input.modelId ?? "",
                input.cronExpression,
                enabled ? 1 : 0,
                maxResults,
                autoRecover ? 1 : 0,
                nextRunAt,
                now, now,
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findById(id))!;
    }

    async update(id: number, input: UpdatePlanInput, nextRunAt: string | null): Promise<ScheduledTestPlanRecord | null> {
        const existing = await this.findById(id);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.modelId !== undefined) { sets.push("model_id = ?"); values.push(input.modelId); }
        if (input.cronExpression !== undefined) { sets.push("cron_expression = ?"); values.push(input.cronExpression); }
        if (input.enabled !== undefined) { sets.push("enabled = ?"); values.push(input.enabled ? 1 : 0); }
        if (input.maxResults !== undefined) { sets.push("max_results = ?"); values.push(input.maxResults); }
        if (input.autoRecover !== undefined) { sets.push("auto_recover = ?"); values.push(input.autoRecover ? 1 : 0); }
        if (nextRunAt !== undefined) { sets.push("next_run_at = ?"); values.push(nextRunAt); }

        if (sets.length === 1) return existing;

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE scheduled_test_plans SET ${sets.join(", ")} WHERE id = ?`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(
            this.#db,
            "DELETE FROM scheduled_test_plans WHERE id = ?",
            [id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async listResults(planId: number, limit: number): Promise<ScheduledTestResultRecord[]> {
        const rows = await allRows<ResultRow>(
            this.#db,
            "SELECT * FROM scheduled_test_results WHERE plan_id = ? ORDER BY created_at DESC LIMIT ?",
            [planId, limit]
        );
        return rows.map(resultRowToRecord);
    }
}
