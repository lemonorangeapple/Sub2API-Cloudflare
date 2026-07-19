import type { D1ScheduledTestPlanRepository, ScheduledTestPlanRecord, ScheduledTestResultRecord, CreatePlanInput, UpdatePlanInput } from "../repositories/scheduled-test-plans.ts";

export class ScheduledTestError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "ScheduledTestError";
        this.code = code;
        this.status = status;
    }
}

const CRON_5FIELD_RE = /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$/;

function validateCronExpression(expr: string): void {
    if (!CRON_5FIELD_RE.test(expr)) {
        throw new ScheduledTestError("invalid_cron", 400, "Invalid cron expression: must be 5 fields (minute hour dom month dow)");
    }
}

export class D1ScheduledTestPlanService {
    readonly #repo: D1ScheduledTestPlanRepository;

    constructor(repo: D1ScheduledTestPlanRepository) {
        this.#repo = repo;
    }

    async getById(id: number): Promise<ScheduledTestPlanRecord> {
        const plan = await this.#repo.findById(id);
        if (plan === null) throw new ScheduledTestError("plan_not_found", 404, "Plan not found");
        return plan;
    }

    async listByAccountId(accountId: number): Promise<ScheduledTestPlanRecord[]> {
        return this.#repo.listByAccountId(accountId);
    }

    async create(input: CreatePlanInput): Promise<ScheduledTestPlanRecord> {
        if (!input.cronExpression || input.cronExpression.trim().length === 0) {
            throw new ScheduledTestError("cron_required", 400, "cron_expression is required");
        }
        validateCronExpression(input.cronExpression.trim());
        const maxResults = (input.maxResults ?? 50) <= 0 ? 50 : input.maxResults!;
        return this.#repo.create({ ...input, cronExpression: input.cronExpression.trim(), maxResults }, null);
    }

    async update(id: number, input: UpdatePlanInput): Promise<ScheduledTestPlanRecord> {
        const existing = await this.#repo.findById(id);
        if (existing === null) throw new ScheduledTestError("plan_not_found", 404, "Plan not found");

        const merged = {
            modelId: input.modelId ?? existing.modelId,
            cronExpression: input.cronExpression ?? existing.cronExpression,
            enabled: input.enabled ?? existing.enabled,
            maxResults: input.maxResults ?? existing.maxResults,
            autoRecover: input.autoRecover ?? existing.autoRecover,
        };

        if (merged.cronExpression.trim().length > 0) {
            validateCronExpression(merged.cronExpression.trim());
        }

        const updated = await this.#repo.update(id, {
            ...input,
            cronExpression: input.cronExpression?.trim(),
        }, null);
        return updated!;
    }

    async delete(id: number): Promise<void> {
        const deleted = await this.#repo.delete(id);
        if (!deleted) throw new ScheduledTestError("plan_not_found", 404, "Plan not found");
    }

    async listResults(planId: number, limit: number): Promise<ScheduledTestResultRecord[]> {
        await this.getById(planId);
        return this.#repo.listResults(planId, limit <= 0 ? 50 : limit);
    }
}
