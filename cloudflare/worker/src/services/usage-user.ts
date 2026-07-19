import type { D1UsageUserRepository, UsageLogRow, UsageStatsResult, TrendPoint, ModelStat, ErrorLogRow, ErrorDetailRow, PlatformQuotaRow } from "../repositories/usage-user.ts";

export class UsageUserError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "UsageUserError";
        this.status = status;
        this.code = code;
    }
}

export class D1UsageUserService {
    readonly #repo: D1UsageUserRepository;

    constructor(repo: D1UsageUserRepository) {
        this.#repo = repo;
    }

    async listUsage(
        userId: number,
        page: number,
        pageSize: number,
        filters: { apiKeyId?: number; groupId?: number; model?: string; startDate?: string; endDate?: string; sortBy?: string; sortOrder?: string }
    ): Promise<{ items: UsageLogRow[]; total: number; page: number; pageSize: number }> {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        const p = Math.max(1, page);
        const ps = Math.min(100, Math.max(1, pageSize));
        const result = await this.#repo.listUsage(userId, p, ps, filters);
        return { ...result, page: p, pageSize: ps };
    }

    async getUsageById(userId: number, id: number): Promise<UsageLogRow> {
        if (id <= 0) throw new UsageUserError(400, "INVALID_ID", "id must be positive");
        const row = await this.#repo.getUsageById(userId, id);
        if (row === null) throw new UsageUserError(404, "NOT_FOUND", "usage record not found");
        return row;
    }

    async getStats(userId: number, startDate?: string, endDate?: string): Promise<UsageStatsResult> {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        const result = await this.#repo.getStats(userId, startDate, endDate);
        if (result === null) {
            return { totalRequests: 0, totalInputTokens: 0, totalOutputTokens: 0, totalCacheCreationTokens: 0, totalCacheReadTokens: 0, totalTokens: 0, totalCost: 0, totalActualCost: 0, averageDurationMs: 0 };
        }
        return result;
    }

    async getDashboardStats(userId: number) {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        return this.#repo.getDashboardStats(userId);
    }

    async getTrend(userId: number, startDate: string, endDate: string, granularity: string): Promise<TrendPoint[]> {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        if (granularity !== "hour" && granularity !== "day") throw new UsageUserError(400, "INVALID_GRANULARITY", "granularity must be hour or day");
        return this.#repo.getTrend(userId, startDate, endDate, granularity);
    }

    async getModelStats(userId: number, startDate?: string, endDate?: string): Promise<ModelStat[]> {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        return this.#repo.getModelStats(userId, startDate, endDate);
    }

    async getAPIKeyDailyUsage(userId: number, apiKeyId: number, days: number): Promise<{ date: string; requests: number; inputTokens: number; outputTokens: number; totalTokens: number; cost: number; actualCost: number }[]> {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        if (apiKeyId <= 0) throw new UsageUserError(400, "INVALID_API_KEY_ID", "api_key_id must be positive");
        const owned = await this.#repo.verifyAPIKeyOwnership(userId, apiKeyId);
        if (!owned) throw new UsageUserError(404, "API_KEY_NOT_FOUND", "API key not found or not owned by user");
        const d = Math.max(1, Math.min(365, days));
        return this.#repo.getAPIKeyDailyUsage(userId, apiKeyId, d);
    }

    async getSnapshotV2(userId: number, startDate: string, endDate: string): Promise<{
        trend: TrendPoint[];
        modelStats: ModelStat[];
    }> {
        const [trend, modelStats] = await Promise.all([
            this.#repo.getTrend(userId, startDate, endDate, "day"),
            this.#repo.getModelStats(userId, startDate, endDate),
        ]);
        return { trend, modelStats };
    }

    async listErrors(
        userId: number,
        page: number,
        pageSize: number,
        filters: { model?: string; apiKeyId?: number; startDate?: string; endDate?: string }
    ): Promise<{ items: ErrorLogRow[]; total: number; page: number; pageSize: number }> {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        const p = Math.max(1, page);
        const ps = Math.min(100, Math.max(1, pageSize));
        const result = await this.#repo.listErrors(userId, p, ps, filters);
        return { ...result, page: p, pageSize: ps };
    }

    async getErrorDetail(userId: number, id: number): Promise<ErrorDetailRow> {
        if (id <= 0) throw new UsageUserError(400, "INVALID_ID", "id must be positive");
        const row = await this.#repo.getErrorDetail(userId, id);
        if (row === null) throw new UsageUserError(404, "NOT_FOUND", "error record not found");
        return row;
    }

    async getPlatformQuotas(userId: number): Promise<PlatformQuotaRow[]> {
        if (userId <= 0) throw new UsageUserError(400, "INVALID_USER_ID", "user_id must be positive");
        return this.#repo.listPlatformQuotas(userId);
    }
}
