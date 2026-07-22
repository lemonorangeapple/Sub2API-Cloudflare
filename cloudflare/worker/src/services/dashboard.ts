import { D1DashboardRepositoryImpl, type D1DashboardRepository } from "../repositories/dashboard.ts";

export class DashboardError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "DashboardError";
        this.status = status;
        this.code = code;
    }
}

export class D1DashboardService {
    readonly #repo: D1DashboardRepository;

    constructor(repo: D1DashboardRepository) {
        this.#repo = repo;
    }

    async getStats(period: string, startDate?: string, endDate?: string): Promise<ReturnType<D1DashboardRepository["getStats"]>> {
        return this.#repo.getStats(period, startDate, endDate);
    }

    async getRealtimeMetrics(): Promise<ReturnType<D1DashboardRepository["getRealtimeMetrics"]>> {
        return this.#repo.getRealtimeMetrics();
    }

    async getUsageTrend(period: string, granularity: string, startDate?: string, endDate?: string): Promise<ReturnType<D1DashboardRepository["getUsageTrend"]>> {
        return this.#repo.getUsageTrend(period, granularity, startDate, endDate);
    }

    async getModelStats(period: string, startDate?: string, endDate?: string): Promise<ReturnType<D1DashboardRepository["getModelStats"]>> {
        return this.#repo.getModelStats(period, startDate, endDate);
    }

    async getGroupStats(period: string, startDate?: string, endDate?: string): Promise<ReturnType<D1DashboardRepository["getGroupStats"]>> {
        return this.#repo.getGroupStats(period, startDate, endDate);
    }

    async getAPIKeyUsageTrend(apiKeyIds: number[], period: string): Promise<ReturnType<D1DashboardRepository["getAPIKeyUsageTrend"]>> {
        return this.#repo.getAPIKeyUsageTrend(apiKeyIds, period);
    }

    async getUserUsageTrend(startDate: string, endDate: string, granularity: string, limit: number): Promise<ReturnType<D1DashboardRepository["getUserUsageTrend"]>> {
        return this.#repo.getUserUsageTrend(startDate, endDate, granularity, limit);
    }

    async getUserSpendingRanking(period: string, limit: number, startDate?: string, endDate?: string): Promise<ReturnType<D1DashboardRepository["getUserSpendingRanking"]>> {
        return this.#repo.getUserSpendingRanking(period, limit, startDate, endDate);
    }

    async getBatchUsersUsage(userIds: number[], period: string): Promise<ReturnType<D1DashboardRepository["getBatchUsersUsage"]>> {
        return this.#repo.getBatchUsersUsage(userIds, period);
    }

    async getBatchAPIKeysUsage(apiKeyIds: number[], period: string): Promise<ReturnType<D1DashboardRepository["getBatchAPIKeysUsage"]>> {
        return this.#repo.getBatchAPIKeysUsage(apiKeyIds, period);
    }

    async getUserBreakdown(userId: number, period: string): Promise<ReturnType<D1DashboardRepository["getUserBreakdown"]>> {
        return this.#repo.getUserBreakdown(userId, period);
    }

    async backfillAggregation(from: string, to: string): Promise<ReturnType<D1DashboardRepository["backfillAggregation"]>> {
        return this.#repo.backfillAggregation(from, to);
    }
}
