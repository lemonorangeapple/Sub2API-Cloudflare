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

    async getSnapshotV2(period: string): Promise<ReturnType<D1DashboardRepository["getSnapshotV2"]>> {
        return this.#repo.getSnapshotV2(period);
    }

    async getStats(period: string): Promise<ReturnType<D1DashboardRepository["getStats"]>> {
        return this.#repo.getStats(period);
    }

    async getRealtimeMetrics(): Promise<ReturnType<D1DashboardRepository["getRealtimeMetrics"]>> {
        return this.#repo.getRealtimeMetrics();
    }

    async getUsageTrend(period: string, granularity: string): Promise<ReturnType<D1DashboardRepository["getUsageTrend"]>> {
        return this.#repo.getUsageTrend(period, granularity);
    }

    async getModelStats(period: string): Promise<ReturnType<D1DashboardRepository["getModelStats"]>> {
        return this.#repo.getModelStats(period);
    }

    async getGroupStats(period: string): Promise<ReturnType<D1DashboardRepository["getGroupStats"]>> {
        return this.#repo.getGroupStats(period);
    }

    async getAPIKeyUsageTrend(apiKeyIds: number[], period: string): Promise<ReturnType<D1DashboardRepository["getAPIKeyUsageTrend"]>> {
        return this.#repo.getAPIKeyUsageTrend(apiKeyIds, period);
    }

    async getUserUsageTrend(userIds: number[], period: string): Promise<ReturnType<D1DashboardRepository["getUserUsageTrend"]>> {
        return this.#repo.getUserUsageTrend(userIds, period);
    }

    async getUserSpendingRanking(period: string, limit: number): Promise<ReturnType<D1DashboardRepository["getUserSpendingRanking"]>> {
        return this.#repo.getUserSpendingRanking(period, limit);
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