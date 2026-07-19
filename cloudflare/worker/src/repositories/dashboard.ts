import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface DashboardSnapshot {
    totalRequests: number;
    totalCost: number;
    actualCost: number;
    activeUsers: number;
    activeAPIKeys: number;
    activeAccounts: number;
    avgLatencyMs: number;
    errorRate: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    topModels: Array<{ model: string; requests: number; cost: number }>;
    topGroups: Array<{ groupId: number; groupName: string; requests: number; cost: number }>;
    topUsers: Array<{ userId: number; username: string; requests: number; cost: number }>;
    topAPIKeys: Array<{ apiKeyId: number; keyName: string; requests: number; cost: number }>;
}

export interface DashboardStats {
    totalRequests: number;
    totalTokens: number;
    totalCost: number;
    activeUsers: number;
    activeAPIKeys: number;
    activeAccounts: number;
    errorRate: number;
    avgLatencyMs: number;
}

export interface RealtimeMetrics {
    qps: number;
    tps: number;
    concurrentUsers: number;
    activeRequests: number;
    latencyP50: number;
    latencyP95: number;
    latencyP99: number;
    errorRate: number;
    modelDistribution: Record<string, number>;
}

export interface UsageTrendPoint {
    bucket: string;
    requests: number;
    inputTokens: number;
    outputTokens: number;
    cacheCreationTokens: number;
    cacheReadTokens: number;
    totalCost: number;
    actualCost: number;
    avgLatencyMs: number;
    errorRate: number;
    activeUsers: number;
}

export interface ModelStats {
    model: string;
    requests: number;
    inputTokens: number;
    outputTokens: number;
    cacheCreationTokens: number;
    cacheReadTokens: number;
    totalCost: number;
    actualCost: number;
    avgLatencyMs: number;
    errorRate: number;
}

export interface GroupStats {
    groupId: number;
    groupName: string;
    requests: number;
    cost: number;
    activeUsers: number;
    activeAPIKeys: number;
}

interface DashboardAggregationRow {
    total_requests: number;
    input_tokens: number;
    output_tokens: number;
    cache_creation_tokens: number;
    cache_read_tokens: number;
    total_cost: number;
    actual_cost: number;
    total_duration_ms: number;
}

export interface APIKeyUsageTrend {
    apiKeyId: number;
    keyName: string;
    trend: UsageTrendPoint[];
}

export interface UserUsageTrend {
    userId: number;
    username: string;
    trend: UsageTrendPoint[];
}

export interface UserSpendingRanking {
    userId: number;
    username: string;
    email: string;
    totalCost: number;
    totalRequests: number;
    totalTokens: number;
}

export interface BatchUsageResult {
    userId: number;
    username: string;
    requests: number;
    cost: number;
    tokens: number;
}

export interface UserBreakdown {
    userId: number;
    username: string;
    email: string;
    requests: number;
    cost: number;
    tokens: number;
    models: Record<string, number>;
    groups: Record<string, number>;
}

export interface D1DashboardRepository {
    getSnapshotV2(period: string): Promise<DashboardSnapshot>;
    getStats(period: string): Promise<DashboardStats>;
    getRealtimeMetrics(): Promise<RealtimeMetrics>;
    getUsageTrend(period: string, granularity: string): Promise<UsageTrendPoint[]>;
    getModelStats(period: string): Promise<ModelStats[]>;
    getGroupStats(period: string): Promise<GroupStats[]>;
    getAPIKeyUsageTrend(apiKeyIds: number[], period: string): Promise<APIKeyUsageTrend[]>;
    getUserUsageTrend(userIds: number[], period: string): Promise<UserUsageTrend[]>;
    getUserSpendingRanking(period: string, limit: number): Promise<UserSpendingRanking[]>;
    getBatchUsersUsage(userIds: number[], period: string): Promise<BatchUsageResult[]>;
    getBatchAPIKeysUsage(apiKeyIds: number[], period: string): Promise<BatchUsageResult[]>;
    getUserBreakdown(userId: number, period: string): Promise<UserBreakdown>;
    backfillAggregation(from: string, to: string): Promise<{ processed: number }>;
}

export class D1DashboardRepositoryImpl implements D1DashboardRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    private parsePeriod(period: string): { start: string; end: string } {
        const now = new Date();
        let start: Date;
        switch (period) {
            case "hour":
                start = new Date(now.getTime() - 60 * 60 * 1000);
                break;
            case "day":
                start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                break;
            case "week":
                start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                break;
            case "month":
                start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                break;
            case "quarter":
                start = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
                break;
            case "year":
                start = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
                break;
            default:
                start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        }
        return { start: start.toISOString(), end: now.toISOString() };
    }

    async getSnapshotV2(period: string): Promise<DashboardSnapshot> {
        const { start, end } = this.parsePeriod(period);
        const hourly = await this.getHourlyAggregation(start, end);
        const daily = await this.getDailyAggregation(start, end);

        const totalRequests = hourly.reduce((sum, h) => sum + h.total_requests, 0) +
            daily.reduce((sum, d) => sum + d.total_requests, 0);
        const totalCost = hourly.reduce((sum, h) => sum + h.total_cost, 0) +
            daily.reduce((sum, d) => sum + d.total_cost, 0);
        const actualCost = hourly.reduce((sum, h) => sum + h.actual_cost, 0) +
            daily.reduce((sum, d) => sum + d.actual_cost, 0);
        const totalDuration = hourly.reduce((sum, h) => sum + h.total_duration_ms, 0) +
            daily.reduce((sum, d) => sum + d.total_duration_ms, 0);
        const totalErrorLogs = await this.getErrorCount(start, end);

        const activeUsers = await this.getActiveUsersCount(start, end);
        const activeAPIKeys = await this.getActiveAPIKeysCount(start, end);
        const activeAccounts = await this.getActiveAccountsCount(start, end);

        const modelStats = await this.getModelStats(period);
        const groupStats = await this.getGroupStats(period);

        return {
            totalRequests,
            totalCost,
            actualCost,
            activeUsers,
            activeAPIKeys,
            activeAccounts,
            avgLatencyMs: totalRequests > 0 ? totalDuration / totalRequests : 0,
            errorRate: totalRequests > 0 ? totalErrorLogs / totalRequests : 0,
            p50LatencyMs: await this.getPercentileLatency(start, end, 50),
            p95LatencyMs: await this.getPercentileLatency(start, end, 95),
            p99LatencyMs: await this.getPercentileLatency(start, end, 99),
            topModels: modelStats.slice(0, 10).map((m) => ({ model: m.model, requests: m.requests, cost: m.totalCost })),
            topGroups: groupStats.slice(0, 10).map((g) => ({ groupId: g.groupId, groupName: g.groupName, requests: g.requests, cost: g.cost })),
            topUsers: [],
            topAPIKeys: [],
        };
    }

    async getStats(period: string): Promise<DashboardStats> {
        const { start, end } = this.parsePeriod(period);
        const hourly = await this.getHourlyAggregation(start, end);
        const daily = await this.getDailyAggregation(start, end);

        const totalRequests = hourly.reduce((sum, h) => sum + h.total_requests, 0) +
            daily.reduce((sum, d) => sum + d.total_requests, 0);
        const totalTokens = hourly.reduce((sum, h) => sum + h.input_tokens + h.output_tokens + h.cache_creation_tokens + h.cache_read_tokens, 0) +
            daily.reduce((sum, d) => sum + d.input_tokens + d.output_tokens + d.cache_creation_tokens + d.cache_read_tokens, 0);
        const totalCost = hourly.reduce((sum, h) => sum + h.total_cost, 0) +
            daily.reduce((sum, d) => sum + d.total_cost, 0);
        const totalDuration = hourly.reduce((sum, h) => sum + h.total_duration_ms, 0) +
            daily.reduce((sum, d) => sum + d.total_duration_ms, 0);
        const errorLogs = await this.getErrorCount(start, end);

        return {
            totalRequests,
            totalTokens,
            totalCost,
            activeUsers: await this.getActiveUsersCount(start, end),
            activeAPIKeys: await this.getActiveAPIKeysCount(start, end),
            activeAccounts: await this.getActiveAccountsCount(start, end),
            errorRate: totalRequests > 0 ? errorLogs / totalRequests : 0,
            avgLatencyMs: totalRequests > 0 ? totalDuration / totalRequests : 0,
        };
    }

    async getRealtimeMetrics(): Promise<RealtimeMetrics> {
        const now = new Date();
        const fiveMinAgo = new Date(now.getTime() - 5 * 60 * 1000).toISOString();
        const logs = await allRows<{
            model: string; created_at: string; duration_ms: number | null;
        }>(this.#db, `SELECT model, created_at, duration_ms FROM usage_logs WHERE created_at >= ? ORDER BY created_at DESC LIMIT 1000`, [fiveMinAgo]);

        const total = logs.length;
        const latencies = logs.map((l) => l.duration_ms).filter((l): l is number => l !== null).sort((a, b) => a - b);
        const modelDist: Record<string, number> = {};
        for (const l of logs) modelDist[l.model] = (modelDist[l.model] ?? 0) + 1;

        return {
            qps: total / 300,
            tps: logs.reduce((sum, l) => sum + (l.duration_ms ?? 0), 0) / 300,
            concurrentUsers: total,
            activeRequests: 0,
            latencyP50: latencies[Math.floor(latencies.length * 0.5)] ?? 0,
            latencyP95: latencies[Math.floor(latencies.length * 0.95)] ?? 0,
            latencyP99: latencies[Math.floor(latencies.length * 0.99)] ?? 0,
            errorRate: 0,
            modelDistribution: modelDist,
        };
    }

    async getUsageTrend(period: string, granularity: string): Promise<UsageTrendPoint[]> {
        const { start, end } = this.parsePeriod(period);
        const isHourly = granularity === "hour";

        if (isHourly) {
            const rows = await allRows<{
                bucket_start: string; total_requests: number; input_tokens: number; output_tokens: number;
                cache_creation_tokens: number; cache_read_tokens: number; total_cost: number; actual_cost: number;
                total_duration_ms: number; active_users: number;
            }>(this.#db, `SELECT * FROM usage_dashboard_hourly WHERE bucket_start >= ? AND bucket_start <= ? ORDER BY bucket_start`, [start, end]);
            return rows.map((r) => ({
                bucket: r.bucket_start,
                requests: r.total_requests,
                inputTokens: r.input_tokens,
                outputTokens: r.output_tokens,
                cacheCreationTokens: r.cache_creation_tokens,
                cacheReadTokens: r.cache_read_tokens,
                totalCost: r.total_cost,
                actualCost: r.actual_cost,
                avgLatencyMs: r.total_requests > 0 ? r.total_duration_ms / r.total_requests : 0,
                errorRate: 0,
                activeUsers: r.active_users,
            }));
        } else {
            const rows = await allRows<{
                bucket_date: string; total_requests: number; input_tokens: number; output_tokens: number;
                cache_creation_tokens: number; cache_read_tokens: number; total_cost: number; actual_cost: number;
                total_duration_ms: number; active_users: number;
            }>(this.#db, `SELECT * FROM usage_dashboard_daily WHERE bucket_date >= ? AND bucket_date <= ? ORDER BY bucket_date`, [start.split("T")[0], end.split("T")[0]]);
            return rows.map((r) => ({
                bucket: r.bucket_date,
                requests: r.total_requests,
                inputTokens: r.input_tokens,
                outputTokens: r.output_tokens,
                cacheCreationTokens: r.cache_creation_tokens,
                cacheReadTokens: r.cache_read_tokens,
                totalCost: r.total_cost,
                actualCost: r.actual_cost,
                avgLatencyMs: r.total_requests > 0 ? r.total_duration_ms / r.total_requests : 0,
                errorRate: 0,
                activeUsers: r.active_users,
            }));
        }
    }

    async getModelStats(period: string): Promise<ModelStats[]> {
        const { start, end } = this.parsePeriod(period);
        const rows = await allRows<{
            model: string; total_requests: number; input_tokens: number; output_tokens: number;
            cache_creation_tokens: number; cache_read_tokens: number; total_cost: number; actual_cost: number;
            total_duration_ms: number;
        }>(this.#db,
            `SELECT model,
                    SUM(1) as total_requests,
                    SUM(input_tokens) as input_tokens,
                    SUM(output_tokens) as output_tokens,
                    SUM(cache_creation_tokens) as cache_creation_tokens,
                    SUM(cache_read_tokens) as cache_read_tokens,
                    SUM(total_cost) as total_cost,
                    SUM(actual_cost) as actual_cost,
                    SUM(duration_ms) as total_duration_ms
             FROM usage_logs
             WHERE created_at >= ? AND created_at <= ?
             GROUP BY model
             ORDER BY total_requests DESC
             LIMIT 50`,
            [start, end]
        );
        return rows.map((r) => ({
            model: r.model,
            requests: r.total_requests,
            inputTokens: r.input_tokens,
            outputTokens: r.output_tokens,
            cacheCreationTokens: r.cache_creation_tokens,
            cacheReadTokens: r.cache_read_tokens,
            totalCost: r.total_cost,
            actualCost: r.actual_cost,
            avgLatencyMs: r.total_requests > 0 ? r.total_duration_ms / r.total_requests : 0,
            errorRate: 0,
        }));
    }

    async getGroupStats(period: string): Promise<GroupStats[]> {
        const { start, end } = this.parsePeriod(period);
        const rows = await allRows<{
            group_id: number; group_name: string; total_requests: number; total_cost: number;
            active_users: number; active_api_keys: number;
        }>(this.#db,
            `SELECT g.id as group_id, g.name as group_name,
                    COUNT(ul.id) as total_requests,
                    SUM(ul.total_cost) as total_cost,
                    COUNT(DISTINCT ul.user_id) as active_users,
                    COUNT(DISTINCT ul.api_key_id) as active_api_keys
             FROM usage_logs ul
             JOIN groups g ON ul.group_id = g.id
             WHERE ul.created_at >= ? AND ul.created_at <= ?
             GROUP BY g.id, g.name
             ORDER BY total_requests DESC`,
            [start, end]
        );
        return rows.map((r) => ({
            groupId: r.group_id,
            groupName: r.group_name,
            requests: r.total_requests,
            cost: r.total_cost ?? 0,
            activeUsers: r.active_users,
            activeAPIKeys: r.active_api_keys,
        }));
    }

    async getAPIKeyUsageTrend(apiKeyIds: number[], period: string): Promise<APIKeyUsageTrend[]> {
        if (apiKeyIds.length === 0) return [];
        const { start, end } = this.parsePeriod(period);
        const placeholders = apiKeyIds.map(() => "?").join(",");
        const rows = await allRows<{
            api_key_id: number; bucket_start: string; total_requests: number; total_cost: number;
            input_tokens: number; output_tokens: number; total_duration_ms: number;
        }>(this.#db,
            `SELECT api_key_id, bucket_start, total_requests, total_cost, input_tokens, output_tokens, total_duration_ms
             FROM usage_dashboard_hourly
             WHERE bucket_start >= ? AND bucket_start <= ? AND api_key_id IN (${placeholders})
             ORDER BY api_key_id, bucket_start`,
            [start, end, ...apiKeyIds]
        );
        const byKey = new Map<number, UsageTrendPoint[]>();
        for (const r of rows) {
            const arr = byKey.get(r.api_key_id) ?? [];
            arr.push({
                bucket: r.bucket_start,
                requests: r.total_requests,
                inputTokens: r.input_tokens,
                outputTokens: r.output_tokens,
                cacheCreationTokens: 0,
                cacheReadTokens: 0,
                totalCost: r.total_cost,
                actualCost: 0,
                avgLatencyMs: r.total_requests > 0 ? r.total_duration_ms / r.total_requests : 0,
                errorRate: 0,
                activeUsers: 0,
            });
            byKey.set(r.api_key_id, arr);
        }
        const keyNames = await this.getAPIKeyNames(apiKeyIds);
        return Array.from(byKey.entries()).map(([apiKeyId, trend]) => ({
            apiKeyId,
            keyName: keyNames.get(apiKeyId) ?? `key_${apiKeyId}`,
            trend,
        }));
    }

    async getUserUsageTrend(userIds: number[], period: string): Promise<UserUsageTrend[]> {
        if (userIds.length === 0) return [];
        const { start, end } = this.parsePeriod(period);
        const placeholders = userIds.map(() => "?").join(",");
        const rows = await allRows<{
            user_id: number; bucket_start: string; total_requests: number; total_cost: number;
            input_tokens: number; output_tokens: number; total_duration_ms: number;
        }>(this.#db,
            `SELECT user_id, bucket_start, total_requests, total_cost, input_tokens, output_tokens, total_duration_ms
             FROM usage_dashboard_hourly_users
             WHERE bucket_start >= ? AND bucket_start <= ? AND user_id IN (${placeholders})
             ORDER BY user_id, bucket_start`,
            [start, end, ...userIds]
        );
        const byUser = new Map<number, UsageTrendPoint[]>();
        for (const r of rows) {
            const arr = byUser.get(r.user_id) ?? [];
            arr.push({
                bucket: r.bucket_start,
                requests: r.total_requests,
                inputTokens: r.input_tokens,
                outputTokens: r.output_tokens,
                cacheCreationTokens: 0,
                cacheReadTokens: 0,
                totalCost: r.total_cost,
                actualCost: 0,
                avgLatencyMs: r.total_requests > 0 ? r.total_duration_ms / r.total_requests : 0,
                errorRate: 0,
                activeUsers: 0,
            });
            byUser.set(r.user_id, arr);
        }
        const userNames = await this.getUserNames(userIds);
        return Array.from(byUser.entries()).map(([userId, trend]) => ({
            userId,
            username: userNames.get(userId) ?? `user_${userId}`,
            trend,
        }));
    }

    async getUserSpendingRanking(period: string, limit: number): Promise<UserSpendingRanking[]> {
        const { start, end } = this.parsePeriod(period);
        const rows = await allRows<{
            user_id: number; username: string; email: string; total_cost: number; total_requests: number; total_tokens: number;
        }>(this.#db,
            `SELECT u.id as user_id, u.username, u.email,
                    COALESCE(SUM(ul.total_cost), 0) as total_cost,
                    COUNT(ul.id) as total_requests,
                    COALESCE(SUM(ul.input_tokens + ul.output_tokens + ul.cache_creation_tokens + ul.cache_read_tokens), 0) as total_tokens
             FROM users u
             LEFT JOIN usage_logs ul ON u.id = ul.user_id AND ul.created_at >= ? AND ul.created_at <= ?
             WHERE u.deleted_at IS NULL
             GROUP BY u.id, u.username, u.email
             ORDER BY total_cost DESC
             LIMIT ?`,
            [start, end, limit]
        );
        return rows.map((r) => ({
            userId: r.user_id,
            username: r.username,
            email: r.email,
            totalCost: r.total_cost,
            totalRequests: r.total_requests,
            totalTokens: r.total_tokens,
        }));
    }

    async getBatchUsersUsage(userIds: number[], period: string): Promise<BatchUsageResult[]> {
        if (userIds.length === 0) return [];
        const { start, end } = this.parsePeriod(period);
        const placeholders = userIds.map(() => "?").join(",");
        const rows = await allRows<{
            user_id: number; username: string; total_requests: number; total_cost: number; total_tokens: number;
        }>(this.#db,
            `SELECT u.id as user_id, u.username,
                    COUNT(ul.id) as total_requests,
                    COALESCE(SUM(ul.total_cost), 0) as total_cost,
                    COALESCE(SUM(ul.input_tokens + ul.output_tokens + ul.cache_creation_tokens + ul.cache_read_tokens), 0) as total_tokens
             FROM users u
             LEFT JOIN usage_logs ul ON u.id = ul.user_id AND ul.created_at >= ? AND ul.created_at <= ?
             WHERE u.id IN (${placeholders})
             GROUP BY u.id, u.username`,
            [start, end, ...userIds]
        );
        return rows.map((r) => ({
            userId: r.user_id,
            username: r.username,
            requests: r.total_requests,
            cost: r.total_cost,
            tokens: r.total_tokens,
        }));
    }

    async getBatchAPIKeysUsage(apiKeyIds: number[], period: string): Promise<BatchUsageResult[]> {
        if (apiKeyIds.length === 0) return [];
        const { start, end } = this.parsePeriod(period);
        const placeholders = apiKeyIds.map(() => "?").join(",");
        const rows = await allRows<{
            api_key_id: number; key_name: string; total_requests: number; total_cost: number; total_tokens: number;
        }>(this.#db,
            `SELECT ak.id as api_key_id, ak.name as key_name,
                    COUNT(ul.id) as total_requests,
                    COALESCE(SUM(ul.total_cost), 0) as total_cost,
                    COALESCE(SUM(ul.input_tokens + ul.output_tokens + ul.cache_creation_tokens + ul.cache_read_tokens), 0) as total_tokens
             FROM api_keys ak
             LEFT JOIN usage_logs ul ON ak.id = ul.api_key_id AND ul.created_at >= ? AND ul.created_at <= ?
             WHERE ak.id IN (${placeholders})
             GROUP BY ak.id, ak.name`,
            [start, end, ...apiKeyIds]
        );
        return rows.map((r) => ({
            userId: r.api_key_id,
            username: r.key_name,
            requests: r.total_requests,
            cost: r.total_cost,
            tokens: r.total_tokens,
        }));
    }

    async getUserBreakdown(userId: number, period: string): Promise<UserBreakdown> {
        const { start, end } = this.parsePeriod(period);
        const user = await firstRow<{ id: number; username: string; email: string }>(this.#db, "SELECT id, username, email FROM users WHERE id = ?", [userId]);
        if (!user) throw new Error("User not found");

        const modelRows = await allRows<{ model: string; count: number }>(this.#db,
            `SELECT model, COUNT(*) as count FROM usage_logs WHERE user_id = ? AND created_at >= ? AND created_at <= ? GROUP BY model ORDER BY count DESC`,
            [userId, start, end]
        );
        const groupRows = await allRows<{ group_name: string; count: number }>(this.#db,
            `SELECT g.name as group_name, COUNT(*) as count FROM usage_logs ul JOIN groups g ON ul.group_id = g.id WHERE ul.user_id = ? AND ul.created_at >= ? AND ul.created_at <= ? GROUP BY g.name ORDER BY count DESC`,
            [userId, start, end]
        );

        const agg = await firstRow<{
            total_requests: number; total_cost: number; total_tokens: number;
        }>(this.#db,
            `SELECT COUNT(*) as total_requests, COALESCE(SUM(total_cost), 0) as total_cost,
                    COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens), 0) as total_tokens
             FROM usage_logs WHERE user_id = ? AND created_at >= ? AND created_at <= ?`,
            [userId, start, end]
        );

        return {
            userId,
            username: user.username,
            email: user.email,
            requests: agg?.total_requests ?? 0,
            cost: agg?.total_cost ?? 0,
            tokens: agg?.total_tokens ?? 0,
            models: Object.fromEntries(modelRows.map((r) => [r.model, r.count])),
            groups: Object.fromEntries(groupRows.map((r) => [r.group_name, r.count])),
        };
    }

    async backfillAggregation(from: string, to: string): Promise<{ processed: number }> {
        let processed = 0;
        const start = new Date(from);
        const end = new Date(to);
        const current = new Date(start);

        while (current <= end) {
            const bucketStart = current.toISOString();
            const bucketDate = current.toISOString().split("T")[0];
            const nextHour = new Date(current.getTime() + 60 * 60 * 1000);

            const hourlyAgg = await firstRow<{
                total_requests: number; input_tokens: number; output_tokens: number;
                cache_creation_tokens: number; cache_read_tokens: number; total_cost: number; actual_cost: number;
                total_duration_ms: number; active_users: number; account_cost: number;
            }>(this.#db,
                `SELECT COUNT(*) as total_requests,
                        SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens,
                        SUM(cache_creation_tokens) as cache_creation_tokens, SUM(cache_read_tokens) as cache_read_tokens,
                        SUM(total_cost) as total_cost, SUM(total_cost) as actual_cost,
                        SUM(duration_ms) as total_duration_ms,
                        COUNT(DISTINCT user_id) as active_users,
                        SUM(total_cost) as account_cost
                 FROM usage_logs
                 WHERE created_at >= ? AND created_at < ?`,
                [bucketStart, nextHour.toISOString()]
            );

            if (hourlyAgg && hourlyAgg.total_requests > 0) {
                await runStatement(
                    this.#db,
                    `INSERT INTO usage_dashboard_hourly (bucket_start, total_requests, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens, total_cost, actual_cost, total_duration_ms, active_users, account_cost, computed_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                     ON CONFLICT(bucket_start) DO UPDATE SET
                        total_requests = excluded.total_requests,
                        input_tokens = excluded.input_tokens,
                        output_tokens = excluded.output_tokens,
                        cache_creation_tokens = excluded.cache_creation_tokens,
                        cache_read_tokens = excluded.cache_read_tokens,
                        total_cost = excluded.total_cost,
                        actual_cost = excluded.actual_cost,
                        total_duration_ms = excluded.total_duration_ms,
                        active_users = excluded.active_users,
                        account_cost = excluded.account_cost,
                        computed_at = excluded.computed_at`,
                    [bucketStart, hourlyAgg.total_requests, hourlyAgg.input_tokens, hourlyAgg.output_tokens,
                        hourlyAgg.cache_creation_tokens, hourlyAgg.cache_read_tokens, hourlyAgg.total_cost,
                        hourlyAgg.actual_cost, hourlyAgg.total_duration_ms, hourlyAgg.active_users, hourlyAgg.account_cost]
                );
                processed++;
            }

            current.setTime(current.getTime() + 60 * 60 * 1000);
        }

        return { processed };
    }

    private async getHourlyAggregation(start: string, end: string): Promise<DashboardAggregationRow[]> {
        return allRows<DashboardAggregationRow>(this.#db, `SELECT * FROM usage_dashboard_hourly WHERE bucket_start >= ? AND bucket_start <= ?`, [start, end]);
    }

    private async getDailyAggregation(start: string, end: string): Promise<DashboardAggregationRow[]> {
        return allRows<DashboardAggregationRow>(this.#db, `SELECT * FROM usage_dashboard_daily WHERE bucket_date >= ? AND bucket_date <= ?`, [start.split("T")[0], end.split("T")[0]]);
    }

    private async getErrorCount(start: string, end: string): Promise<number> {
        const row = await firstRow<{ cnt: number }>(this.#db, `SELECT COUNT(*) as cnt FROM ops_error_logs WHERE created_at >= ? AND created_at <= ?`, [start, end]);
        return row?.cnt ?? 0;
    }

    private async getActiveUsersCount(start: string, end: string): Promise<number> {
        const row = await firstRow<{ cnt: number }>(this.#db, `SELECT COUNT(DISTINCT user_id) as cnt FROM usage_logs WHERE created_at >= ? AND created_at <= ?`, [start, end]);
        return row?.cnt ?? 0;
    }

    private async getActiveAPIKeysCount(start: string, end: string): Promise<number> {
        const row = await firstRow<{ cnt: number }>(this.#db, `SELECT COUNT(DISTINCT api_key_id) as cnt FROM usage_logs WHERE created_at >= ? AND created_at <= ?`, [start, end]);
        return row?.cnt ?? 0;
    }

    private async getActiveAccountsCount(start: string, end: string): Promise<number> {
        const row = await firstRow<{ cnt: number }>(this.#db, `SELECT COUNT(DISTINCT account_id) as cnt FROM usage_logs WHERE created_at >= ? AND created_at <= ?`, [start, end]);
        return row?.cnt ?? 0;
    }

    private async getPercentileLatency(start: string, end: string, percentile: number): Promise<number> {
        const rows = await allRows<{ duration_ms: number }>(this.#db, `SELECT duration_ms FROM usage_logs WHERE created_at >= ? AND created_at <= ? AND duration_ms IS NOT NULL ORDER BY duration_ms`, [start, end]);
        if (rows.length === 0) return 0;
        const idx = Math.floor(rows.length * (percentile / 100));
        return rows[idx]?.duration_ms ?? 0;
    }

    private async getAPIKeyNames(apiKeyIds: number[]): Promise<Map<number, string>> {
        const names = new Map<number, string>();
        if (apiKeyIds.length === 0) return names;
        const placeholders = apiKeyIds.map(() => "?").join(",");
        const rows = await allRows<{ id: number; name: string }>(this.#db, `SELECT id, name FROM api_keys WHERE id IN (${placeholders})`, apiKeyIds);
        for (const r of rows) names.set(r.id, r.name);
        return names;
    }

    private async getUserNames(userIds: number[]): Promise<Map<number, string>> {
        const names = new Map<number, string>();
        if (userIds.length === 0) return names;
        const placeholders = userIds.map(() => "?").join(",");
        const rows = await allRows<{ id: number; username: string }>(this.#db, `SELECT id, username FROM users WHERE id IN (${placeholders})`, userIds);
        for (const r of rows) names.set(r.id, r.username);
        return names;
    }
}
