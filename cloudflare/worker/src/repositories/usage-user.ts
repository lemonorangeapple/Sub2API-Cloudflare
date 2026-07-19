import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow } from "./d1.ts";

export interface UsageLogRow {
    id: number;
    requestId: string;
    model: string;
    requestedModel: string | null;
    inputTokens: number;
    outputTokens: number;
    cacheCreationTokens: number;
    cacheReadTokens: number;
    totalCost: number;
    actualCost: number;
    billingType: number;
    stream: number;
    durationMs: number | null;
    firstTokenMs: number | null;
    userAgent: string | null;
    imageCount: number;
    videoCount: number;
    groupId: number | null;
    subscriptionId: number | null;
    apiKeyId: number;
    accountId: number;
    createdAt: string;
}

export interface UsageStatsResult {
    totalRequests: number;
    totalInputTokens: number;
    totalOutputTokens: number;
    totalCacheCreationTokens: number;
    totalCacheReadTokens: number;
    totalTokens: number;
    totalCost: number;
    totalActualCost: number;
    averageDurationMs: number;
}

export interface TrendPoint {
    date: string;
    requests: number;
    inputTokens: number;
    outputTokens: number;
    cacheCreationTokens: number;
    cacheReadTokens: number;
    totalTokens: number;
    cost: number;
    actualCost: number;
}

export interface ModelStat {
    model: string;
    requests: number;
    inputTokens: number;
    outputTokens: number;
    cacheCreationTokens: number;
    cacheReadTokens: number;
    totalTokens: number;
    cost: number;
    actualCost: number;
}

export class D1UsageUserRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async listUsage(
        userId: number,
        page: number,
        pageSize: number,
        filters: { apiKeyId?: number; groupId?: number; model?: string; startDate?: string; endDate?: string; sortBy?: string; sortOrder?: string }
    ): Promise<{ items: UsageLogRow[]; total: number }> {
        const offset = (page - 1) * pageSize;
        const conditions: string[] = ["user_id = ?"];
        const values: D1Value[] = [userId];

        if (filters.apiKeyId !== undefined) { conditions.push("api_key_id = ?"); values.push(filters.apiKeyId); }
        if (filters.groupId !== undefined) { conditions.push("group_id = ?"); values.push(filters.groupId); }
        if (filters.model !== undefined) { conditions.push("model LIKE ?"); values.push(`%${filters.model}%`); }
        if (filters.startDate !== undefined) { conditions.push("created_at >= ?"); values.push(filters.startDate); }
        if (filters.endDate !== undefined) { conditions.push("created_at < ?"); values.push(filters.endDate); }

        const where = conditions.join(" AND ");
        const allowedSortBy = ["created_at", "total_cost", "model", "duration_ms"].includes(filters.sortBy ?? "") ? filters.sortBy! : "created_at";
        const order = filters.sortOrder === "asc" ? "ASC" : "DESC";

        const countRow = await firstRow<{ cnt: number }>(this.#db, `SELECT COUNT(*) as cnt FROM usage_logs WHERE ${where}`, values);
        const total = countRow?.cnt ?? 0;

        const rows = await allRows<{
            id: number; request_id: string; model: string; requested_model: string | null;
            input_tokens: number; output_tokens: number; cache_creation_tokens: number; cache_read_tokens: number;
            total_cost: number; actual_cost: number; billing_type: number; stream: number;
            duration_ms: number | null; first_token_ms: number | null; user_agent: string | null;
            image_count: number; video_count: number; group_id: number | null; subscription_id: number | null;
            api_key_id: number; account_id: number; created_at: string;
        }>(
            this.#db,
            `SELECT id, request_id, model, requested_model, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
                    total_cost, actual_cost, billing_type, stream, duration_ms, first_token_ms, user_agent,
                    image_count, video_count, group_id, subscription_id, api_key_id, account_id, created_at
             FROM usage_logs WHERE ${where} ORDER BY ${allowedSortBy} ${order} LIMIT ? OFFSET ?`,
            [...values, pageSize, offset]
        );

        return {
            items: rows.map((r) => ({
                id: r.id, requestId: r.request_id, model: r.model, requestedModel: r.requested_model,
                inputTokens: r.input_tokens, outputTokens: r.output_tokens,
                cacheCreationTokens: r.cache_creation_tokens, cacheReadTokens: r.cache_read_tokens,
                totalCost: r.total_cost, actualCost: r.actual_cost, billingType: r.billing_type,
                stream: r.stream, durationMs: r.duration_ms, firstTokenMs: r.first_token_ms,
                userAgent: r.user_agent, imageCount: r.image_count, videoCount: r.video_count,
                groupId: r.group_id, subscriptionId: r.subscription_id, apiKeyId: r.api_key_id,
                accountId: r.account_id, createdAt: r.created_at,
            })),
            total,
        };
    }

    async getUsageById(userId: number, id: number): Promise<UsageLogRow | null> {
        const row = await firstRow<{
            id: number; request_id: string; model: string; requested_model: string | null;
            input_tokens: number; output_tokens: number; cache_creation_tokens: number; cache_read_tokens: number;
            total_cost: number; actual_cost: number; billing_type: number; stream: number;
            duration_ms: number | null; first_token_ms: number | null; user_agent: string | null;
            image_count: number; video_count: number; group_id: number | null; subscription_id: number | null;
            api_key_id: number; account_id: number; created_at: string;
        }>(
            this.#db,
            `SELECT id, request_id, model, requested_model, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
                    total_cost, actual_cost, billing_type, stream, duration_ms, first_token_ms, user_agent,
                    image_count, video_count, group_id, subscription_id, api_key_id, account_id, created_at
             FROM usage_logs WHERE id = ? AND user_id = ? LIMIT 1`,
            [id, userId]
        );
        if (row === null) return null;
        return {
            id: row.id, requestId: row.request_id, model: row.model, requestedModel: row.requested_model,
            inputTokens: row.input_tokens, outputTokens: row.output_tokens,
            cacheCreationTokens: row.cache_creation_tokens, cacheReadTokens: row.cache_read_tokens,
            totalCost: row.total_cost, actualCost: row.actual_cost, billingType: row.billing_type,
            stream: row.stream, durationMs: row.duration_ms, firstTokenMs: row.first_token_ms,
            userAgent: row.user_agent, imageCount: row.image_count, videoCount: row.video_count,
            groupId: row.group_id, subscriptionId: row.subscription_id, apiKeyId: row.api_key_id,
            accountId: row.account_id, createdAt: row.created_at,
        };
    }

    async getStats(userId: number, startDate?: string, endDate?: string): Promise<UsageStatsResult | null> {
        const conditions: string[] = ["user_id = ?"];
        const values: D1Value[] = [userId];
        if (startDate !== undefined) { conditions.push("created_at >= ?"); values.push(startDate); }
        if (endDate !== undefined) { conditions.push("created_at < ?"); values.push(endDate); }
        const where = conditions.join(" AND ");

        const row = await firstRow<{
            requests: number; input_tokens: number; output_tokens: number;
            cache_creation_tokens: number; cache_read_tokens: number;
            total_cost: number; actual_cost: number; avg_duration: number;
        }>(
            this.#db,
            `SELECT COUNT(*) as requests,
                    COALESCE(SUM(input_tokens), 0) as input_tokens,
                    COALESCE(SUM(output_tokens), 0) as output_tokens,
                    COALESCE(SUM(cache_creation_tokens), 0) as cache_creation_tokens,
                    COALESCE(SUM(cache_read_tokens), 0) as cache_read_tokens,
                    COALESCE(SUM(total_cost), 0) as total_cost,
                    COALESCE(SUM(actual_cost), 0) as actual_cost,
                    COALESCE(AVG(CASE WHEN duration_ms IS NOT NULL THEN duration_ms ELSE NULL END), 0) as avg_duration
             FROM usage_logs WHERE ${where}`,
            values
        );
        if (row === null) return null;

        const totalTokens = row.input_tokens + row.output_tokens + row.cache_creation_tokens + row.cache_read_tokens;
        return {
            totalRequests: row.requests,
            totalInputTokens: row.input_tokens,
            totalOutputTokens: row.output_tokens,
            totalCacheCreationTokens: row.cache_creation_tokens,
            totalCacheReadTokens: row.cache_read_tokens,
            totalTokens,
            totalCost: row.total_cost,
            totalActualCost: row.actual_cost,
            averageDurationMs: row.avg_duration,
        };
    }

    async getDashboardStats(userId: number): Promise<{
        totalApiKeys: number;
        activeApiKeys: number;
        totalRequests: number;
        totalInputTokens: number;
        totalOutputTokens: number;
        totalTokens: number;
        totalCost: number;
        totalActualCost: number;
        todayRequests: number;
        todayTokens: number;
        todayCost: number;
        averageDurationMs: number;
    }> {
        const now = new Date();
        const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();

        const apiKeyRow = await firstRow<{ total: number; active: number }>(
            this.#db,
            "SELECT COUNT(*) as total, SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active FROM api_keys WHERE user_id = ? AND deleted_at IS NULL",
            [userId]
        );

        const totalRow = await firstRow<{
            requests: number; input_tokens: number; output_tokens: number;
            cost: number; actual_cost: number; avg_duration: number;
        }>(
            this.#db,
            `SELECT COUNT(*) as requests,
                    COALESCE(SUM(input_tokens), 0) as input_tokens,
                    COALESCE(SUM(output_tokens), 0) as output_tokens,
                    COALESCE(SUM(total_cost), 0) as cost,
                    COALESCE(SUM(actual_cost), 0) as actual_cost,
                    COALESCE(AVG(CASE WHEN duration_ms IS NOT NULL THEN duration_ms ELSE NULL END), 0) as avg_duration
             FROM usage_logs WHERE user_id = ?`,
            [userId]
        );

        const todayRow = await firstRow<{ requests: number; tokens: number; cost: number }>(
            this.#db,
            `SELECT COUNT(*) as requests,
                    COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens), 0) as tokens,
                    COALESCE(SUM(total_cost), 0) as cost
             FROM usage_logs WHERE user_id = ? AND created_at >= ?`,
            [userId, todayStart]
        );

        return {
            totalApiKeys: apiKeyRow?.total ?? 0,
            activeApiKeys: apiKeyRow?.active ?? 0,
            totalRequests: totalRow?.requests ?? 0,
            totalInputTokens: totalRow?.input_tokens ?? 0,
            totalOutputTokens: totalRow?.output_tokens ?? 0,
            totalTokens: (totalRow?.input_tokens ?? 0) + (totalRow?.output_tokens ?? 0),
            totalCost: totalRow?.cost ?? 0,
            totalActualCost: totalRow?.actual_cost ?? 0,
            todayRequests: todayRow?.requests ?? 0,
            todayTokens: todayRow?.tokens ?? 0,
            todayCost: todayRow?.cost ?? 0,
            averageDurationMs: totalRow?.avg_duration ?? 0,
        };
    }

    async getTrend(userId: number, startDate: string, endDate: string, granularity: string): Promise<TrendPoint[]> {
        if (granularity === "hour") {
            const rows = await allRows<{
                bucket: string; requests: number; input_tokens: number; output_tokens: number;
                cache_creation_tokens: number; cache_read_tokens: number; cost: number; actual_cost: number;
            }>(
                this.#db,
                `SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) as bucket,
                        COUNT(*) as requests,
                        COALESCE(SUM(input_tokens), 0) as input_tokens,
                        COALESCE(SUM(output_tokens), 0) as output_tokens,
                        COALESCE(SUM(cache_creation_tokens), 0) as cache_creation_tokens,
                        COALESCE(SUM(cache_read_tokens), 0) as cache_read_tokens,
                        COALESCE(SUM(total_cost), 0) as cost,
                        COALESCE(SUM(actual_cost), 0) as actual_cost
                 FROM usage_logs
                 WHERE user_id = ? AND created_at >= ? AND created_at < ?
                 GROUP BY bucket ORDER BY bucket ASC`,
                [userId, startDate, endDate]
            );
            return rows.map((r) => ({
                date: r.bucket,
                requests: r.requests,
                inputTokens: r.input_tokens,
                outputTokens: r.output_tokens,
                cacheCreationTokens: r.cache_creation_tokens,
                cacheReadTokens: r.cache_read_tokens,
                totalTokens: r.input_tokens + r.output_tokens + r.cache_creation_tokens + r.cache_read_tokens,
                cost: r.cost,
                actualCost: r.actual_cost,
            }));
        }

        const rows = await allRows<{
            bucket: string; requests: number; input_tokens: number; output_tokens: number;
            cache_creation_tokens: number; cache_read_tokens: number; cost: number; actual_cost: number;
        }>(
            this.#db,
            `SELECT strftime('%Y-%m-%d', created_at) as bucket,
                    COUNT(*) as requests,
                    COALESCE(SUM(input_tokens), 0) as input_tokens,
                    COALESCE(SUM(output_tokens), 0) as output_tokens,
                    COALESCE(SUM(cache_creation_tokens), 0) as cache_creation_tokens,
                    COALESCE(SUM(cache_read_tokens), 0) as cache_read_tokens,
                    COALESCE(SUM(total_cost), 0) as cost,
                    COALESCE(SUM(actual_cost), 0) as actual_cost
             FROM usage_logs
             WHERE user_id = ? AND created_at >= ? AND created_at < ?
             GROUP BY bucket ORDER BY bucket ASC`,
            [userId, startDate, endDate]
        );
        return rows.map((r) => ({
            date: r.bucket,
            requests: r.requests,
            inputTokens: r.input_tokens,
            outputTokens: r.output_tokens,
            cacheCreationTokens: r.cache_creation_tokens,
            cacheReadTokens: r.cache_read_tokens,
            totalTokens: r.input_tokens + r.output_tokens + r.cache_creation_tokens + r.cache_read_tokens,
            cost: r.cost,
            actualCost: r.actual_cost,
        }));
    }

    async getModelStats(userId: number, startDate?: string, endDate?: string): Promise<ModelStat[]> {
        const conditions: string[] = ["user_id = ?"];
        const values: D1Value[] = [userId];
        if (startDate !== undefined) { conditions.push("created_at >= ?"); values.push(startDate); }
        if (endDate !== undefined) { conditions.push("created_at < ?"); values.push(endDate); }
        const where = conditions.join(" AND ");

        const rows = await allRows<{
            model: string; requests: number; input_tokens: number; output_tokens: number;
            cache_creation_tokens: number; cache_read_tokens: number; cost: number; actual_cost: number;
        }>(
            this.#db,
            `SELECT COALESCE(requested_model, model) as model,
                    COUNT(*) as requests,
                    COALESCE(SUM(input_tokens), 0) as input_tokens,
                    COALESCE(SUM(output_tokens), 0) as output_tokens,
                    COALESCE(SUM(cache_creation_tokens), 0) as cache_creation_tokens,
                    COALESCE(SUM(cache_read_tokens), 0) as cache_read_tokens,
                    COALESCE(SUM(total_cost), 0) as cost,
                    COALESCE(SUM(actual_cost), 0) as actual_cost
             FROM usage_logs WHERE ${where}
             GROUP BY COALESCE(requested_model, model) ORDER BY requests DESC`,
            values
        );
        return rows.map((r) => ({
            model: r.model,
            requests: r.requests,
            inputTokens: r.input_tokens,
            outputTokens: r.output_tokens,
            cacheCreationTokens: r.cache_creation_tokens,
            cacheReadTokens: r.cache_read_tokens,
            totalTokens: r.input_tokens + r.output_tokens + r.cache_creation_tokens + r.cache_read_tokens,
            cost: r.cost,
            actualCost: r.actual_cost,
        }));
    }

    async getAPIKeyDailyUsage(userId: number, apiKeyId: number, days: number): Promise<{ date: string; requests: number; inputTokens: number; outputTokens: number; totalTokens: number; cost: number; actualCost: number }[]> {
        const startDate = new Date(Date.now() - days * 86400000).toISOString();
        const rows = await allRows<{
            bucket: string; requests: number; input_tokens: number; output_tokens: number;
            cache_read_tokens: number; cost: number; actual_cost: number;
        }>(
            this.#db,
            `SELECT strftime('%Y-%m-%d', created_at) as bucket,
                    COUNT(*) as requests,
                    COALESCE(SUM(input_tokens), 0) as input_tokens,
                    COALESCE(SUM(output_tokens), 0) as output_tokens,
                    COALESCE(SUM(cache_read_tokens), 0) as cache_read_tokens,
                    COALESCE(SUM(total_cost), 0) as cost,
                    COALESCE(SUM(actual_cost), 0) as actual_cost
             FROM usage_logs
             WHERE user_id = ? AND api_key_id = ? AND created_at >= ?
             GROUP BY bucket ORDER BY bucket ASC`,
            [userId, apiKeyId, startDate]
        );
        return rows.map((r) => ({
            date: r.bucket,
            requests: r.requests,
            inputTokens: r.input_tokens,
            outputTokens: r.output_tokens,
            totalTokens: r.input_tokens + r.output_tokens + r.cache_read_tokens,
            cost: r.cost,
            actualCost: r.actual_cost,
        }));
    }

    async verifyAPIKeyOwnership(userId: number, apiKeyId: number): Promise<boolean> {
        const row = await firstRow<{ id: number }>(
            this.#db, "SELECT id FROM api_keys WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1",
            [apiKeyId, userId]
        );
        return row !== null;
    }

    async listErrors(
        userId: number,
        page: number,
        pageSize: number,
        filters: { model?: string; apiKeyId?: number; startDate?: string; endDate?: string }
    ): Promise<{ items: ErrorLogRow[]; total: number }> {
        const offset = (page - 1) * pageSize;
        const conditions: string[] = [
            "(user_id = ? OR deleted_key_owner_user_id = ?)",
            "is_count_tokens = 0",
        ];
        const values: D1Value[] = [userId, userId];

        if (filters.apiKeyId !== undefined) { conditions.push("api_key_id = ?"); values.push(filters.apiKeyId); }
        if (filters.model !== undefined) { conditions.push("(COALESCE(requested_model, model, '') LIKE ?)"); values.push(`%${filters.model}%`); }
        if (filters.startDate !== undefined) { conditions.push("created_at >= ?"); values.push(filters.startDate); }
        if (filters.endDate !== undefined) { conditions.push("created_at < ?"); values.push(filters.endDate); }

        const where = conditions.join(" AND ");

        const countRow = await firstRow<{ cnt: number }>(this.#db, `SELECT COUNT(*) as cnt FROM ops_error_logs WHERE ${where}`, values);
        const total = countRow?.cnt ?? 0;

        const rows = await allRows<{
            id: number; created_at: string; error_phase: string; error_type: string;
            status_code: number | null; model: string | null; requested_model: string | null;
            platform: string | null; error_message: string | null; api_key_id: number | null;
            group_id: number | null; stream: number; user_agent: string | null;
            client_ip: string | null; inbound_endpoint: string | null;
        }>(
            this.#db,
            `SELECT e.id, e.created_at, e.error_phase, e.error_type, e.status_code,
                    e.model, e.requested_model, e.platform, e.error_message,
                    e.api_key_id, e.group_id, e.stream, e.user_agent, e.client_ip, e.inbound_endpoint
             FROM ops_error_logs e WHERE ${where} ORDER BY e.created_at DESC LIMIT ? OFFSET ?`,
            [...values, pageSize, offset]
        );

        return {
            items: rows.map((r) => ({
                id: r.id, createdAt: r.created_at, model: r.requested_model ?? r.model ?? "",
                inboundEndpoint: r.inbound_endpoint ?? "", statusCode: r.status_code ?? 0,
                category: mapErrorCategory(r.error_phase, r.error_type),
                platform: r.platform ?? "", message: r.error_message ?? "",
                groupId: r.group_id, stream: r.stream === 1, userAgent: r.user_agent,
                clientIp: r.client_ip,
            })),
            total,
        };
    }

    async getErrorDetail(userId: number, id: number): Promise<ErrorDetailRow | null> {
        const row = await firstRow<{
            id: number; created_at: string; error_phase: string; error_type: string;
            status_code: number | null; model: string | null; requested_model: string | null;
            platform: string | null; error_message: string | null; error_body: string | null;
            upstream_status_code: number | null; api_key_id: number | null;
            group_id: number | null; stream: number; user_agent: string | null;
            client_ip: string | null; inbound_endpoint: string | null;
            deleted_key_owner_user_id: number | null;
        }>(
            this.#db,
            `SELECT e.id, e.created_at, e.error_phase, e.error_type, e.status_code,
                    e.model, e.requested_model, e.platform, e.error_message, e.error_body,
                    e.upstream_status_code, e.api_key_id, e.group_id, e.stream, e.user_agent,
                    e.client_ip, e.inbound_endpoint, e.deleted_key_owner_user_id
             FROM ops_error_logs e WHERE e.id = ? LIMIT 1`,
            [id]
        );
        if (row === null) return null;
        const ownedDirectly = row.deleted_key_owner_user_id !== null ? row.deleted_key_owner_user_id === userId : false;
        const ownedViaUserId = true;
        if (!ownedViaUserId) {
            const userRow = await firstRow<{ id: number }>(
                this.#db, "SELECT id FROM ops_error_logs WHERE id = ? AND user_id = ?", [id, userId]
            );
            if (userRow === null && !ownedDirectly) return null;
        }
        return {
            id: row.id, createdAt: row.created_at, model: row.requested_model ?? row.model ?? "",
            inboundEndpoint: row.inbound_endpoint ?? "", statusCode: row.status_code ?? 0,
            category: mapErrorCategory(row.error_phase, row.error_type),
            platform: row.platform ?? "", message: row.error_message ?? "",
            groupId: row.group_id, stream: row.stream === 1, userAgent: row.user_agent,
            clientIp: row.client_ip, errorBody: row.error_body ?? "",
            upstreamStatusCode: row.upstream_status_code,
        };
    }

    async listPlatformQuotas(userId: number): Promise<PlatformQuotaRow[]> {
        const rows = await allRows<{
            platform: string; daily_limit_usd: number | null; weekly_limit_usd: number | null;
            monthly_limit_usd: number | null; daily_usage_usd: number; weekly_usage_usd: number;
            monthly_usage_usd: number; daily_window_start: string | null;
            weekly_window_start: string | null; monthly_window_start: string | null;
        }>(
            this.#db,
            `SELECT platform, daily_limit_usd, weekly_limit_usd, monthly_limit_usd,
                    daily_usage_usd, weekly_usage_usd, monthly_usage_usd,
                    daily_window_start, weekly_window_start, monthly_window_start
             FROM user_platform_quotas WHERE user_id = ? AND deleted_at IS NULL`,
            [userId]
        );
        return rows.map((r) => ({
            platform: r.platform,
            dailyLimitUsd: r.daily_limit_usd, weeklyLimitUsd: r.weekly_limit_usd,
            monthlyLimitUsd: r.monthly_limit_usd,
            dailyUsageUsd: r.daily_usage_usd, weeklyUsageUsd: r.weekly_usage_usd,
            monthlyUsageUsd: r.monthly_usage_usd,
        }));
    }
}

export interface ErrorLogRow {
    id: number;
    createdAt: string;
    model: string;
    inboundEndpoint: string;
    statusCode: number;
    category: string;
    platform: string;
    message: string;
    groupId: number | null;
    stream: boolean;
    userAgent: string | null;
    clientIp: string | null;
}

export interface ErrorDetailRow extends ErrorLogRow {
    errorBody: string;
    upstreamStatusCode: number | null;
}

export interface PlatformQuotaRow {
    platform: string;
    dailyLimitUsd: number | null;
    weeklyLimitUsd: number | null;
    monthlyLimitUsd: number | null;
    dailyUsageUsd: number;
    weeklyUsageUsd: number;
    monthlyUsageUsd: number;
}

function mapErrorCategory(phase: string, type: string): string {
    const authTypes = ["auth", "oauth", "token", "api_key"];
    if (phase === "auth" || authTypes.includes(type)) return "auth";
    if (phase === "routing") return "service_unavailable";
    if (["account_auth", "upstream", "network"].includes(phase)) return "upstream";
    if (phase === "internal") return "internal";
    if (phase === "request") {
        if (type === "rate_limit_error") return "rate_limit";
        if (["billing_error", "subscription_error"].includes(type)) return "quota";
        if (type === "invalid_request_error") return "invalid_request";
        if (type === "cyber_policy") return "cyber";
    }
    return "other";
}
