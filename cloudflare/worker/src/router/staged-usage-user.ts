import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1UsageUserRepository } from "../repositories/usage-user.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1UsageUserService, UsageUserError } from "../services/usage-user.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
} from "./responses.ts";

const USAGE_LIST_RE = /^\/api\/v1\/usage\/?$/;
const USAGE_STATS_RE = /^\/api\/v1\/usage\/stats\/?$/;
const USAGE_ERRORS_RE = /^\/api\/v1\/usage\/errors\/?$/;
const USAGE_ERROR_BY_ID_RE = /^\/api\/v1\/usage\/errors\/(\d+)\/?$/;
const USAGE_DASHBOARD_STATS_RE = /^\/api\/v1\/usage\/dashboard\/stats\/?$/;
const USAGE_DASHBOARD_TREND_RE = /^\/api\/v1\/usage\/dashboard\/trend\/?$/;
const USAGE_DASHBOARD_MODELS_RE = /^\/api\/v1\/usage\/dashboard\/models\/?$/;
const USAGE_DASHBOARD_SNAPSHOT_V2_RE = /^\/api\/v1\/usage\/dashboard\/snapshot-v2\/?$/;
const USAGE_BY_ID_RE = /^\/api\/v1\/usage\/(\d+)\/?$/;
const USER_API_KEY_DAILY_USAGE_RE = /^\/api\/v1\/user\/api-keys\/(\d+)\/usage\/daily\/?$/;
const USER_PLATFORM_QUOTAS_RE = /^\/api\/v1\/user\/platform-quotas\/?$/;

export interface StagedUsageUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

function boundedIntegerEnv(value: string | undefined, defaultValue: number, min: number, max: number): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

function parseOptionalInt(url: URL, key: string): number | undefined {
    const v = url.searchParams.get(key);
    if (v === null || v.trim() === "") return undefined;
    const n = Number.parseInt(v.trim(), 10);
    return Number.isInteger(n) ? n : undefined;
}

function parseDateParam(url: URL, key: string): string | undefined {
    const v = url.searchParams.get(key);
    if (v === null || v.trim() === "") return undefined;
    return v.trim();
}

export function isUsageUserPath(path: string): boolean {
    return path.startsWith("/api/v1/usage") || path.startsWith("/api/v1/user/api-keys/") || path.startsWith("/api/v1/user/platform-quotas");
}

async function authenticateUser(request: Request, env: StagedUsageUserEnv, clock: () => number): Promise<{ userId: number }> {
    const authHeader = request.headers.get("authorization");
    if (!authHeader) throw new AccessAuthError("UNAUTHORIZED", "Missing authorization header");
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) throw new AccessAuthError("UNAUTHORIZED", "JWT secret is not configured");
    const users = new D1AuthUserRepository(env.DB!);
    const sessions = new D1AuthSessionRepository(env.DB!);
    const signer = new Hs256JwtSigner(secret, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 7 * 24 * 60 * 60), clock);
    const verifier = new Hs256JwtVerifier(secret, clock);
    const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), clock);
    const auth = new AccessAuthService(users, verifier, tokens, clock);
    const subject = await auth.authenticateAuthorization(authHeader);
    return { userId: subject.user.id };
}

export async function routeStagedUsageUser(
    request: Request,
    env: StagedUsageUserEnv
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (!isUsageUserPath(pathname)) return null;
    if (env.DB === undefined) return middlewareAuthError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    if (method !== "GET") return null;

    try {
        const auth = await authenticateUser(request, env, Date.now);
        const repo = new D1UsageUserRepository(env.DB);
        const svc = new D1UsageUserService(repo);

        const userId = auth.userId;

        // GET /api/v1/usage/dashboard/snapshot-v2
        if (USAGE_DASHBOARD_SNAPSHOT_V2_RE.test(pathname)) {
            const period = url.searchParams.get("period") ?? "month";
            const { startDate, endDate } = computePeriodRange(period);
            const result = await svc.getSnapshotV2(userId, startDate, endDate);
            return legacySuccess({
                trend: result.trend,
                model_stats: result.modelStats,
                group_stats: [],
            });
        }

        // GET /api/v1/usage/dashboard/models
        if (USAGE_DASHBOARD_MODELS_RE.test(pathname)) {
            const period = url.searchParams.get("period") ?? "month";
            const { startDate, endDate } = computePeriodRange(period);
            const models = await svc.getModelStats(userId, startDate, endDate);
            return legacySuccess({ items: models });
        }

        // GET /api/v1/usage/dashboard/trend
        if (USAGE_DASHBOARD_TREND_RE.test(pathname)) {
            const period = url.searchParams.get("period") ?? "month";
            const granularity = url.searchParams.get("granularity") ?? (period === "today" ? "hour" : "day");
            const { startDate, endDate } = computePeriodRange(period);
            const trend = await svc.getTrend(userId, startDate, endDate, granularity);
            return legacySuccess({ items: trend });
        }

        // GET /api/v1/usage/dashboard/stats
        if (USAGE_DASHBOARD_STATS_RE.test(pathname)) {
            const stats = await svc.getDashboardStats(userId);
            return legacySuccess({
                total_api_keys: stats.totalApiKeys,
                active_api_keys: stats.activeApiKeys,
                total_requests: stats.totalRequests,
                total_input_tokens: stats.totalInputTokens,
                total_output_tokens: stats.totalOutputTokens,
                total_tokens: stats.totalTokens,
                total_cost: stats.totalCost,
                total_actual_cost: stats.totalActualCost,
                today_requests: stats.todayRequests,
                today_tokens: stats.todayTokens,
                today_cost: stats.todayCost,
                average_duration_ms: stats.averageDurationMs,
            });
        }

        // GET /api/v1/usage/stats
        if (USAGE_STATS_RE.test(pathname)) {
            const period = url.searchParams.get("period") ?? "month";
            const { startDate, endDate } = computePeriodRange(period);
            const stats = await svc.getStats(userId, startDate, endDate);
            return legacySuccess({
                total_requests: stats.totalRequests,
                total_input_tokens: stats.totalInputTokens,
                total_output_tokens: stats.totalOutputTokens,
                total_cache_creation_tokens: stats.totalCacheCreationTokens,
                total_cache_read_tokens: stats.totalCacheReadTokens,
                total_tokens: stats.totalTokens,
                total_cost: stats.totalCost,
                total_actual_cost: stats.totalActualCost,
                average_duration_ms: stats.averageDurationMs,
            });
        }

        // GET /api/v1/user/platform-quotas
        if (USER_PLATFORM_QUOTAS_RE.test(pathname)) {
            const quotas = await svc.getPlatformQuotas(userId);
            return legacySuccess({ platform_quotas: quotas.map((q) => ({
                platform: q.platform,
                daily_limit_usd: q.dailyLimitUsd,
                weekly_limit_usd: q.weeklyLimitUsd,
                monthly_limit_usd: q.monthlyLimitUsd,
                daily_usage_usd: q.dailyUsageUsd,
                weekly_usage_usd: q.weeklyUsageUsd,
                monthly_usage_usd: q.monthlyUsageUsd,
            })) });
        }

        // GET /api/v1/usage/errors/:id
        const errorByIdMatch = USAGE_ERROR_BY_ID_RE.exec(pathname);
        if (errorByIdMatch !== null) {
            const id = Number(errorByIdMatch[1]);
            const detail = await svc.getErrorDetail(userId, id);
            return legacySuccess({
                id: detail.id, created_at: detail.createdAt, model: detail.model,
                inbound_endpoint: detail.inboundEndpoint, status_code: detail.statusCode,
                category: detail.category, platform: detail.platform, message: detail.message,
                stream: detail.stream, user_agent: detail.userAgent,
                error_body: detail.errorBody,
                upstream_status_code: detail.upstreamStatusCode,
            });
        }

        // GET /api/v1/usage/errors
        if (USAGE_ERRORS_RE.test(pathname)) {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const model = url.searchParams.get("model") ?? undefined;
            const apiKeyId = parseOptionalInt(url, "api_key_id");
            const startDate = parseDateParam(url, "start_date");
            const endDate = parseDateParam(url, "end_date");
            const result = await svc.listErrors(userId, page, pageSize, { model, apiKeyId, startDate, endDate });
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize });
        }

        // GET /api/v1/user/api-keys/:id/usage/daily
        const apiKeyDailyMatch = USER_API_KEY_DAILY_USAGE_RE.exec(pathname);
        if (apiKeyDailyMatch !== null) {
            const apiKeyId = Number(apiKeyDailyMatch[1]);
            const days = parseOptionalInt(url, "days") ?? 30;
            const items = await svc.getAPIKeyDailyUsage(userId, apiKeyId, days);
            return legacySuccess({ items });
        }

        // GET /api/v1/usage/:id
        const idMatch = USAGE_BY_ID_RE.exec(pathname);
        if (idMatch !== null) {
            const id = Number(idMatch[1]);
            const row = await svc.getUsageById(userId, id);
            return legacySuccess({
                id: row.id, request_id: row.requestId, model: row.model, requested_model: row.requestedModel,
                input_tokens: row.inputTokens, output_tokens: row.outputTokens,
                cache_creation_tokens: row.cacheCreationTokens, cache_read_tokens: row.cacheReadTokens,
                total_cost: row.totalCost, actual_cost: row.actualCost,
                billing_type: row.billingType, stream: row.stream === 1,
                duration_ms: row.durationMs, user_agent: row.userAgent,
                image_count: row.imageCount, video_count: row.videoCount,
                group_id: row.groupId, api_key_id: row.apiKeyId,
                created_at: row.createdAt,
            });
        }

        // GET /api/v1/usage
        if (USAGE_LIST_RE.test(pathname)) {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const apiKeyId = parseOptionalInt(url, "api_key_id");
            const groupId = parseOptionalInt(url, "group_id");
            const model = url.searchParams.get("model") ?? undefined;
            const sortBy = url.searchParams.get("sort_by") ?? undefined;
            const sortOrder = url.searchParams.get("sort_order") ?? undefined;
            const period = url.searchParams.get("period") ?? undefined;
            let startDate: string | undefined = parseDateParam(url, "start_date");
            let endDate: string | undefined = parseDateParam(url, "end_date");

            if (period !== undefined && startDate === undefined) {
                const range = computePeriodRange(period);
                startDate = range.startDate;
                endDate = range.endDate;
            }

            const result = await svc.listUsage(userId, page, pageSize, { apiKeyId, groupId, model, startDate, endDate, sortBy, sortOrder });
            return legacySuccess({
                items: result.items.map((r) => ({
                    id: r.id, request_id: r.requestId, model: r.model, requested_model: r.requestedModel,
                    input_tokens: r.inputTokens, output_tokens: r.outputTokens,
                    cache_creation_tokens: r.cacheCreationTokens, cache_read_tokens: r.cacheReadTokens,
                    total_cost: r.totalCost, actual_cost: r.actualCost,
                    billing_type: r.billingType, stream: r.stream === 1,
                    duration_ms: r.durationMs, first_token_ms: r.firstTokenMs,
                    user_agent: r.userAgent, image_count: r.imageCount, video_count: r.videoCount,
                    group_id: r.groupId, subscription_id: r.subscriptionId,
                    api_key_id: r.apiKeyId, account_id: r.accountId,
                    created_at: r.createdAt,
                })),
                total: result.total, page: result.page, page_size: result.pageSize,
            });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof UsageUserError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}

function computePeriodRange(period: string): { startDate: string; endDate: string } {
    const now = new Date();
    const endDate = now.toISOString();
    let startDate: string;

    switch (period) {
        case "today": {
            const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
            startDate = todayStart.toISOString();
            break;
        }
        case "week": {
            const weekAgo = new Date(now.getTime() - 7 * 86400000);
            startDate = weekAgo.toISOString();
            break;
        }
        case "month": {
            const monthAgo = new Date(now.getTime() - 30 * 86400000);
            startDate = monthAgo.toISOString();
            break;
        }
        default: {
            const monthAgo = new Date(now.getTime() - 30 * 86400000);
            startDate = monthAgo.toISOString();
        }
    }

    return { startDate, endDate };
}
