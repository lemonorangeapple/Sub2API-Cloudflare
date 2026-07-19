import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AccountError, D1AccountService, type CreateAccountInput } from "../services/accounts.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const ACCOUNTS_PATH = "/api/v1/admin/accounts";
const ACCOUNTS_ID = /^\/api\/v1\/admin\/accounts\/(\d+)$/u;
const ACCOUNTS_ID_GROUPS = /^\/api\/v1\/admin\/accounts\/(\d+)\/groups$/u;
const ACCOUNTS_ID_STATS = /^\/api\/v1\/admin\/accounts\/(\d+)\/stats$/u;
const ACCOUNTS_ID_CLEAR_ERROR = /^\/api\/v1\/admin\/accounts\/(\d+)\/clear-error$/u;
const ACCOUNTS_ID_USAGE = /^\/api\/v1\/admin\/accounts\/(\d+)\/usage$/u;
const ACCOUNTS_ID_CLEAR_RATE_LIMIT = /^\/api\/v1\/admin\/accounts\/(\d+)\/clear-rate-limit$/u;
const ACCOUNTS_ID_RESET_QUOTA = /^\/api\/v1\/admin\/accounts\/(\d+)\/reset-quota$/u;
const ACCOUNTS_ID_TEMP_UNSCHEDULABLE = /^\/api\/v1\/admin\/accounts\/(\d+)\/temp-unschedulable$/u;
const ACCOUNTS_ID_SCHEDULABLE = /^\/api\/v1\/admin\/accounts\/(\d+)\/schedulable$/u;
const ACCOUNTS_ID_RECOVER_STATE = /^\/api\/v1\/admin\/accounts\/(\d+)\/recover-state$/u;
const ACCOUNTS_ID_SET_PRIVACY = /^\/api\/v1\/admin\/accounts\/(\d+)\/set-privacy$/u;
const ACCOUNTS_ID_TEST = /^\/api\/v1\/admin\/accounts\/(\d+)\/test$/u;
const ACCOUNTS_ID_APPLY_OAUTH = /^\/api\/v1\/admin\/accounts\/(\d+)\/apply-oauth-credentials$/u;
const ACCOUNTS_ID_TODAY_STATS = /^\/api\/v1\/admin\/accounts\/(\d+)\/today-stats$/u;
const ACCOUNTS_ID_REVERT_PROXY_FALLBACK = /^\/api\/v1\/admin\/accounts\/(\d+)\/revert-proxy-fallback$/u;
const ACCOUNTS_ID_SHADOW = /^\/api\/v1\/admin\/accounts\/(\d+)\/shadow$/u;
const ACCOUNTS_ID_MODELS = /^\/api\/v1\/admin\/accounts\/(\d+)\/models$/u;
const ACCOUNTS_ID_MODEL_SYNC = /^\/api\/v1\/admin\/accounts\/(\d+)\/models\/sync-upstream$/u;
const ACCOUNTS_ID_REFRESH = /^\/api\/v1\/admin\/accounts\/(\d+)\/refresh$/u;
const ACCOUNTS_ID_REFRESH_TIER = /^\/api\/v1\/admin\/accounts\/(\d+)\/refresh-tier$/u;
const ACCOUNTS_CHECK_MIXED_CHANNEL = "/api/v1/admin/accounts/check-mixed-channel";
const ACCOUNTS_TODAY_STATS_BATCH = "/api/v1/admin/accounts/today-stats/batch";
const ACCOUNTS_BULK_UPDATE = "/api/v1/admin/accounts/bulk-update";
const ACCOUNTS_BATCH_CLEAR_ERROR = "/api/v1/admin/accounts/batch-clear-error";
const ACCOUNTS_BATCH_REFRESH = "/api/v1/admin/accounts/batch-refresh";
const ACCOUNTS_DATA = "/api/v1/admin/accounts/data";
const ACCOUNTS_MODEL_SYNC_PREVIEW = "/api/v1/admin/accounts/models/sync-upstream-preview";
const ACCOUNTS_SYNC_CRS = "/api/v1/admin/accounts/sync/crs";
const ACCOUNTS_SYNC_CRS_PREVIEW = "/api/v1/admin/accounts/sync/crs/preview";
const ACCOUNTS_ANTIGRAVITY_DEFAULT_MAPPING = "/api/v1/admin/accounts/antigravity/default-model-mapping";
const ACCOUNTS_BATCH_REFRESH_TIER = "/api/v1/admin/accounts/batch-refresh-tier";
const ACCOUNTS_OAUTH_STUBS = new Set([
    "/api/v1/admin/accounts/generate-auth-url",
    "/api/v1/admin/accounts/generate-setup-token-url",
    "/api/v1/admin/accounts/exchange-code",
    "/api/v1/admin/accounts/exchange-setup-token-code",
    "/api/v1/admin/accounts/cookie-auth",
    "/api/v1/admin/accounts/setup-token-cookie-auth"
]);
const ACCOUNTS_BATCH = "/api/v1/admin/accounts/batch";
const ACCOUNTS_BATCH_UPDATE_CREDS = "/api/v1/admin/accounts/batch-update-credentials";
const ACCOUNTS_IMPORT_CODEX_SESSION = "/api/v1/admin/accounts/import/codex-session";

export interface StagedAccountsEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedAccountsDependencies {
    clock?: () => number;
}

function boundedIntegerEnv(
    value: string | undefined,
    defaultValue: number,
    min: number,
    max: number
): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

function parseOptionalInt(url: URL, key: string): number | undefined {
    const value = url.searchParams.get(key);
    if (value === null || value.trim() === "") return undefined;
    const parsed = Number.parseInt(value.trim(), 10);
    return Number.isInteger(parsed) ? parsed : undefined;
}

function parseQueryString(url: URL, key: string): string | undefined {
    const value = url.searchParams.get(key);
    return value !== null && value.trim() !== "" ? value.trim() : undefined;
}

function parseBoolQuery(url: URL, key: string, defaultValue = false): boolean {
    const value = url.searchParams.get(key);
    if (value === null || value.trim() === "") return defaultValue;
    return value.trim() === "true";
}

async function authenticateAdmin(
    request: Request,
    env: StagedAccountsEnv,
    clock: () => number
): Promise<{ userId: number; role: string }> {
    const authHeader = request.headers.get("authorization");
    if (!authHeader) {
        throw new AccessAuthError("UNAUTHORIZED", "Missing authorization header");
    }
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) throw new AccessAuthError("UNAUTHORIZED", "JWT secret is not configured");

    const users = new D1AuthUserRepository(env.DB!);
    const sessions = new D1AuthSessionRepository(env.DB!);
    const signer = new Hs256JwtSigner(secret, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 7 * 24 * 60 * 60), clock);
    const verifier = new Hs256JwtVerifier(secret, clock);
    const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), clock);
    const auth = new AccessAuthService(users, verifier, tokens, clock);
    const subject = await auth.authenticateAuthorization(authHeader);
    return { userId: subject.user.id, role: subject.user.role };
}

export async function routeStagedAccounts(
    request: Request,
    env: StagedAccountsEnv,
    dependencies: StagedAccountsDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = ACCOUNTS_ID.exec(path);
    const idGroupsMatch = ACCOUNTS_ID_GROUPS.exec(path);
    const idStatsMatch = ACCOUNTS_ID_STATS.exec(path);
    const idClearErrorMatch = ACCOUNTS_ID_CLEAR_ERROR.exec(path);
    const idUsageMatch = ACCOUNTS_ID_USAGE.exec(path);
    const idClearRateLimitMatch = ACCOUNTS_ID_CLEAR_RATE_LIMIT.exec(path);
    const idResetQuotaMatch = ACCOUNTS_ID_RESET_QUOTA.exec(path);
    const idTempUnschedulableMatch = ACCOUNTS_ID_TEMP_UNSCHEDULABLE.exec(path);
    const idSchedulableMatch = ACCOUNTS_ID_SCHEDULABLE.exec(path);
    const idRecoverStateMatch = ACCOUNTS_ID_RECOVER_STATE.exec(path);
    const idSetPrivacyMatch = ACCOUNTS_ID_SET_PRIVACY.exec(path);
    const idTestMatch = ACCOUNTS_ID_TEST.exec(path);
    const idApplyOAuthMatch = ACCOUNTS_ID_APPLY_OAUTH.exec(path);
    const idTodayStatsMatch = ACCOUNTS_ID_TODAY_STATS.exec(path);
    const idRevertProxyFallbackMatch = ACCOUNTS_ID_REVERT_PROXY_FALLBACK.exec(path);
    const idShadowMatch = ACCOUNTS_ID_SHADOW.exec(path);
    const idModelsMatch = ACCOUNTS_ID_MODELS.exec(path);
    const idModelSyncMatch = ACCOUNTS_ID_MODEL_SYNC.exec(path);
    const idRefreshMatch = ACCOUNTS_ID_REFRESH.exec(path);
    const idRefreshTierMatch = ACCOUNTS_ID_REFRESH_TIER.exec(path);

    const isKnownPath =
        path === ACCOUNTS_PATH ||
        path === ACCOUNTS_CHECK_MIXED_CHANNEL ||
        path === ACCOUNTS_TODAY_STATS_BATCH ||
        path === ACCOUNTS_BULK_UPDATE ||
        path === ACCOUNTS_BATCH_CLEAR_ERROR ||
        path === ACCOUNTS_BATCH_REFRESH ||
        path === ACCOUNTS_DATA ||
        path === ACCOUNTS_MODEL_SYNC_PREVIEW ||
        path === ACCOUNTS_SYNC_CRS ||
        path === ACCOUNTS_SYNC_CRS_PREVIEW ||
        path === ACCOUNTS_ANTIGRAVITY_DEFAULT_MAPPING ||
        path === ACCOUNTS_BATCH_REFRESH_TIER ||
        ACCOUNTS_OAUTH_STUBS.has(path) ||
        path === ACCOUNTS_BATCH ||
        path === ACCOUNTS_BATCH_UPDATE_CREDS ||
        path === ACCOUNTS_IMPORT_CODEX_SESSION ||
        idMatch !== null ||
        idGroupsMatch !== null ||
        idStatsMatch !== null ||
        idClearErrorMatch !== null ||
        idUsageMatch !== null ||
        idClearRateLimitMatch !== null ||
        idResetQuotaMatch !== null ||
        idTempUnschedulableMatch !== null ||
        idSchedulableMatch !== null ||
        idRecoverStateMatch !== null ||
        idSetPrivacyMatch !== null ||
        idTestMatch !== null ||
        idApplyOAuthMatch !== null ||
        idTodayStatsMatch !== null ||
        idRevertProxyFallbackMatch !== null ||
        idShadowMatch !== null ||
        idModelsMatch !== null ||
        idModelSyncMatch !== null ||
        idRefreshMatch !== null ||
        idRefreshTierMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1AccountService(env.DB);

        // GET /api/v1/admin/accounts — list
        if (path === ACCOUNTS_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const platform = parseQueryString(url, "platform");
            const type = parseQueryString(url, "type");
            const status = parseQueryString(url, "status");
            const search = parseQueryString(url, "search");
            const groupId = parseOptionalInt(url, "group");
            const groupUngrouped = parseBoolQuery(url, "group_ungrouped");
            const privacyMode = parseQueryString(url, "privacy_mode");
            const sortBy = parseQueryString(url, "sort_by") ?? "name";
            const sortOrder = parseQueryString(url, "sort_order") ?? "asc";

            const result = await service.list({ page, pageSize, platform, type, status, search, groupId, groupUngrouped, privacyMode, sortBy, sortOrder });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // POST /api/v1/admin/accounts — create
        if (path === ACCOUNTS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const created = await service.create(body as unknown as Parameters<typeof service.create>[0]);
            return legacySuccess(created);
        }

        // POST /api/v1/admin/accounts/batch — batch create
        if (path === ACCOUNTS_BATCH && request.method === "POST") {
            const body = await request.json() as { accounts?: CreateAccountInput[] };
            if (!body || !Array.isArray(body.accounts) || body.accounts.length === 0) {
                return legacyError(400, "accounts array is required", "INVALID_BODY");
            }
            const results = await service.batchCreate(body.accounts);
            return legacySuccess({ success: results.length, failed: 0, results });
        }

        // POST /api/v1/admin/accounts/batch-update-credentials
        if (path === ACCOUNTS_BATCH_UPDATE_CREDS && request.method === "POST") {
            const body = await request.json() as { account_ids?: number[]; field?: string; value?: unknown };
            if (!body || !Array.isArray(body.account_ids) || body.account_ids.length === 0) {
                return legacyError(400, "account_ids array is required", "INVALID_BODY");
            }
            if (!body.field || !["account_uuid", "org_uuid", "intercept_warmup_requests"].includes(body.field)) {
                return legacyError(400, "field must be one of: account_uuid, org_uuid, intercept_warmup_requests", "INVALID_FIELD");
            }
            const credentials = JSON.stringify({ [body.field]: body.value });
            const extra = body.value !== undefined ? JSON.stringify({}) : undefined;
            const result = await service.batchUpdateCredentials(body.account_ids, credentials, extra);
            return legacySuccess({ updated: result.updated });
        }

        if (path === ACCOUNTS_IMPORT_CODEX_SESSION && request.method === "POST") {
            return legacySuccess(await service.importCodexSession(await request.json() as Record<string, unknown>));
        }

        if (path === ACCOUNTS_CHECK_MIXED_CHANNEL && request.method === "POST") {
            const body = await request.json() as { platform?: string; group_ids?: number[]; account_id?: number };
            if (!body || typeof body.platform !== "string" || !Array.isArray(body.group_ids)) {
                return legacyError(400, "platform and group_ids are required", "INVALID_BODY");
            }
            const result = await service.checkMixedChannelRisk({ platform: body.platform, groupIds: body.group_ids, accountId: typeof body.account_id === "number" ? body.account_id : undefined });
            return legacySuccess(result);
        }

        if (path === ACCOUNTS_BULK_UPDATE && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            let accountIds = Array.isArray(body.account_ids) ? body.account_ids.map(Number) : [];
            if (accountIds.length === 0 && body.filters && typeof body.filters === "object" && !Array.isArray(body.filters)) {
                const filters = body.filters as Record<string, unknown>;
                const found = await service.list({
                    page: 1,
                    pageSize: 10000,
                    platform: typeof filters.platform === "string" ? filters.platform : undefined,
                    type: typeof filters.type === "string" ? filters.type : undefined,
                    status: typeof filters.status === "string" ? filters.status : undefined,
                    search: typeof filters.search === "string" ? filters.search : undefined,
                    groupId: typeof filters.group === "string" || typeof filters.group === "number" ? Number(filters.group) : undefined,
                    privacyMode: typeof filters.privacy_mode === "string" ? filters.privacy_mode : undefined,
                    sortBy: "id",
                    sortOrder: "asc"
                });
                accountIds = found.items.map((item) => Number(item.id));
            }
            if (accountIds.length === 0) return legacyError(400, "account_ids or filters are required", "INVALID_BODY");
            const { account_ids: _accountIds, filters: _filters, confirm_mixed_channel_risk: _confirm, ...updates } = body;
            if (Object.keys(updates).length === 0) return legacyError(400, "At least one update field is required", "INVALID_BODY");
            return legacySuccess(await service.bulkUpdate(accountIds, updates));
        }

        if (path === ACCOUNTS_BATCH_CLEAR_ERROR && request.method === "POST") {
            const body = await request.json() as { account_ids?: number[] };
            if (!body || !Array.isArray(body.account_ids) || body.account_ids.length === 0) return legacyError(400, "account_ids array is required", "INVALID_BODY");
            return legacySuccess(await service.batchClearError(body.account_ids));
        }

        if (path === ACCOUNTS_BATCH_REFRESH && request.method === "POST") {
            const body = await request.json() as { account_ids?: unknown };
            if (!body || !Array.isArray(body.account_ids)) return legacyError(400, "account_ids array is required", "INVALID_BODY");
            const ids = body.account_ids.map(Number).filter((id) => Number.isInteger(id) && id > 0);
            if (ids.length === 0) return legacyError(400, "account_ids array is required", "INVALID_BODY");
            return legacySuccess(await service.batchRefresh(ids));
        }

        if (path === ACCOUNTS_DATA && request.method === "GET") {
            const ids = (url.searchParams.get("ids") ?? "").split(",").map((value) => value.trim()).filter((value) => value !== "").map(Number).filter((value) => Number.isInteger(value) && value > 0);
            const includeProxies = url.searchParams.get("include_proxies") !== "false";
            return legacySuccess(await service.exportData(ids.length > 0 ? ids : undefined, includeProxies));
        }

        if (path === ACCOUNTS_DATA && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            return legacySuccess(await service.importData(body));
        }

        if (path === ACCOUNTS_ANTIGRAVITY_DEFAULT_MAPPING && request.method === "GET") {
            return legacySuccess(service.getAntigravityDefaultModelMapping());
        }

        if (path === ACCOUNTS_MODEL_SYNC_PREVIEW && request.method === "POST") {
            return legacySuccess(await service.syncUpstreamModelsPreview(await request.json() as Parameters<typeof service.syncUpstreamModelsPreview>[0]));
        }

        if (path === ACCOUNTS_SYNC_CRS_PREVIEW && request.method === "POST") {
            return legacySuccess(await service.previewFromCrs(await request.json() as Parameters<typeof service.previewFromCrs>[0]));
        }

        if (path === ACCOUNTS_SYNC_CRS && request.method === "POST") {
            return legacySuccess(await service.syncFromCrs(await request.json() as Parameters<typeof service.syncFromCrs>[0]));
        }

        if (ACCOUNTS_OAUTH_STUBS.has(path) && request.method === "POST") {
            return legacyError(501, "This upstream account operation is not available in serverless mode", "NOT_IMPLEMENTED");
        }

        // GET /api/v1/admin/accounts/:id
        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const account = await service.getById(id);
            return legacySuccess(account);
        }

        // PUT /api/v1/admin/accounts/:id
        if (idMatch !== null && request.method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, body);
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/accounts/:id
        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Account deleted successfully" });
        }

        // GET /api/v1/admin/accounts/:id/groups
        if (idGroupsMatch !== null && request.method === "GET") {
            const id = Number(idGroupsMatch[1]);
            const groups = await service.getGroups(id);
            return legacySuccess(groups);
        }

        // POST /api/v1/admin/accounts/:id/groups — set groups
        if (idGroupsMatch !== null && request.method === "POST") {
            const id = Number(idGroupsMatch[1]);
            const body = await request.json() as { group_ids?: number[] };
            if (!body || !Array.isArray(body.group_ids)) {
                return legacyError(400, "group_ids array is required", "INVALID_BODY");
            }
            await service.setGroups(id, body.group_ids);
            return legacySuccess({ message: "Groups updated successfully" });
        }

        // GET /api/v1/admin/accounts/:id/stats
        if (idStatsMatch !== null && request.method === "GET") {
            const id = Number(idStatsMatch[1]);
            const stats = await service.getUsageStats(id, parseOptionalInt(url, "days") ?? 30);
            return legacySuccess(stats);
        }

        if (idClearErrorMatch !== null && request.method === "POST") {
            return legacySuccess(await service.clearError(Number(idClearErrorMatch[1])));
        }

        if (idUsageMatch !== null && request.method === "GET") {
            const id = Number(idUsageMatch[1]);
            const usage = await service.getUsage(id);
            return legacySuccess(usage);
        }

        if (idClearRateLimitMatch !== null && request.method === "POST") {
            const id = Number(idClearRateLimitMatch[1]);
            const updated = await service.clearRateLimit(id);
            return legacySuccess(updated);
        }

        if (idResetQuotaMatch !== null && request.method === "POST") {
            const id = Number(idResetQuotaMatch[1]);
            const updated = await service.resetQuota(id);
            return legacySuccess(updated);
        }

        if (idTempUnschedulableMatch !== null) {
            const id = Number(idTempUnschedulableMatch[1]);
            if (request.method === "GET") {
                const status = await service.getTempUnschedulableStatus(id);
                return legacySuccess(status);
            }
            if (request.method === "DELETE") {
                const updated = await service.setTempUnschedulable(id, null, null);
                return legacySuccess(updated);
            }
        }

        if (idSchedulableMatch !== null && request.method === "POST") {
            const id = Number(idSchedulableMatch[1]);
            const body = await request.json() as { schedulable?: boolean };
            const updated = await service.setSchedulable(id, !!body?.schedulable);
            return legacySuccess(updated);
        }

        if (idRecoverStateMatch !== null && request.method === "POST") {
            const id = Number(idRecoverStateMatch[1]);
            const updated = await service.resetQuota(id);
            return legacySuccess(updated);
        }

        if (idSetPrivacyMatch !== null && request.method === "POST") {
            return legacySuccess(await service.setPrivacy(Number(idSetPrivacyMatch[1])));
        }

        if (idTestMatch !== null && request.method === "POST") {
            return legacySuccess(await service.testConnectivity(Number(idTestMatch[1])));
        }

        if (idApplyOAuthMatch !== null && request.method === "POST") {
            const body = await request.json() as { type?: string; credentials?: Record<string, unknown>; extra?: Record<string, unknown> };
            return legacySuccess(await service.applyOAuthCredentials(Number(idApplyOAuthMatch[1]), {
                type: body.type ?? "",
                credentials: body.credentials ?? {},
                extra: body.extra
            }));
        }

        if (idTodayStatsMatch !== null && request.method === "GET") {
            return legacySuccess(await service.getTodayStats(Number(idTodayStatsMatch[1])));
        }

        if (idRevertProxyFallbackMatch !== null && request.method === "POST") {
            await service.revertProxyFallback(Number(idRevertProxyFallbackMatch[1]));
            return legacySuccess({ message: "Proxy fallback reverted successfully" });
        }

        if (idShadowMatch !== null && request.method === "POST") {
            const body = await request.json() as { name?: string; priority?: number; concurrency?: number; group_ids?: number[] };
            return legacySuccess(await service.createShadow(Number(idShadowMatch[1]), body ?? {}));
        }

        if (idModelsMatch !== null && request.method === "GET") {
            return legacySuccess(await service.getAvailableModels(Number(idModelsMatch[1])));
        }

        if (idModelSyncMatch !== null && request.method === "POST") {
            return legacySuccess(await service.syncUpstreamModels(Number(idModelSyncMatch[1])));
        }

        if (idRefreshMatch !== null && request.method === "POST") {
            return legacySuccess(await service.refreshAccount(Number(idRefreshMatch[1])));
        }

        if ((idRefreshTierMatch !== null || path === ACCOUNTS_BATCH_REFRESH_TIER) && request.method === "POST") {
            return legacyError(501, "Google One tier refresh is not available in serverless mode", "NOT_IMPLEMENTED");
        }

        if (path === ACCOUNTS_TODAY_STATS_BATCH && request.method === "POST") {
            const body = await request.json() as { account_ids?: number[] };
            if (!body || !Array.isArray(body.account_ids)) {
                return legacyError(400, "account_ids array is required", "INVALID_BODY");
            }
            const stats: Record<string, unknown> = {};
            for (const accountId of body.account_ids) {
                stats[String(accountId)] = await service.getTodayStats(accountId);
            }
            return legacySuccess({ stats });
        }

        return routerError(405, "method_not_allowed", "Method not allowed for this account route");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AccountError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
