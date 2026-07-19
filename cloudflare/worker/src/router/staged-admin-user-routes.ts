import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { D1AdminUserRoutesRepository } from "../repositories/admin-user-routes.ts";
import type { UserListFilter } from "../repositories/admin-user-routes.ts";
import { AdminUserRoutesError, D1AdminUserRoutesService } from "../services/admin-user-routes.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { BcryptPasswordService } from "../services/password.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
} from "./responses.ts";

const USERS_RE = /^\/api\/v1\/admin\/users\/?$/;
const USER_ID_RE = /^\/api\/v1\/admin\/users\/(\d+)\/?$/;
const USER_BALANCE_RE = /^\/api\/v1\/admin\/users\/(\d+)\/balance\/?$/;
const USER_USAGE_RE = /^\/api\/v1\/admin\/users\/(\d+)\/usage\/?$/;
const USER_BALANCE_HISTORY_RE = /^\/api\/v1\/admin\/users\/(\d+)\/balance-history\/?$/;
const BATCH_CONCURRENCY_RE = /^\/api\/v1\/admin\/users\/batch-concurrency\/?$/;
const USER_PLATFORM_QUOTAS_RE = /^\/api\/v1\/admin\/users\/(\d+)\/platform-quotas\/?$/;
const USER_PLATFORM_QUOTAS_RESET_RE = /^\/api\/v1\/admin\/users\/(\d+)\/platform-quotas\/reset\/?$/;
const USER_AUTH_IDENTITIES_RE = /^\/api\/v1\/admin\/users\/(\d+)\/auth-identities\/?$/;
const USER_API_KEYS_RE = /^\/api\/v1\/admin\/users\/(\d+)\/api-keys\/?$/;
const USER_REPLACE_GROUP_RE = /^\/api\/v1\/admin\/users\/(\d+)\/replace-group\/?$/;
const USER_RPM_STATUS_RE = /^\/api\/v1\/admin\/users\/(\d+)\/rpm-status\/?$/;

export interface StagedAdminUserRoutesEnv {
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

export function isAdminUserRoutesPath(path: string): boolean {
    return path.startsWith("/api/v1/admin/users");
}

async function authenticateAdmin(request: Request, env: StagedAdminUserRoutesEnv, clock: () => number): Promise<{ userId: number; role: string }> {
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
    return { userId: subject.user.id, role: subject.user.role };
}

export async function routeStagedAdminUserRoutes(
    request: Request,
    env: StagedAdminUserRoutesEnv
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (!isAdminUserRoutesPath(pathname)) return null;
    if (env.DB === undefined) return middlewareAuthError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, Date.now);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repo = new D1AdminUserRoutesRepository(env.DB);
        const svc = new D1AdminUserRoutesService(repo);

        // GET /admin/users — list users with pagination and filters
        if (USERS_RE.test(pathname) && method === "GET") {
            const filter: UserListFilter = {
                page: parseOptionalInt(url, "page") ?? 1,
                pageSize: parseOptionalInt(url, "page_size") ?? 20,
                search: url.searchParams.get("search") || undefined,
                status: url.searchParams.get("status") || undefined,
                role: url.searchParams.get("role") || undefined,
                sortBy: url.searchParams.get("sort_by") || undefined,
                sortOrder: (url.searchParams.get("sort_order") as "asc" | "desc") || undefined,
            };
            const result = await svc.listUsers(filter);
            const pages = Math.max(1, Math.ceil(result.total / filter.pageSize));
            return legacySuccess({
                items: result.items,
                total: result.total,
                page: filter.page,
                page_size: filter.pageSize,
                pages,
            });
        }

        // POST /admin/users/batch-concurrency
        if (BATCH_CONCURRENCY_RE.test(pathname) && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            const userIds = Array.isArray(body.user_ids) ? body.user_ids.map(Number) : [];
            const all = body.all === true;
            const concurrency = typeof body.concurrency === "number" ? body.concurrency : 0;
            const mode = typeof body.mode === "string" ? body.mode : "set";
            const result = await svc.batchConcurrency(userIds, all, concurrency, mode);
            return legacySuccess(result);
        }

        // POST /admin/users/:id/platform-quotas/reset
        const resetMatch = USER_PLATFORM_QUOTAS_RESET_RE.exec(pathname);
        if (resetMatch !== null && method === "POST") {
            const id = Number(resetMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            const platform = typeof body.platform === "string" ? body.platform : "";
            const win = typeof body.window === "string" ? body.window : "";
            const quotas = await svc.resetPlatformQuotaWindow(id, platform, win);
            return legacySuccess({ platform_quotas: quotas });
        }

        // GET/PUT /admin/users/:id/platform-quotas
        const pqMatch = USER_PLATFORM_QUOTAS_RE.exec(pathname);
        if (pqMatch !== null) {
            const id = Number(pqMatch[1]);
            if (method === "GET") {
                const quotas = await svc.getPlatformQuotas(id);
                return legacySuccess({ platform_quotas: quotas });
            }
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                const rawQuotas = Array.isArray(body.quotas) ? body.quotas : [];
                const quotas = rawQuotas.map((q: Record<string, unknown>) => ({
                    platform: typeof q.platform === "string" ? q.platform : "",
                    dailyLimitUsd: typeof q.daily_limit_usd === "number" ? q.daily_limit_usd : null,
                    weeklyLimitUsd: typeof q.weekly_limit_usd === "number" ? q.weekly_limit_usd : null,
                    monthlyLimitUsd: typeof q.monthly_limit_usd === "number" ? q.monthly_limit_usd : null,
                })).filter((q) => q.platform !== "" && q.dailyLimitUsd !== undefined && q.weeklyLimitUsd !== undefined && q.monthlyLimitUsd !== undefined);
                const result = await svc.updatePlatformQuotas(id, quotas);
                return legacySuccess({ platform_quotas: result });
            }
        }

        // GET /admin/users/:id/usage
        const usageMatch = USER_USAGE_RE.exec(pathname);
        if (usageMatch !== null && method === "GET") {
            const id = Number(usageMatch[1]);
            const period = url.searchParams.get("period") ?? "month";
            const result = await svc.getUserUsage(id, period);
            return legacySuccess({ period: result.period, total_requests: result.totalRequests, total_cost: result.totalCost, total_tokens: result.totalTokens, avg_duration_ms: result.avgDurationMs });
        }

        // GET /admin/users/:id/balance-history
        const balanceHistoryMatch = USER_BALANCE_HISTORY_RE.exec(pathname);
        if (balanceHistoryMatch !== null && method === "GET") {
            const id = Number(balanceHistoryMatch[1]);
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? parseOptionalInt(url, "limit") ?? 20;
            const type = url.searchParams.get("type") ?? undefined;
            const result = await svc.getBalanceHistory(id, page, pageSize, type);
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize, pages: result.pages, total_recharged: result.totalRecharged });
        }

        // POST /admin/users/:id/balance
        const balanceMatch = USER_BALANCE_RE.exec(pathname);
        if (balanceMatch !== null && method === "POST") {
            const id = Number(balanceMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            const balance = typeof body.balance === "number" ? body.balance : 0;
            const operation = typeof body.operation === "string" ? body.operation : "add";
            const notes = typeof body.notes === "string" ? body.notes : "";
            const result = await svc.updateBalance(id, balance, operation, notes);
            return legacySuccess(result);
        }

        // POST /admin/users — create user
        if (USERS_RE.test(pathname) && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            const passwords = new BcryptPasswordService();
            const result = await svc.createUser({
                email: typeof body.email === "string" ? body.email : "",
                password: typeof body.password === "string" ? body.password : "",
                username: typeof body.username === "string" ? body.username : "",
                notes: typeof body.notes === "string" ? body.notes : "",
                role: typeof body.role === "string" ? body.role : "user",
                balance: typeof body.balance === "number" ? body.balance : null,
                concurrency: typeof body.concurrency === "number" ? body.concurrency : 0,
                rpmLimit: typeof body.rpm_limit === "number" ? body.rpm_limit : 0,
                allowedGroups: Array.isArray(body.allowed_groups) ? body.allowed_groups.map(Number) : [],
            }, passwords);
            return legacySuccess(result);
        }

        // POST /admin/users/:id/rpm-status
        const rpmMatch = USER_RPM_STATUS_RE.exec(pathname);
        if (rpmMatch !== null && method === "GET") {
            const id = Number(rpmMatch[1]);
            const result = await svc.getUserRPMStatus(id);
            return legacySuccess({ user_rpm_used: result.userRpmUsed, user_rpm_limit: result.userRpmLimit, per_group: result.perGroup });
        }

        // POST /admin/users/:id/replace-group
        const rgMatch = USER_REPLACE_GROUP_RE.exec(pathname);
        if (rgMatch !== null && method === "POST") {
            const id = Number(rgMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            const oldGroupId = typeof body.old_group_id === "number" ? body.old_group_id : 0;
            const newGroupId = typeof body.new_group_id === "number" ? body.new_group_id : 0;
            const result = await svc.replaceUserGroup(id, oldGroupId, newGroupId);
            return legacySuccess({ migrated_keys: result.migratedKeys });
        }

        // GET /admin/users/:id/api-keys
        const akMatch = USER_API_KEYS_RE.exec(pathname);
        if (akMatch !== null && method === "GET") {
            const id = Number(akMatch[1]);
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const sortBy = url.searchParams.get("sort_by") ?? "created_at";
            const sortOrder = url.searchParams.get("sort_order") ?? "desc";
            const result = await svc.getUserAPIKeys(id, page, pageSize, sortBy, sortOrder);
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize });
        }

        // POST /admin/users/:id/auth-identities
        const aiMatch = USER_AUTH_IDENTITIES_RE.exec(pathname);
        if (aiMatch !== null && method === "POST") {
            const id = Number(aiMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            const rawChannel = body.channel;
            const channel = rawChannel && typeof rawChannel === "object"
                ? {
                    channel: typeof (rawChannel as Record<string, unknown>).channel === "string" ? (rawChannel as Record<string, unknown>).channel as string : "",
                    channelAppId: typeof (rawChannel as Record<string, unknown>).channel_app_id === "string" ? (rawChannel as Record<string, unknown>).channel_app_id as string : "",
                    channelSubject: typeof (rawChannel as Record<string, unknown>).channel_subject === "string" ? (rawChannel as Record<string, unknown>).channel_subject as string : "",
                    metadata: typeof (rawChannel as Record<string, unknown>).metadata === "object" && (rawChannel as Record<string, unknown>).metadata !== null ? (rawChannel as Record<string, unknown>).metadata as Record<string, unknown> : {},
                }
                : null;
            const result = await svc.bindAuthIdentity(id, {
                providerType: typeof body.provider_type === "string" ? body.provider_type : "",
                providerKey: typeof body.provider_key === "string" ? body.provider_key : "",
                providerSubject: typeof body.provider_subject === "string" ? body.provider_subject : "",
                issuer: typeof body.issuer === "string" ? body.issuer : null,
                metadata: typeof body.metadata === "object" && body.metadata !== null ? body.metadata as Record<string, unknown> : {},
                channel,
            });
            return legacySuccess({
                id: result.id, user_id: result.userId, provider_type: result.providerType,
                provider_key: result.providerKey, provider_subject: result.providerSubject,
                verified_at: result.verifiedAt, issuer: result.issuer, metadata: result.metadata,
                created_at: result.createdAt, updated_at: result.updatedAt,
                channel: result.channel ? {
                    channel: result.channel.channel, channel_app_id: result.channel.channelAppId,
                    channel_subject: result.channel.channelSubject, metadata: result.channel.metadata,
                    created_at: result.channel.createdAt, updated_at: result.channel.updatedAt,
                } : undefined,
            });
        }

        // /admin/users/:id — PUT, DELETE, GET
        const idMatch = USER_ID_RE.exec(pathname);

        if (idMatch !== null && method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            const passwords = new BcryptPasswordService();
            const result = await svc.updateUser(id, {
                email: typeof body.email === "string" ? body.email : undefined,
                password: typeof body.password === "string" ? body.password : undefined,
                username: body.username !== undefined ? (typeof body.username === "string" ? body.username : "") : undefined,
                notes: body.notes !== undefined ? (typeof body.notes === "string" ? body.notes : "") : undefined,
                role: typeof body.role === "string" ? body.role : undefined,
                status: typeof body.status === "string" ? body.status : undefined,
                balance: body.balance !== undefined ? (typeof body.balance === "number" ? body.balance : 0) : undefined,
                concurrency: body.concurrency !== undefined ? (typeof body.concurrency === "number" ? body.concurrency : 0) : undefined,
                rpmLimit: body.rpm_limit !== undefined ? (typeof body.rpm_limit === "number" ? body.rpm_limit : 0) : undefined,
                allowedGroups: body.allowed_groups !== undefined ? (Array.isArray(body.allowed_groups) ? body.allowed_groups.map(Number) : []) : undefined,
                groupRates: typeof body.group_rates === "object" && body.group_rates !== null ? body.group_rates as Record<string, number | null> : undefined,
            }, passwords, auth.userId);
            return legacySuccess(result);
        }

        // DELETE /admin/users/:id
        if (idMatch !== null && method === "DELETE") {
            const id = Number(idMatch[1]);
            await svc.deleteUser(id);
            return legacySuccess({ message: "User deleted successfully" });
        }

        // GET /admin/users/:id
        if (idMatch !== null && method === "GET") {
            const id = Number(idMatch[1]);
            const includeDeleted = url.searchParams.get("include_deleted") === "true";
            const user = await svc.getUserById(id, includeDeleted);
            return legacySuccess(user);
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AdminUserRoutesError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
