import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { D1SubscriptionService, SubscriptionError } from "../services/subscriptions.ts";
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

const SUBSCRIPTIONS_PATH = "/api/v1/admin/subscriptions";
const SUBSCRIPTIONS_ASSIGN = "/api/v1/admin/subscriptions/assign";
const SUBSCRIPTIONS_BULK_ASSIGN = "/api/v1/admin/subscriptions/bulk-assign";
const SUBSCRIPTIONS_ID = /^\/api\/v1\/admin\/subscriptions\/(\d+)$/u;
const SUBSCRIPTIONS_ID_PROGRESS = /^\/api\/v1\/admin\/subscriptions\/(\d+)\/progress$/u;
const SUBSCRIPTIONS_ID_EXTEND = /^\/api\/v1\/admin\/subscriptions\/(\d+)\/extend$/u;
const SUBSCRIPTIONS_ID_RESET_QUOTA = /^\/api\/v1\/admin\/subscriptions\/(\d+)\/reset-quota$/u;
const SUBSCRIPTIONS_ID_REVOKE = /^\/api\/v1\/admin\/subscriptions\/(\d+)\/revoke$/u;
const SUBSCRIPTIONS_ID_RESTORE = /^\/api\/v1\/admin\/subscriptions\/(\d+)\/restore$/u;
const GROUPS_ID_SUBSCRIPTIONS = /^\/api\/v1\/admin\/groups\/(\d+)\/subscriptions$/u;
const USERS_ID_SUBSCRIPTIONS = /^\/api\/v1\/admin\/users\/(\d+)\/subscriptions$/u;

export interface StagedSubscriptionsEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedSubscriptionsDependencies {
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

async function authenticateAdmin(
    request: Request,
    env: StagedSubscriptionsEnv,
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

export async function routeStagedSubscriptions(
    request: Request,
    env: StagedSubscriptionsEnv,
    dependencies: StagedSubscriptionsDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = SUBSCRIPTIONS_ID.exec(path);
    const idProgressMatch = SUBSCRIPTIONS_ID_PROGRESS.exec(path);
    const idExtendMatch = SUBSCRIPTIONS_ID_EXTEND.exec(path);
    const idResetQuotaMatch = SUBSCRIPTIONS_ID_RESET_QUOTA.exec(path);
    const idRevokeMatch = SUBSCRIPTIONS_ID_REVOKE.exec(path);
    const idRestoreMatch = SUBSCRIPTIONS_ID_RESTORE.exec(path);
    const groupSubsMatch = GROUPS_ID_SUBSCRIPTIONS.exec(path);
    const userSubsMatch = USERS_ID_SUBSCRIPTIONS.exec(path);

    const isKnownPath =
        path === SUBSCRIPTIONS_PATH ||
        path === SUBSCRIPTIONS_ASSIGN ||
        path === SUBSCRIPTIONS_BULK_ASSIGN ||
        idMatch !== null ||
        idProgressMatch !== null ||
        idExtendMatch !== null ||
        idResetQuotaMatch !== null ||
        idRevokeMatch !== null ||
        idRestoreMatch !== null ||
        groupSubsMatch !== null ||
        userSubsMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1SubscriptionService(env.DB);

        // GET /api/v1/admin/subscriptions — list
        if (path === SUBSCRIPTIONS_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const userId = parseOptionalInt(url, "user_id");
            const groupId = parseOptionalInt(url, "group_id");
            const status = parseQueryString(url, "status");
            const platform = parseQueryString(url, "platform");
            const sortBy = parseQueryString(url, "sort_by") ?? "created_at";
            const sortOrder = parseQueryString(url, "sort_order") ?? "desc";
            const result = await service.list({ page, pageSize, userId, groupId, status, platform, sortBy, sortOrder });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // POST /api/v1/admin/subscriptions/assign — assign subscription
        if (path === SUBSCRIPTIONS_ASSIGN && request.method === "POST") {
            const body = await request.json() as { user_id?: number; group_id?: number; validity_days?: number; notes?: string };
            if (!body || typeof body.user_id !== "number" || typeof body.group_id !== "number") {
                return legacyError(400, "user_id and group_id are required", "INVALID_BODY");
            }
            const created = await service.assign({
                userId: body.user_id,
                groupId: body.group_id,
                validityDays: body.validity_days ?? 30,
                assignedBy: auth.userId,
                notes: body.notes,
            });
            return legacySuccess(created);
        }

        // POST /api/v1/admin/subscriptions/bulk-assign — bulk assign
        if (path === SUBSCRIPTIONS_BULK_ASSIGN && request.method === "POST") {
            const body = await request.json() as { user_ids?: number[]; group_id?: number; validity_days?: number; notes?: string };
            if (!body || !Array.isArray(body.user_ids) || body.user_ids.length === 0 || typeof body.group_id !== "number") {
                return legacyError(400, "user_ids array and group_id are required", "INVALID_BODY");
            }
            const result = await service.bulkAssign({
                userIds: body.user_ids,
                groupId: body.group_id,
                validityDays: body.validity_days ?? 30,
                assignedBy: auth.userId,
                notes: body.notes,
            });
            return legacySuccess(result);
        }

        // GET /api/v1/admin/subscriptions/:id — get by ID
        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const sub = await service.getById(id);
            return legacySuccess(sub);
        }

        // GET /api/v1/admin/subscriptions/:id/progress — get progress
        if (idProgressMatch !== null && request.method === "GET") {
            const id = Number(idProgressMatch[1]);
            const progress = await service.getProgress(id);
            return legacySuccess(progress);
        }

        // POST /api/v1/admin/subscriptions/:id/extend — extend/shorten
        if (idExtendMatch !== null && request.method === "POST") {
            const id = Number(idExtendMatch[1]);
            const body = await request.json() as { days?: number };
            if (!body || typeof body.days !== "number") {
                return legacyError(400, "days is required", "INVALID_BODY");
            }
            const updated = await service.extend(id, body.days);
            return legacySuccess(updated);
        }

        // POST /api/v1/admin/subscriptions/:id/reset-quota — reset usage
        if (idResetQuotaMatch !== null && request.method === "POST") {
            const id = Number(idResetQuotaMatch[1]);
            const body = await request.json() as { daily?: boolean; weekly?: boolean; monthly?: boolean };
            if (!body || (!body.daily && !body.weekly && !body.monthly)) {
                return legacyError(400, "At least one of daily, weekly, or monthly must be true", "INVALID_BODY");
            }
            const updated = await service.resetQuota(id, !!body.daily, !!body.weekly, !!body.monthly);
            return legacySuccess(updated);
        }

        // POST /api/v1/admin/subscriptions/:id/revoke — revoke
        if (idRevokeMatch !== null && request.method === "POST") {
            const id = Number(idRevokeMatch[1]);
            await service.revoke(id);
            return legacySuccess({ message: "Subscription revoked successfully" });
        }

        // POST /api/v1/admin/subscriptions/:id/restore — restore
        if (idRestoreMatch !== null && request.method === "POST") {
            const id = Number(idRestoreMatch[1]);
            const updated = await service.restore(id);
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/subscriptions/:id — revoke (backward compat)
        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.revoke(id);
            return legacySuccess({ message: "Subscription revoked successfully" });
        }

        // GET /api/v1/admin/groups/:id/subscriptions — list by group
        if (groupSubsMatch !== null && request.method === "GET") {
            const groupId = Number(groupSubsMatch[1]);
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const result = await service.listByGroup(groupId, page, pageSize);
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // GET /api/v1/admin/users/:id/subscriptions — list by user
        if (userSubsMatch !== null && request.method === "GET") {
            const userId = Number(userSubsMatch[1]);
            const subs = await service.listByUser(userId);
            return legacySuccess(subs);
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof SubscriptionError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
