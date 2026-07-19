import { D1ChannelMonitorRepository } from "../repositories/channel-monitors.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { D1AffiliateRepository } from "../repositories/affiliates.ts";
import { AffiliateError, D1AffiliateService } from "../services/affiliates.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
} from "./responses.ts";

const BASE = "/api/v1/admin/affiliates";
const USERS_BASE = "/api/v1/admin/affiliates/users";
const USERS_RE = /^\/api\/v1\/admin\/affiliates\/users\/?$/;
const USERS_LOOKUP_RE = /^\/api\/v1\/admin\/affiliates\/users\/lookup\/?$/;
const USERS_BATCH_RATE_RE = /^\/api\/v1\/admin\/affiliates\/users\/batch-rate\/?$/;
const USER_ID_RE = /^\/api\/v1\/admin\/affiliates\/users\/(\d+)\/?$/;
const USER_OVERVIEW_RE = /^\/api\/v1\/admin\/affiliates\/users\/(\d+)\/overview\/?$/;
const INVITES_RE = /^\/api\/v1\/admin\/affiliates\/invites\/?$/;
const REBATES_RE = /^\/api\/v1\/admin\/affiliates\/rebates\/?$/;
const TRANSFERS_RE = /^\/api\/v1\/admin\/affiliates\/transfers\/?$/;

export interface StagedAffiliatesEnv {
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

export function isAffiliatePath(path: string): boolean {
    return path.startsWith(BASE);
}

function parseOptionalInt(url: URL, key: string): number | undefined {
    const v = url.searchParams.get(key);
    if (v === null || v.trim() === "") return undefined;
    const n = Number.parseInt(v.trim(), 10);
    return Number.isInteger(n) ? n : undefined;
}

function parseOptionalString(url: URL, key: string): string | undefined {
    const v = url.searchParams.get(key);
    return v !== null && v.trim() !== "" ? v.trim() : undefined;
}

function parseDateParam(raw: string | undefined): string | undefined {
    if (!raw || !raw.trim()) return undefined;
    const trimmed = raw.trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
        return trimmed + "T23:59:59.999Z";
    }
    return trimmed;
}

async function authenticateAdmin(request: Request, env: StagedAffiliatesEnv, clock: () => number): Promise<{ userId: number; role: string }> {
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

export async function routeStagedAffiliates(
    request: Request,
    env: StagedAffiliatesEnv
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    const isKnown = pathname.startsWith(BASE);
    if (!isKnown) return null;
    if (env.DB === undefined) return middlewareAuthError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, Date.now);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repo = new D1AffiliateRepository(env.DB);
        const svc = new D1AffiliateService(repo);

        // POST /admin/affiliates/users/batch-rate
        if (USERS_BATCH_RATE_RE.test(pathname) && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            const userIds = Array.isArray(body.user_ids) ? body.user_ids.map(Number) : [];
            const rate = typeof body.aff_rebate_rate_percent === "number" ? body.aff_rebate_rate_percent : null;
            const clear = body.clear === true;
            const result = await svc.batchSetRate(userIds, rate, clear);
            return legacySuccess(result);
        }

        // GET /admin/affiliates/users/lookup
        if (USERS_LOOKUP_RE.test(pathname) && method === "GET") {
            const q = url.searchParams.get("q") ?? "";
            const items = await svc.lookupUsers(q);
            return legacySuccess(items);
        }

        // GET /admin/affiliates/users
        if (USERS_RE.test(pathname) && method === "GET") {
            const page = parseOptionalInt(url, "page");
            const pageSize = parseOptionalInt(url, "page_size") ?? parseOptionalInt(url, "limit");
            const search = parseOptionalString(url, "search");
            const result = await svc.listUsers({ page, pageSize, search });
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize, pages: result.pages });
        }

        // GET /admin/affiliates/users/:user_id/overview
        const overviewMatch = USER_OVERVIEW_RE.exec(pathname);
        if (overviewMatch !== null && method === "GET") {
            const overview = await svc.getUserOverview(Number(overviewMatch[1]));
            return legacySuccess(overview);
        }

        // PUT /admin/affiliates/users/:user_id
        const userIdMatch = USER_ID_RE.exec(pathname);
        if (userIdMatch !== null && method === "PUT") {
            const body = await request.json() as Record<string, unknown>;
            const result = await svc.updateUserSettings(Number(userIdMatch[1]), {
                affCode: typeof body.aff_code === "string" ? body.aff_code : undefined,
                affRebateRatePercent: typeof body.aff_rebate_rate_percent === "number" ? body.aff_rebate_rate_percent : (body.clear_rebate_rate === true ? null : undefined),
                clearRebateRate: body.clear_rebate_rate === true,
            });
            return legacySuccess(result);
        }

        // DELETE /admin/affiliates/users/:user_id
        if (userIdMatch !== null && method === "DELETE") {
            const result = await svc.clearUserSettings(Number(userIdMatch[1]));
            return legacySuccess(result);
        }

        // GET /admin/affiliates/invites
        if (INVITES_RE.test(pathname) && method === "GET") {
            const page = parseOptionalInt(url, "page");
            const pageSize = parseOptionalInt(url, "page_size") ?? parseOptionalInt(url, "limit");
            const search = parseOptionalString(url, "search");
            const sortBy = parseOptionalString(url, "sort_by");
            const sortOrder = parseOptionalString(url, "sort_order");
            const startAt = parseDateParam(parseOptionalString(url, "start_at"));
            const endAt = parseDateParam(parseOptionalString(url, "end_at"));
            const result = await svc.listInviteRecords({ page, pageSize, search, sortBy, sortOrder, startAt, endAt });
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize, pages: result.pages });
        }

        // GET /admin/affiliates/rebates
        if (REBATES_RE.test(pathname) && method === "GET") {
            const page = parseOptionalInt(url, "page");
            const pageSize = parseOptionalInt(url, "page_size") ?? parseOptionalInt(url, "limit");
            const search = parseOptionalString(url, "search");
            const sortBy = parseOptionalString(url, "sort_by");
            const sortOrder = parseOptionalString(url, "sort_order");
            const startAt = parseDateParam(parseOptionalString(url, "start_at"));
            const endAt = parseDateParam(parseOptionalString(url, "end_at"));
            const result = await svc.listRebateRecords({ page, pageSize, search, sortBy, sortOrder, startAt, endAt });
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize, pages: result.pages });
        }

        // GET /admin/affiliates/transfers
        if (TRANSFERS_RE.test(pathname) && method === "GET") {
            const page = parseOptionalInt(url, "page");
            const pageSize = parseOptionalInt(url, "page_size") ?? parseOptionalInt(url, "limit");
            const search = parseOptionalString(url, "search");
            const sortBy = parseOptionalString(url, "sort_by");
            const sortOrder = parseOptionalString(url, "sort_order");
            const startAt = parseDateParam(parseOptionalString(url, "start_at"));
            const endAt = parseDateParam(parseOptionalString(url, "end_at"));
            const result = await svc.listTransferRecords({ page, pageSize, search, sortBy, sortOrder, startAt, endAt });
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize, pages: result.pages });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AffiliateError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
