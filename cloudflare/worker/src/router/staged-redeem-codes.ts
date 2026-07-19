import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { D1RedeemCodeService, RedeemCodeError } from "../services/redeem-codes.ts";
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

const REDEEM_CODES_PATH = "/api/v1/admin/redeem-codes";
const REDEEM_CODES_STATS = "/api/v1/admin/redeem-codes/stats";
const REDEEM_CODES_EXPORT = "/api/v1/admin/redeem-codes/export";
const REDEEM_CODES_GENERATE = "/api/v1/admin/redeem-codes/generate";
const REDEEM_CODES_CREATE_AND_REDEEM = "/api/v1/admin/redeem-codes/create-and-redeem";
const REDEEM_CODES_BATCH_DELETE = "/api/v1/admin/redeem-codes/batch-delete";
const REDEEM_CODES_BATCH_UPDATE = "/api/v1/admin/redeem-codes/batch-update";
const REDEEM_CODES_ID = /^\/api\/v1\/admin\/redeem-codes\/(\d+)$/u;
const REDEEM_CODES_ID_EXPIRE = /^\/api\/v1\/admin\/redeem-codes\/(\d+)\/expire$/u;

export interface StagedRedeemCodesEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedRedeemCodesDependencies {
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
    env: StagedRedeemCodesEnv,
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

export async function routeStagedRedeemCodes(
    request: Request,
    env: StagedRedeemCodesEnv,
    dependencies: StagedRedeemCodesDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = REDEEM_CODES_ID.exec(path);
    const idExpireMatch = REDEEM_CODES_ID_EXPIRE.exec(path);

    const isKnownPath =
        path === REDEEM_CODES_PATH ||
        path === REDEEM_CODES_STATS ||
        path === REDEEM_CODES_EXPORT ||
        path === REDEEM_CODES_GENERATE ||
        path === REDEEM_CODES_CREATE_AND_REDEEM ||
        path === REDEEM_CODES_BATCH_DELETE ||
        path === REDEEM_CODES_BATCH_UPDATE ||
        idMatch !== null ||
        idExpireMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1RedeemCodeService(env.DB);

        // GET /api/v1/admin/redeem-codes — list
        if (path === REDEEM_CODES_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const type = parseQueryString(url, "type");
            const status = parseQueryString(url, "status");
            const search = parseQueryString(url, "search");
            const sortBy = parseQueryString(url, "sort_by") ?? "id";
            const sortOrder = parseQueryString(url, "sort_order") ?? "desc";
            const result = await service.list({ page, pageSize, type, status, search, sortBy, sortOrder });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // GET /api/v1/admin/redeem-codes/stats
        if (path === REDEEM_CODES_STATS && request.method === "GET") {
            const stats = await service.getStats();
            return legacySuccess(stats);
        }

        // GET /api/v1/admin/redeem-codes/export
        if (path === REDEEM_CODES_EXPORT && request.method === "GET") {
            const type = parseQueryString(url, "type");
            const status = parseQueryString(url, "status");
            const search = parseQueryString(url, "search");
            const sortBy = parseQueryString(url, "sort_by") ?? "id";
            const sortOrder = parseQueryString(url, "sort_order") ?? "desc";
            const csv = await service.export({ type, status, search, sortBy, sortOrder });
            return new Response(csv, {
                status: 200,
                headers: {
                    "content-type": "text/csv",
                    "content-disposition": "attachment; filename=redeem_codes.csv",
                },
            });
        }

        // POST /api/v1/admin/redeem-codes/generate
        if (path === REDEEM_CODES_GENERATE && request.method === "POST") {
            const body = await request.json() as { count?: number; type?: string; value?: number; group_id?: number; validity_days?: number; expires_at?: string; expires_in_days?: number };
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const created = await service.generate({
                count: body.count ?? 1,
                type: body.type ?? "balance",
                value: body.value ?? 0,
                groupId: body.group_id ?? null,
                validityDays: body.validity_days ?? 30,
                expiresAt: body.expires_at ?? null,
                expiresInDays: body.expires_in_days ?? null,
            });
            return legacySuccess(created);
        }

        // POST /api/v1/admin/redeem-codes/create-and-redeem
        if (path === REDEEM_CODES_CREATE_AND_REDEEM && request.method === "POST") {
            const body = await request.json() as { code?: string; type?: string; value?: number; user_id?: number; group_id?: number; validity_days?: number; notes?: string; expires_at?: string; expires_in_days?: number };
            if (!body || typeof body.code !== "string" || typeof body.user_id !== "number" || typeof body.value !== "number") {
                return legacyError(400, "code, value, and user_id are required", "INVALID_BODY");
            }
            const result = await service.createAndRedeem({
                code: body.code,
                type: body.type,
                value: body.value,
                userId: body.user_id,
                groupId: body.group_id ?? null,
                validityDays: body.validity_days,
                notes: body.notes,
                expiresAt: body.expires_at ?? null,
                expiresInDays: body.expires_in_days ?? null,
            });
            return legacySuccess(result);
        }

        // POST /api/v1/admin/redeem-codes/batch-delete
        if (path === REDEEM_CODES_BATCH_DELETE && request.method === "POST") {
            const body = await request.json() as { ids?: number[] };
            if (!body || !Array.isArray(body.ids) || body.ids.length === 0) {
                return legacyError(400, "ids array is required", "INVALID_BODY");
            }
            const deleted = await service.batchDelete(body.ids);
            return legacySuccess({ deleted, message: "Redeem codes deleted successfully" });
        }

        // POST /api/v1/admin/redeem-codes/batch-update
        if (path === REDEEM_CODES_BATCH_UPDATE && request.method === "POST") {
            const body = await request.json() as { ids?: number[]; fields?: { status?: string; expires_at?: string | null; notes?: string | null; group_id?: number | null } };
            if (!body || !Array.isArray(body.ids) || body.ids.length === 0 || !body.fields) {
                return legacyError(400, "ids and fields are required", "INVALID_BODY");
            }
            const result = await service.batchUpdate({ ids: body.ids, fields: body.fields });
            return legacySuccess({ updated: result.updated, message: "Redeem codes updated successfully" });
        }

        // GET /api/v1/admin/redeem-codes/:id
        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const code = await service.getById(id);
            return legacySuccess(code);
        }

        // DELETE /api/v1/admin/redeem-codes/:id
        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Redeem code deleted successfully" });
        }

        // POST /api/v1/admin/redeem-codes/:id/expire
        if (idExpireMatch !== null && request.method === "POST") {
            const id = Number(idExpireMatch[1]);
            const code = await service.expire(id);
            return legacySuccess(code);
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof RedeemCodeError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
