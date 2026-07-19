import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PromoCodeService, PromoCodeError } from "../services/promo-codes.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const PROMO_CODES_PATH = "/api/v1/admin/promo-codes";
const PROMO_CODES_ID = /^\/api\/v1\/admin\/promo-codes\/(\d+)$/u;
const PROMO_CODES_ID_USAGES = /^\/api\/v1\/admin\/promo-codes\/(\d+)\/usages$/u;

export interface StagedPromoCodesEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedPromoCodesDependencies {
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
    env: StagedPromoCodesEnv,
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

export async function routeStagedPromoCodes(
    request: Request,
    env: StagedPromoCodesEnv,
    dependencies: StagedPromoCodesDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = PROMO_CODES_ID.exec(path);
    const idUsagesMatch = PROMO_CODES_ID_USAGES.exec(path);

    const isKnownPath =
        path === PROMO_CODES_PATH ||
        idMatch !== null ||
        idUsagesMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1PromoCodeService(env.DB);

        // GET /api/v1/admin/promo-codes — list
        if (path === PROMO_CODES_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const status = parseQueryString(url, "status");
            const search = parseQueryString(url, "search");
            const sortBy = parseQueryString(url, "sort_by") ?? "created_at";
            const sortOrder = parseQueryString(url, "sort_order") ?? "desc";
            const result = await service.list({ page, pageSize, status, search, sortBy, sortOrder });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // POST /api/v1/admin/promo-codes — create
        if (path === PROMO_CODES_PATH && request.method === "POST") {
            const body = await request.json() as { code?: string; bonus_amount?: number; max_uses?: number; expires_at?: string; notes?: string };
            if (!body || typeof body.bonus_amount !== "number") {
                return legacyError(400, "bonus_amount is required", "INVALID_BODY");
            }
            const created = await service.create({
                code: body.code,
                bonusAmount: body.bonus_amount,
                maxUses: body.max_uses,
                expiresAt: body.expires_at ?? null,
                notes: body.notes ?? null,
            });
            return legacySuccess(created);
        }

        // GET /api/v1/admin/promo-codes/:id — get by id
        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const code = await service.getById(id);
            return legacySuccess(code);
        }

        // PUT /api/v1/admin/promo-codes/:id — update
        if (idMatch !== null && request.method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as { code?: string; bonus_amount?: number; max_uses?: number; status?: string; expires_at?: string | null; notes?: string | null };
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, {
                code: body.code,
                bonusAmount: body.bonus_amount,
                maxUses: body.max_uses,
                status: body.status,
                expiresAt: body.expires_at,
                notes: body.notes,
            });
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/promo-codes/:id — delete
        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Promo code deleted successfully" });
        }

        // GET /api/v1/admin/promo-codes/:id/usages — list usages
        if (idUsagesMatch !== null && request.method === "GET") {
            const id = Number(idUsagesMatch[1]);
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const result = await service.listUsages(id, { page, pageSize });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof PromoCodeError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
