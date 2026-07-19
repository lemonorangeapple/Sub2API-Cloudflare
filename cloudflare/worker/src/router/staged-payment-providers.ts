import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PaymentProviderService, PaymentProviderError } from "../services/payment-providers.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const PROVIDERS_PATH = "/api/v1/admin/payment/providers";
const PROVIDERS_ID = /^\/api\/v1\/admin\/payment\/providers\/(\d+)$/u;

export interface StagedPaymentProvidersEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedPaymentProvidersDependencies {
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

function normalizeConfig(value: unknown): string {
    if (typeof value === "string") return value;
    if (value !== null && typeof value === "object") return JSON.stringify(value);
    return "";
}

function normalizeStringOrArray(value: unknown): string {
    if (typeof value === "string") return value;
    if (Array.isArray(value)) return JSON.stringify(value);
    return "";
}

function normalizeFlag(value: unknown): number {
    if (typeof value === "boolean") return value ? 1 : 0;
    if (typeof value === "number") return value ? 1 : 0;
    return 0;
}

function transformRecordForResponse<T extends Record<string, unknown>>(record: T): T {
    const out = { ...record };
    if (typeof out.config === "string") {
        try { out.config = JSON.parse(out.config); } catch { /* keep as-is */ }
    }
    if (typeof out.supportedTypes === "string") {
        try { const p = JSON.parse(out.supportedTypes); if (Array.isArray(p)) out.supportedTypes = p; } catch { /* keep as-is */ }
    }
    if (typeof out.enabled === "number") out.enabled = out.enabled === 1;
    if (typeof out.refundEnabled === "number") out.refundEnabled = out.refundEnabled === 1;
    if (typeof out.allowUserRefund === "number") out.allowUserRefund = out.allowUserRefund === 1;
    return out;
}

async function authenticateAdmin(
    request: Request,
    env: StagedPaymentProvidersEnv,
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

export async function routeStagedPaymentProviders(
    request: Request,
    env: StagedPaymentProvidersEnv,
    dependencies: StagedPaymentProvidersDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = PROVIDERS_ID.exec(path);

    const isKnownPath =
        path === PROVIDERS_PATH ||
        idMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1PaymentProviderService(env.DB);

        // GET /api/v1/admin/payment/providers — list
        if (path === PROVIDERS_PATH && request.method === "GET") {
            const providers = await service.list();
            return legacySuccess(providers.map(transformRecordForResponse));
        }

        // POST /api/v1/admin/payment/providers — create
        if (path === PROVIDERS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const providerKey = body.provider_key;
            const config = body.config;
            if (typeof providerKey !== "string" || providerKey.trim() === "") {
                return legacyError(400, "provider_key and config are required", "INVALID_BODY");
            }
            if (config === undefined || config === null || config === "" || (typeof config !== "string" && typeof config !== "object")) {
                return legacyError(400, "provider_key and config are required", "INVALID_BODY");
            }
            const created = await service.create({
                providerKey: providerKey as string,
                name: body.name as string | undefined,
                config: normalizeConfig(config),
                supportedTypes: normalizeStringOrArray(body.supported_types),
                enabled: normalizeFlag(body.enabled),
                paymentMode: body.payment_mode as string | undefined,
                sortOrder: body.sort_order as number | undefined,
                limits: body.limits as string | undefined,
                refundEnabled: normalizeFlag(body.refund_enabled),
                allowUserRefund: normalizeFlag(body.allow_user_refund),
            });
            return legacySuccess(transformRecordForResponse(created));
        }

        // GET /api/v1/admin/payment/providers/:id — get by id
        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const provider = await service.getById(id);
            return legacySuccess(provider ? transformRecordForResponse(provider) : null);
        }

        // PUT /api/v1/admin/payment/providers/:id — update
        if (idMatch !== null && request.method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, {
                providerKey: body.provider_key as string | undefined,
                name: body.name as string | undefined,
                config: body.config !== undefined ? normalizeConfig(body.config) : undefined,
                supportedTypes: body.supported_types !== undefined ? normalizeStringOrArray(body.supported_types) : undefined,
                enabled: body.enabled !== undefined ? normalizeFlag(body.enabled) : undefined,
                paymentMode: body.payment_mode as string | undefined,
                sortOrder: body.sort_order as number | undefined,
                limits: body.limits as string | undefined,
                refundEnabled: body.refund_enabled !== undefined ? normalizeFlag(body.refund_enabled) : undefined,
                allowUserRefund: body.allow_user_refund !== undefined ? normalizeFlag(body.allow_user_refund) : undefined,
            });
            return legacySuccess(transformRecordForResponse(updated));
        }

        // DELETE /api/v1/admin/payment/providers/:id — delete
        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Payment provider deleted successfully" });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof PaymentProviderError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
