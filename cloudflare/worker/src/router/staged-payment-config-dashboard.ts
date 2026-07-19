import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PaymentConfigDashboardService, PaymentConfigDashboardError } from "../services/payment-config-dashboard.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const CONFIG_PATH = "/api/v1/admin/payment/config";
const DASHBOARD_PATH = "/api/v1/admin/payment/dashboard";

export interface StagedPaymentConfigDashboardEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedPaymentConfigDashboardDependencies {
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

async function authenticateAdmin(
    request: Request,
    env: StagedPaymentConfigDashboardEnv,
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
    const authSubject = await auth.authenticateAuthorization(authHeader);
    return { userId: authSubject.user.id, role: authSubject.user.role };
}

function snakeToCamelMap(input: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
        const camelKey = key.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
        out[camelKey] = value;
    }
    return out;
}

export async function routeStagedPaymentConfigDashboard(
    request: Request,
    env: StagedPaymentConfigDashboardEnv,
    dependencies: StagedPaymentConfigDashboardDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const isKnownPath = path === CONFIG_PATH || path === DASHBOARD_PATH;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1PaymentConfigDashboardService(env.DB);

        // GET /api/v1/admin/payment/config — get config
        if (path === CONFIG_PATH && request.method === "GET") {
            const cfg = await service.getConfig();
            return legacySuccess(cfg);
        }

        // PUT /api/v1/admin/payment/config — update config
        if (path === CONFIG_PATH && request.method === "PUT") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            await service.updateConfig(snakeToCamelMap(body) as any);
            return legacySuccess({ message: "updated" });
        }

        // GET /api/v1/admin/payment/dashboard — dashboard stats
        if (path === DASHBOARD_PATH && request.method === "GET") {
            const daysParam = url.searchParams.get("days");
            const days = daysParam ? Math.max(1, parseInt(daysParam, 10) || 30) : 30;
            const stats = await service.getDashboardStats(days);
            return legacySuccess(stats);
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof PaymentConfigDashboardError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
