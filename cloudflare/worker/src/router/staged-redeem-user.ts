import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1RedeemCodeService, RedeemCodeError } from "../services/redeem-codes.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const REDEEM_PATH = "/api/v1/redeem";
const REDEEM_HISTORY_PATH = "/api/v1/redeem/history";

export interface StagedRedeemUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedRedeemUserDependencies {
    clock?: () => number;
}

function boundedIntegerEnv(value: string | undefined, defaultValue: number, min: number, max: number): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

async function authenticateUser(
    request: Request,
    env: StagedRedeemUserEnv,
    clock: () => number
): Promise<{ userId: number }> {
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

export async function routeStagedRedeemUser(
    request: Request,
    env: StagedRedeemUserEnv,
    dependencies: StagedRedeemUserDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const isKnownPath = path === REDEEM_PATH || path === REDEEM_HISTORY_PATH;
    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateUser(request, env, clock);
        const service = new D1RedeemCodeService(env.DB);

        if (path === REDEEM_PATH && request.method === "POST") {
            const body = await request.json() as { code?: string };
            if (!body || typeof body.code !== "string" || body.code.trim().length === 0) {
                return legacyError(400, "code is required", "INVALID_BODY");
            }
            const result = await service.redeem(auth.userId, body.code);
            return legacySuccess(result);
        }

        if (path === REDEEM_HISTORY_PATH && request.method === "GET") {
            const limitStr = url.searchParams.get("limit");
            const limit = limitStr ? Math.min(Math.max(1, Number(limitStr)), 100) : 25;
            const history = await service.listByUser(auth.userId, limit);
            return legacySuccess(history);
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof RedeemCodeError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
