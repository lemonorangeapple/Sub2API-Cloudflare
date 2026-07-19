import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1AffiliateRepository } from "../repositories/affiliates.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AffiliateError, D1AffiliateService } from "../services/affiliates.ts";
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

const AFF_PATH = "/api/v1/user/aff";
const AFF_TRANSFER_PATH = "/api/v1/user/aff/transfer";

export interface StagedAffiliatesUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedAffiliatesUserDependencies {
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
    env: StagedAffiliatesUserEnv,
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

export async function routeStagedAffiliatesUser(
    request: Request,
    env: StagedAffiliatesUserEnv,
    dependencies: StagedAffiliatesUserDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const isKnownPath = path === AFF_PATH || path === AFF_TRANSFER_PATH;
    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateUser(request, env, clock);
        const repo = new D1AffiliateRepository(env.DB);
        const svc = new D1AffiliateService(repo);

        if (path === AFF_PATH && request.method === "GET") {
            const detail = await svc.getAffiliateDetail(auth.userId);
            return legacySuccess(detail);
        }

        if (path === AFF_TRANSFER_PATH && request.method === "POST") {
            const result = await svc.transferAffiliateQuota(auth.userId);
            return legacySuccess(result);
        }

        return routerError(405, "method_not_allowed", "Method not allowed for this affiliate route");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AffiliateError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
