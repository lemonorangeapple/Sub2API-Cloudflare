import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ChannelMonitorRepository } from "../repositories/channel-monitors.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { ChannelMonitorsUserError, D1ChannelMonitorsUserService } from "../services/channel-monitors-user.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const LIST_RE = /^\/api\/v1\/channel-monitors\/?$/;
const STATUS_RE = /^\/api\/v1\/channel-monitors\/(\d+)\/status\/?$/;

export function isChannelMonitorsUserPath(path: string): boolean {
    return path.startsWith("/api/v1/channel-monitors");
}

export interface StagedChannelMonitorsUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    TOTP_ENCRYPTION_KEY?: string;
}

function boundedIntegerEnv(value: string | undefined, defaultValue: number, min: number, max: number): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

async function authenticateUser(request: Request, env: StagedChannelMonitorsUserEnv, clock: () => number): Promise<void> {
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
    await auth.authenticateAuthorization(authHeader);
}

export async function routeStagedChannelMonitorsUser(
    request: Request,
    env: StagedChannelMonitorsUserEnv,
    clock: () => number = Date.now
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (!isChannelMonitorsUserPath(pathname)) return null;
    if (method !== "GET") return routerError(405, "method_not_allowed", "Use GET");
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    const repo = new D1ChannelMonitorRepository(env.DB);
    const svc = new D1ChannelMonitorsUserService(repo);

    try {
        await authenticateUser(request, env, clock);

        // GET /api/v1/channel-monitors/:id/status
        const statusMatch = STATUS_RE.exec(pathname);
        if (statusMatch !== null) {
            return legacySuccess(await svc.getDetail(Number(statusMatch[1])));
        }

        // GET /api/v1/channel-monitors
        if (LIST_RE.test(pathname)) {
            return legacySuccess(await svc.list());
        }

        return routerError(404, "not_found", "Route not found");
    } catch (error) {
        if (error instanceof AccessAuthError) return middlewareAuthError(error.status, error.code, error.message);
        if (error instanceof ChannelMonitorsUserError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError(error instanceof Error ? error.message : "internal server error");
    }
}
