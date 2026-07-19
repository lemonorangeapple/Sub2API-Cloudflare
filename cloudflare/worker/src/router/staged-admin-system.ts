import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { AdminSystemError, D1AdminSystemService } from "../services/admin-system.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError,
} from "./responses.ts";

const SYSTEM_VERSION_RE = /^\/api\/v1\/admin\/system\/version\/?$/;
const SYSTEM_CHECK_UPDATES_RE = /^\/api\/v1\/admin\/system\/check-updates\/?$/;
const SYSTEM_ROLLBACK_VERSIONS_RE = /^\/api\/v1\/admin\/system\/rollback-versions\/?$/;
const SYSTEM_UPDATE_RE = /^\/api\/v1\/admin\/system\/update\/?$/;
const SYSTEM_ROLLBACK_RE = /^\/api\/v1\/admin\/system\/rollback\/?$/;
const SYSTEM_RESTART_RE = /^\/api\/v1\/admin\/system\/restart\/?$/;

export interface StagedAdminSystemEnv {
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

export function isAdminSystemPath(path: string): boolean {
    return path.startsWith("/api/v1/admin/system");
}

async function authenticateAdmin(request: Request, env: StagedAdminSystemEnv, clock: () => number): Promise<void> {
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
    if (subject.user.role !== "admin") throw new AccessAuthError("FORBIDDEN", "Admin access required");
}

export async function routeStagedAdminSystem(
    request: Request,
    env: StagedAdminSystemEnv
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (!isAdminSystemPath(pathname)) return null;
    if (env.DB === undefined) return middlewareAuthError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        await authenticateAdmin(request, env, Date.now);
        const svc = new D1AdminSystemService(env);

        // GET /admin/system/version
        if (SYSTEM_VERSION_RE.test(pathname) && method === "GET") {
            const result = await svc.getVersion();
            return legacySuccess({ version: result.version });
        }

        // GET /admin/system/check-updates
        if (SYSTEM_CHECK_UPDATES_RE.test(pathname) && method === "GET") {
            const force = url.searchParams.get("force") === "true";
            const result = await svc.checkUpdates(force);
            return legacySuccess({
                current_version: result.currentVersion,
                latest_version: result.latestVersion,
                has_update: result.hasUpdate,
                cached: result.cached,
                build_type: result.buildType,
                warning: result.warning,
            });
        }

        // GET /admin/system/rollback-versions
        if (SYSTEM_ROLLBACK_VERSIONS_RE.test(pathname) && method === "GET") {
            const result = await svc.getRollbackVersions();
            return legacySuccess({ versions: result.versions });
        }

        // POST /admin/system/update
        if (SYSTEM_UPDATE_RE.test(pathname) && method === "POST") {
            const result = await svc.performUpdate();
            return legacySuccess({
                message: result.message,
                need_restart: result.needRestart,
            });
        }

        // POST /admin/system/rollback
        if (SYSTEM_ROLLBACK_RE.test(pathname) && method === "POST") {
            let body: Record<string, unknown> = {};
            try { body = await request.json() as Record<string, unknown>; } catch { /* empty body */ }
            const version = typeof body.version === "string" ? body.version : undefined;
            const result = await svc.rollback(version);
            return legacySuccess({
                message: result.message,
                need_restart: result.needRestart,
                version: result.version,
            });
        }

        // POST /admin/system/restart
        if (SYSTEM_RESTART_RE.test(pathname) && method === "POST") {
            const result = await svc.restart();
            return legacySuccess({ message: result.message });
        }

        return routerError(405, "method_not_allowed", "Method not allowed for this system route");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AdminSystemError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
