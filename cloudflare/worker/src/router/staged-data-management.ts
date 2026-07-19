import type { D1Database } from "../types/d1.ts";
import { routerError, legacySuccess } from "./responses.ts";

const DATA_MGMT_BASE = "/api/v1/admin/data-management";
const AGENT_HEALTH_PATH = "/api/v1/admin/data-management/agent/health";
const CONFIG_PATH = "/api/v1/admin/data-management/config";
const SOURCE_PROFILES_RE = /^\/api\/v1\/admin\/data-management\/sources\/(postgres|redis)\/profiles$/;
const SOURCE_PROFILE_ACTIVATE_RE = /^\/api\/v1\/admin\/data-management\/sources\/(postgres|redis)\/profiles\/([^/]+)\/activate$/;
const SOURCE_PROFILE_ID_RE = /^\/api\/v1\/admin\/data-management\/sources\/(postgres|redis)\/profiles\/([^/]+)$/;
const S3_TEST_PATH = "/api/v1/admin/data-management/s3/test";
const S3_PROFILES_PATH = "/api/v1/admin/data-management/s3/profiles";
const S3_PROFILE_ACTIVATE_RE = /^\/api\/v1\/admin\/data-management\/s3\/profiles\/([^/]+)\/activate$/;
const S3_PROFILE_ID_RE = /^\/api\/v1\/admin\/data-management\/s3\/profiles\/([^/]+)$/;
const BACKUPS_PATH = "/api/v1/admin/data-management/backups";
const BACKUP_JOB_RE = /^\/api\/v1\/admin\/data-management\/backups\/([^/]+)$/;

export interface StagedDataManagementEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export function isDataManagementPath(pathname: string): boolean {
    return pathname.startsWith(DATA_MGMT_BASE);
}

const DEPRECATED_BODY = { enabled: false, reason: "DATA_MANAGEMENT_DEPRECATED" };

export async function routeStagedDataManagement(
    request: Request,
    env: StagedDataManagementEnv,
    clock: () => number = Date.now
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (!isDataManagementPath(pathname)) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    let body: Record<string, unknown> = {};
    if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
        try {
            body = await request.json() as Record<string, unknown>;
        } catch {
            // empty body allowed
        }
    }

    // Agent health is the one route that always returns 200
    if (pathname === AGENT_HEALTH_PATH && request.method === "GET") {
        return legacySuccess({
            ...DEPRECATED_BODY,
            socket_path: "/tmp/sub2api-datamanagement.sock",
        });
    }

    // All other routes require admin auth
    try {
        const { D1AuthUserRepository } = await import("../repositories/auth-users.ts");
        const { D1AuthSessionRepository } = await import("../repositories/auth-sessions.ts");
        const { AccessAuthService, AccessAuthError } = await import("../services/access-auth.ts");
        const { AuthTokenService } = await import("../services/auth-tokens.ts");
        const { Hs256JwtSigner, Hs256JwtVerifier } = await import("../services/jwt.ts");

        const authHeader = request.headers.get("authorization");
        if (!authHeader) return routerError(401, "unauthorized", "Missing authorization header");
        const secret = env.JWT_SECRET?.trim() ?? "";
        if (!secret) return routerError(401, "unauthorized", "JWT secret is not configured");

        const expiresSec = Number.parseInt(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS ?? "86400", 10) || 86400;
        const refreshDays = Number.parseInt(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS ?? "30", 10) || 30;
        const users = new D1AuthUserRepository(env.DB);
        const sessions = new D1AuthSessionRepository(env.DB);
        const signer = new Hs256JwtSigner(secret, expiresSec, clock);
        const verifier = new Hs256JwtVerifier(secret, clock);
        const tokens = new AuthTokenService(sessions, signer, refreshDays, clock);
        const auth = new AccessAuthService(users, verifier, tokens, clock);

        const subject = await auth.authenticateAuthorization(authHeader);
        if (subject.user.role !== "admin") return routerError(403, "forbidden", "Admin access required");

        // All remaining routes are deprecated stubs (503)
        return routerError(503, "DATA_MANAGEMENT_DEPRECATED", "data management feature is deprecated");
    } catch (error: unknown) {
        if (error != null && typeof error === "object" && "code" in error) return routerError(401, "unauthorized", String((error as unknown as { message?: unknown }).message ?? "Unauthorized"));
        return routerError(500, "internal_error", error instanceof Error ? error.message : "internal server error");
    }
}
