import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AdminBackupError, D1AdminBackupsService } from "../services/admin-backups.ts";
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

const BACKUPS_BASE = "/api/v1/admin/backups";
const S3_CONFIG_PATH = "/api/v1/admin/backups/s3-config";
const S3_CONFIG_TEST_PATH = "/api/v1/admin/backups/s3-config/test";
const SCHEDULE_PATH = "/api/v1/admin/backups/schedule";
const BACKUP_ID_RE = /^\/api\/v1\/admin\/backups\/(\d+)$/;
const BACKUP_DOWNLOAD_RE = /^\/api\/v1\/admin\/backups\/(\d+)\/download-url$/;
const BACKUP_RESTORE_RE = /^\/api\/v1\/admin\/backups\/(\d+)\/restore$/;

export interface StagedAdminBackupsEnv {
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

async function authenticateAdmin(request: Request, env: StagedAdminBackupsEnv, clock: () => number): Promise<{ userId: number; role: string }> {
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

export function isAdminBackupsPath(pathname: string): boolean {
    return pathname.startsWith(BACKUPS_BASE);
}

export async function routeStagedAdminBackups(
    request: Request,
    env: StagedAdminBackupsEnv,
    clock: () => number = Date.now
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (!isAdminBackupsPath(pathname)) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    let body: Record<string, unknown> = {};
    if (request.method === "POST" || request.method === "PUT") {
        try {
            body = await request.json() as Record<string, unknown>;
        } catch {
            // Empty body allowed for some routes
        }
    }

    const idMatch = BACKUP_ID_RE.exec(pathname);
    const downloadMatch = BACKUP_DOWNLOAD_RE.exec(pathname);
    const restoreMatch = BACKUP_RESTORE_RE.exec(pathname);

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const svc = new D1AdminBackupsService(env.DB);

        // GET /api/v1/admin/backups/s3-config
        if (pathname === S3_CONFIG_PATH && request.method === "GET") {
            return legacySuccess(await svc.getS3Config());
        }

        // PUT /api/v1/admin/backups/s3-config
        if (pathname === S3_CONFIG_PATH && request.method === "PUT") {
            return legacySuccess(await svc.updateS3Config(body as Parameters<typeof svc.updateS3Config>[0]));
        }

        // POST /api/v1/admin/backups/s3-config/test
        if (pathname === S3_CONFIG_TEST_PATH && request.method === "POST") {
            return legacySuccess(await svc.testS3Connection());
        }

        // GET /api/v1/admin/backups/schedule
        if (pathname === SCHEDULE_PATH && request.method === "GET") {
            return legacySuccess(await svc.getSchedule());
        }

        // PUT /api/v1/admin/backups/schedule
        if (pathname === SCHEDULE_PATH && request.method === "PUT") {
            return legacySuccess(await svc.updateSchedule(body as Parameters<typeof svc.updateSchedule>[0]));
        }

        // POST /api/v1/admin/backups — create backup
        if (pathname === BACKUPS_BASE && request.method === "POST") {
            const expireDays = typeof body.expire_days === "number" ? body.expire_days : 14;
            return legacySuccess(await svc.createBackup(expireDays));
        }

        // GET /api/v1/admin/backups — list backups
        if (pathname === BACKUPS_BASE && request.method === "GET") {
            return legacySuccess(await svc.listBackups());
        }

        // GET /api/v1/admin/backups/:id
        if (idMatch !== null && request.method === "GET") {
            return legacySuccess(await svc.getBackup(Number(idMatch[1])));
        }

        // DELETE /api/v1/admin/backups/:id
        if (idMatch !== null && request.method === "DELETE") {
            await svc.deleteBackup(Number(idMatch[1]));
            return legacySuccess({ message: "Backup deleted successfully" });
        }

        // GET /api/v1/admin/backups/:id/download-url
        if (downloadMatch !== null && request.method === "GET") {
            return legacySuccess(await svc.getDownloadUrl(Number(downloadMatch[1])));
        }

        // POST /api/v1/admin/backups/:id/restore
        if (restoreMatch !== null && request.method === "POST") {
            const password = typeof body.password === "string" ? body.password : undefined;
            return legacySuccess(await svc.restoreBackup(Number(restoreMatch[1]), password));
        }

        return routerError(404, "not_found", "Route not found");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AdminBackupError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError(error instanceof Error ? error.message : "internal server error");
    }
}
