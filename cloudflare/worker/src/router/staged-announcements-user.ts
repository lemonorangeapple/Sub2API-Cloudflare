import { D1AnnouncementRepository } from "../repositories/announcements.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AnnouncementError, D1AnnouncementService } from "../services/announcements.ts";
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

const ANNOUNCEMENTS_PATH = "/api/v1/announcements";
const ANNOUNCEMENT_READ_PATH = /^\/api\/v1\/announcements\/(\d+)\/read$/u;

export interface StagedAnnouncementsUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedAnnouncementsUserDependencies {
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
    env: StagedAnnouncementsUserEnv,
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

export async function routeStagedAnnouncementsUser(
    request: Request,
    env: StagedAnnouncementsUserEnv,
    dependencies: StagedAnnouncementsUserDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const readMatch = ANNOUNCEMENT_READ_PATH.exec(path);
    const isKnownPath = path === ANNOUNCEMENTS_PATH || readMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateUser(request, env, clock);
        const repository = new D1AnnouncementRepository(env.DB);
        const service = new D1AnnouncementService(repository, env.DB);

        if (path === ANNOUNCEMENTS_PATH && request.method === "GET") {
            const unreadOnly = url.searchParams.get("unread_only") === "true";
            const now = new Date(clock()).toISOString();
            const items = await service.listForUser(auth.userId, unreadOnly, now);
            return legacySuccess(items);
        }

        if (readMatch !== null && request.method === "POST") {
            const id = Number(readMatch[1]);
            const now = new Date(clock()).toISOString();
            await service.markRead(auth.userId, id, now);
            return legacySuccess({ message: "ok" });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AnnouncementError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
