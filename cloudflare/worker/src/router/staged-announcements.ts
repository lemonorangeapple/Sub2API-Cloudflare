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

const ANNOUNCEMENTS_PATH = "/api/v1/admin/announcements";
const ANNOUNCEMENT_ID_PATH = /^\/api\/v1\/admin\/announcements\/(\d+)$/u;
const READ_STATUS_PATH = /^\/api\/v1\/admin\/announcements\/(\d+)\/read-status$/u;

export interface StagedAnnouncementsEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedAnnouncementsDependencies {
    clock?: () => number;
}

function boundedIntegerEnv(value: string | undefined, defaultValue: number, min: number, max: number): number {
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

async function authenticateAdmin(request: Request, env: StagedAnnouncementsEnv, clock: () => number): Promise<{ userId: number; role: string }> {
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

export async function routeStagedAnnouncements(
    request: Request,
    env: StagedAnnouncementsEnv,
    dependencies: StagedAnnouncementsDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = ANNOUNCEMENT_ID_PATH.exec(path);
    const readStatusMatch = READ_STATUS_PATH.exec(path);
    const isKnownPath = path === ANNOUNCEMENTS_PATH || idMatch !== null || readStatusMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repository = new D1AnnouncementRepository(env.DB);
        const service = new D1AnnouncementService(repository);

        if (path === ANNOUNCEMENTS_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const status = parseQueryString(url, "status");
            const search = parseQueryString(url, "search");
            const sortBy = parseQueryString(url, "sort_by") ?? "created_at";
            const sortDir = parseQueryString(url, "sort_order") ?? "desc";

            const result = await service.list({ page, pageSize, status, search, sortBy, sortDir });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        if (path === ANNOUNCEMENTS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const created = await service.create({
                title: body.title as string ?? "",
                content: body.content as string ?? "",
                status: body.status as string | undefined,
                notify_mode: body.notify_mode as string | undefined,
                targeting: body.targeting !== undefined ? JSON.stringify(body.targeting) : undefined,
                starts_at: body.starts_at as string | null | undefined,
                ends_at: body.ends_at as string | null | undefined,
                created_by: auth.userId
            });
            return legacySuccess(created);
        }

        if (readStatusMatch !== null && request.method === "GET") {
            const id = Number(readStatusMatch[1]);
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const search = parseQueryString(url, "search");

            const result = await service.listReadStatus(id, page, pageSize, search);
            return legacySuccess({
                items: result.items,
                total_readers: result.total,
                read_count: result.readCount,
                page,
                page_size: pageSize
            });
        }

        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const item = await service.getById(id);
            return legacySuccess(item);
        }

        if (idMatch !== null && request.method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const updated = await service.update(id, {
                title: body.title as string | undefined,
                content: body.content as string | undefined,
                status: body.status as string | undefined,
                notify_mode: body.notify_mode as string | undefined,
                targeting: body.targeting !== undefined ? JSON.stringify(body.targeting) : undefined,
                starts_at: body.starts_at as string | null | undefined,
                ends_at: body.ends_at as string | null | undefined,
                updated_by: auth.userId
            });
            return legacySuccess(updated);
        }

        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Announcement deleted successfully" });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AnnouncementError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
