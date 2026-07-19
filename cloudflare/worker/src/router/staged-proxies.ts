import { D1ProxyRepository } from "../repositories/proxies.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { ProxyError, D1ProxyService } from "../services/proxies.ts";
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

const PROXY_ID_PATH = /^\/api\/v1\/admin\/proxies\/(\d+)$/u;
const PROXIES_LIST = "/api/v1/admin/proxies";
const PROXIES_ALL = "/api/v1/admin/proxies/all";
const PROXIES_BATCH_DELETE = "/api/v1/admin/proxies/batch-delete";
const PROXIES_BATCH = "/api/v1/admin/proxies/batch";

export const STAGED_PROXY_PATHS = {
    list: PROXIES_LIST,
    all: PROXIES_ALL
} as const;

export interface StagedProxiesEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedProxiesDependencies {
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

async function authenticateAdmin(
    request: Request,
    env: StagedProxiesEnv,
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

export async function routeStagedProxies(
    request: Request,
    env: StagedProxiesEnv,
    dependencies: StagedProxiesDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const proxyIdMatch = PROXY_ID_PATH.exec(path);

    const isKnownPath = path === PROXIES_LIST
        || path === PROXIES_ALL
        || path === PROXIES_BATCH_DELETE
        || path === PROXIES_BATCH
        || proxyIdMatch !== null;

    if (!isKnownPath) return null;

    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") {
            return middlewareAuthError(403, "FORBIDDEN", "Admin access required");
        }

        const repository = new D1ProxyRepository(env.DB);
        const service = new D1ProxyService(repository);

        if (path === PROXIES_LIST && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const protocol = parseQueryString(url, "protocol");
            const status = parseQueryString(url, "status");
            const search = parseQueryString(url, "search");
            const sortBy = parseQueryString(url, "sort_by") ?? "id";
            const sortDir = parseQueryString(url, "sort_order") ?? "desc";

            const result = await service.listProxies({
                page,
                pageSize,
                protocol,
                status,
                search,
                sortBy,
                sortDir
            });

            return legacySuccess({
                items: result.items,
                total: result.total,
                page,
                page_size: pageSize
            });
        }

        if (path === PROXIES_ALL && request.method === "GET") {
            const proxies = await service.listAll();
            return legacySuccess(proxies);
        }

        if (proxyIdMatch !== null && request.method === "GET") {
            const proxyId = Number(proxyIdMatch[1]);
            const proxy = await service.getProxyById(proxyId);
            return legacySuccess(proxy);
        }

        if (path === PROXIES_LIST && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const name = body.name;
            if (typeof name !== "string" || name.trim().length === 0) {
                return legacyError(400, "Proxy name is required", "name_required");
            }

            const port = body.port;
            if (typeof port !== "number" || !Number.isFinite(port) || port < 1 || port > 65535) {
                return legacyError(400, "Valid port (1-65535) is required", "invalid_port");
            }

            const created = await service.createProxy({
                name: name as string,
                protocol: body.protocol as string ?? "http",
                host: body.host as string ?? "",
                port: port as number,
                username: body.username as string | undefined,
                password: body.password as string | undefined,
                expires_at: body.expires_at as string | null | undefined,
                fallback_mode: body.fallback_mode as string | undefined,
                backup_proxy_id: body.backup_proxy_id as number | null | undefined,
                expiry_warn_days: body.expiry_warn_days as number | undefined
            });
            return legacySuccess(created);
        }

        if (proxyIdMatch !== null && request.method === "PUT") {
            const proxyId = Number(proxyIdMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const updated = await service.updateProxy(proxyId, {
                name: body.name as string | undefined,
                protocol: body.protocol as string | undefined,
                host: body.host as string | undefined,
                port: body.port as number | undefined,
                username: body.username as string | undefined,
                password: body.password as string | undefined,
                status: body.status as string | undefined,
                expires_at: body.expires_at as string | null | undefined,
                fallback_mode: body.fallback_mode as string | undefined,
                backup_proxy_id: body.backup_proxy_id as number | null | undefined,
                expiry_warn_days: body.expiry_warn_days as number | undefined
            });
            return legacySuccess(updated);
        }

        if (proxyIdMatch !== null && request.method === "DELETE") {
            const proxyId = Number(proxyIdMatch[1]);
            await service.deleteProxy(proxyId);
            return legacySuccess({ message: "Proxy deleted successfully" });
        }

        if (path === PROXIES_BATCH_DELETE && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const ids = body.ids;
            if (!Array.isArray(ids) || ids.length === 0) {
                return legacyError(400, "At least one proxy ID is required", "ids_required");
            }

            const numericIds = ids.map((id: unknown) => typeof id === "number" && Number.isFinite(id) ? id : Number(id)).filter((id: number) => Number.isFinite(id) && id > 0);
            if (numericIds.length === 0) {
                return legacyError(400, "Valid proxy IDs are required", "invalid_ids");
            }

            const result = await service.batchDeleteProxies(numericIds);
            return legacySuccess(result);
        }

        if (path === PROXIES_BATCH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const proxies = body.proxies;
            if (!Array.isArray(proxies) || proxies.length === 0) {
                return legacyError(400, "At least one proxy is required", "proxies_required");
            }

            const result = await service.batchCreateProxies(proxies as Array<{ protocol: string; host: string; port: number; username?: string; password?: string }>);
            return legacySuccess(result);
        }

        return routerError(405, "method_not_allowed", "Method not allowed for this proxy route");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) {
            return middlewareAuthError(401, error.code, error.message);
        }
        if (error instanceof ProxyError) {
            return legacyError(error.status, error.message, error.code);
        }
        return legacyInternalError();
    }
}
