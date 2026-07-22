import { D1ApiKeyRepository, type ApiKeyRecord } from "../repositories/api-keys.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { allRows } from "../repositories/d1.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { ApiKeyError, D1ApiKeyService } from "../services/api-keys.ts";
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

const KEY_PATH = /^\/api\/v1\/keys(?:\/(\d+))?$/u;
const AVAILABLE_GROUPS_PATH = "/api/v1/groups/available";
const USER_GROUP_RATES_PATH = "/api/v1/groups/rates";
const ADMIN_KEY_PATH = /^\/api\/v1\/admin\/api-keys\/(\d+)$/u;
const ADMIN_USER_KEYS_PATH = /^\/api\/v1\/admin\/users\/(\d+)\/api-keys$/u;
const ADMIN_SEARCH_KEYS_PATH = "/api/v1/admin/usage/search-api-keys";

export const STAGED_API_KEY_PATHS = {
    keys: "/api/v1/keys",
    availableGroups: AVAILABLE_GROUPS_PATH,
    userGroupRates: USER_GROUP_RATES_PATH,
    adminSearchKeys: ADMIN_SEARCH_KEYS_PATH
} as const;

export interface StagedApiKeysEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedApiKeysDependencies {
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

function stringField(body: Record<string, unknown>, key: string): string {
    const value = body[key];
    return typeof value === "string" ? value : "";
}

function optionalNumber(body: Record<string, unknown>, key: string): number | undefined {
    const value = body[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim() !== "") {
        const parsed = Number.parseFloat(value);
        if (Number.isFinite(parsed)) return parsed;
    }
    return undefined;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
    const value = body[key];
    return typeof value === "string" ? value : undefined;
}

function optionalStringArray(body: Record<string, unknown>, key: string): string[] | undefined {
    const value = body[key];
    if (!Array.isArray(value)) return undefined;
    return value.filter((item): item is string => typeof item === "string");
}

function optionalBoolean(body: Record<string, unknown>, key: string): boolean | undefined {
    const value = body[key];
    if (typeof value === "boolean") return value;
    if (typeof value === "string") return value === "true" || value === "1";
    return undefined;
}

async function authenticateAdmin(
    request: Request,
    env: StagedApiKeysEnv,
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

function parseQueryString(url: URL, key: string): string | undefined {
    const value = url.searchParams.get(key);
    return value !== null && value.trim() !== "" ? value.trim() : undefined;
}

function parseOptionalInt(url: URL, key: string): number | undefined {
    const value = url.searchParams.get(key);
    if (value === null || value.trim() === "") return undefined;
    const parsed = Number.parseInt(value.trim(), 10);
    return Number.isInteger(parsed) ? parsed : undefined;
}

export async function routeStagedApiKeys(
    request: Request,
    env: StagedApiKeysEnv,
    dependencies: StagedApiKeysDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const keyMatch = KEY_PATH.exec(path);
    const adminKeyMatch = ADMIN_KEY_PATH.exec(path);
    const adminUserKeysMatch = ADMIN_USER_KEYS_PATH.exec(path);

    const isKnownPath = keyMatch !== null
        || path === AVAILABLE_GROUPS_PATH
        || path === USER_GROUP_RATES_PATH
        || adminKeyMatch !== null
        || adminUserKeysMatch !== null
        || path === ADMIN_SEARCH_KEYS_PATH;

    if (!isKnownPath) return null;

    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    try {
        const auth = await authenticateAdmin(request, env, clock);
        const repository = new D1ApiKeyRepository(env.DB);
        const service = new D1ApiKeyService(repository);

        const isAdmin = auth.role === "admin";
        const hasKeyParam = keyMatch !== null && keyMatch[1] !== undefined;

        if (keyMatch !== null) {
            const keyId = hasKeyParam ? Number(keyMatch[1]) : undefined;

            if (request.method === "GET" && !hasKeyParam) {
                const page = parseOptionalInt(url, "page") ?? 1;
                const pageSize = parseOptionalInt(url, "page_size") ?? 20;
                const search = parseQueryString(url, "search");
                const status = parseQueryString(url, "status");
                const groupId = parseOptionalInt(url, "group_id");
                const orderBy = parseQueryString(url, "order_by") ?? "id";
                const orderDir = (parseQueryString(url, "order_dir") as "asc" | "desc") ?? "desc";

                const result = await service.listKeys({
                    userId: auth.userId,
                    page,
                    pageSize,
                    search,
                    status,
                    groupId,
                    orderBy,
                    orderDir
                });

                return legacySuccess({
                    items: result.items.map(maskKey),
                    total: result.total,
                    page,
                    page_size: pageSize
                });
            }

            if (request.method === "POST" && !hasKeyParam) {
                const body = await request.json() as Record<string, unknown>;
                if (body === null || typeof body !== "object" || Array.isArray(body)) {
                    return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
                }
                const created = await service.createKey(auth.userId, {
                    name: stringField(body, "name"),
                    key: optionalString(body, "key"),
                    group_id: optionalNumber(body, "group_id"),
                    ip_whitelist: optionalStringArray(body, "ip_whitelist"),
                    ip_blacklist: optionalStringArray(body, "ip_blacklist"),
                    quota: optionalNumber(body, "quota"),
                    expires_at: optionalString(body, "expires_at"),
                    rate_limit_5h: optionalNumber(body, "rate_limit_5h"),
                    rate_limit_1d: optionalNumber(body, "rate_limit_1d"),
                    rate_limit_7d: optionalNumber(body, "rate_limit_7d")
                });
                return legacySuccess(maskKey(created));
            }

            if (hasKeyParam && keyId !== undefined) {
                if (request.method === "GET") {
                    const key = await service.getKeyById(keyId, auth.userId);
                    return legacySuccess(maskKey(key));
                }

                if (request.method === "PUT") {
                    const body = await request.json() as Record<string, unknown>;
                    if (body === null || typeof body !== "object" || Array.isArray(body)) {
                        return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
                    }
                    const updated = await service.updateKey(keyId, auth.userId, {
                        name: optionalString(body, "name"),
                        group_id: body.group_id === null ? null : optionalNumber(body, "group_id"),
                        status: optionalString(body, "status"),
                        ip_whitelist: optionalStringArray(body, "ip_whitelist"),
                        ip_blacklist: optionalStringArray(body, "ip_blacklist"),
                        quota: optionalNumber(body, "quota"),
                        expires_at: body.expires_at === null ? null : optionalString(body, "expires_at"),
                        rate_limit_5h: optionalNumber(body, "rate_limit_5h"),
                        rate_limit_1d: optionalNumber(body, "rate_limit_1d"),
                        rate_limit_7d: optionalNumber(body, "rate_limit_7d"),
                        reset_quota: optionalBoolean(body, "reset_quota"),
                        reset_rate_limits: optionalBoolean(body, "reset_rate_limits")
                    });
                    return legacySuccess(maskKey(updated));
                }

                if (request.method === "DELETE") {
                    await service.deleteKey(keyId, auth.userId);
                    return legacySuccess({ message: "API key deleted successfully" });
                }
            }

            return routerError(405, "method_not_allowed", `${path} method not allowed`);
        }

        if (path === AVAILABLE_GROUPS_PATH && request.method === "GET") {
            const available = await allRows<Record<string, unknown>>(
                env.DB,
                `SELECT g.* FROM groups g
                 JOIN user_allowed_groups uag ON g.id = uag.group_id
                 WHERE uag.user_id = ? AND g.deleted_at IS NULL AND g.status = 'active'
                 ORDER BY g.sort_order, g.name`,
                [auth.userId]
            );
            return legacySuccess({ groups: available });
        }

        if (path === USER_GROUP_RATES_PATH && request.method === "GET") {
            const rates = await allRows<{ group_id: number; rate_multiplier: number | null; rpm_override: number | null }>(
                env.DB,
                `SELECT ugrm.group_id, ugrm.rate_multiplier, ugrm.rpm_override
                 FROM user_group_rate_multipliers ugrm
                 JOIN groups g ON ugrm.group_id = g.id
                 WHERE ugrm.user_id = ? AND g.deleted_at IS NULL`,
                [auth.userId]
            );
            const ratesMap: Record<string, number> = {};
            for (const r of rates) {
                if (r.rate_multiplier !== null) ratesMap[String(r.group_id)] = r.rate_multiplier;
            }
            return legacySuccess({ rates: ratesMap });
        }

        if (adminKeyMatch !== null && isAdmin) {
            const targetId = Number(adminKeyMatch[1]);
            if (request.method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                if (body === null || typeof body !== "object" || Array.isArray(body)) {
                    return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
                }
                const adminRepo = new D1ApiKeyRepository(env.DB);
                const updated = await adminRepo.update(targetId, 0, {
                    groupId: optionalNumber(body, "group_id"),
                    resetRateLimits: optionalBoolean(body, "reset_rate_limits")
                });
                if (updated === null) {
                    return legacyError(404, "API key not found", "KEY_NOT_FOUND");
                }
                return legacySuccess(maskKey(updated));
            }
        }

        if (adminUserKeysMatch !== null && isAdmin) {
            const targetUserId = Number(adminUserKeysMatch[1]);
            if (request.method === "GET") {
                const page = parseOptionalInt(url, "page") ?? 1;
                const pageSize = parseOptionalInt(url, "page_size") ?? 20;
                const result = await repository.list({ userId: targetUserId, page, pageSize });
                return legacySuccess({
                    items: result.items.map(maskKey),
                    total: result.total,
                    page,
                    page_size: pageSize
                });
            }
        }

        if (path === ADMIN_SEARCH_KEYS_PATH && request.method === "GET" && isAdmin) {
            const query = parseQueryString(url, "q") ?? "";
            const userId = parseOptionalInt(url, "user_id");
            if (query.length < 2) {
                return legacyError(400, "Search query must be at least 2 characters", "QUERY_TOO_SHORT");
            }
            const repository = new D1ApiKeyRepository(env.DB);
            let results: { id: number; name: string; userId: number }[];
            if (userId !== undefined) {
                results = await repository.searchByUserId(userId, query);
            } else {
                results = [];
            }
            return legacySuccess(results.map((result) => ({
                id: result.id,
                name: result.name,
                user_id: result.userId,
            })));
        }

        return routerError(404, "route_not_found", "Unknown API key route");
    } catch (error) {
        if (error instanceof AccessAuthError) {
            return middlewareAuthError(401, error.code, error.message);
        }
        if (error instanceof ApiKeyError) {
            return legacyError(error.status, error.message, error.code);
        }
        return legacyInternalError(error instanceof Error ? error.message : "internal server error");
    }
}

function maskKey(key: ApiKeyRecord): Record<string, unknown> {
    const fullKey = key.key;
    const masked = fullKey.length > 8
        ? `${fullKey.slice(0, 4)}${"*".repeat(Math.min(fullKey.length - 8, 20))}${fullKey.slice(-4)}`
        : "****";
    const { key: _, ...rest } = key;
    return { ...rest, key: masked };
}
