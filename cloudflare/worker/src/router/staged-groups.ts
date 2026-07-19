import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { GroupError, D1GroupService } from "../services/groups.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { ChannelPricingCatalogService } from "../services/channel-pricing-catalog.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import type { D1Database } from "../types/d1.ts";
import { legacyError, legacyInternalError, legacySuccess, middlewareAuthError, routerError } from "./responses.ts";

const GROUPS_PATH = "/api/v1/admin/groups";
const GROUPS_ALL = "/api/v1/admin/groups/all";
const GROUPS_USAGE_SUMMARY = "/api/v1/admin/groups/usage-summary";
const GROUPS_CAPACITY_SUMMARY = "/api/v1/admin/groups/capacity-summary";
const GROUPS_SORT_ORDER = "/api/v1/admin/groups/sort-order";
const GROUPS_ID = /^\/api\/v1\/admin\/groups\/(\d+)$/u;
const GROUPS_ID_MODELS_CANDIDATES = /^\/api\/v1\/admin\/groups\/(\d+)\/models-list-candidates$/u;
const GROUPS_ID_STATS = /^\/api\/v1\/admin\/groups\/(\d+)\/stats$/u;
const GROUPS_ID_RATE_MULTIPLIERS = /^\/api\/v1\/admin\/groups\/(\d+)\/rate-multipliers$/u;
const GROUPS_ID_RPM_OVERRIDES = /^\/api\/v1\/admin\/groups\/(\d+)\/rpm-overrides$/u;
const GROUPS_ID_API_KEYS = /^\/api\/v1\/admin\/groups\/(\d+)\/api-keys$/u;

export interface StagedGroupsEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

function boundedIntegerEnv(v: string | undefined, d: number, min: number, max: number): number {
    if (v === undefined || v.trim() === "") return d;
    const p = Number.parseInt(v.trim(), 10);
    return Number.isInteger(p) ? Math.min(max, Math.max(min, p)) : d;
}

function parseOptionalInt(url: URL, key: string): number | undefined {
    const val = url.searchParams.get(key);
    if (val === null || val.trim() === "") return undefined;
    const p = Number.parseInt(val.trim(), 10);
    return Number.isInteger(p) ? p : undefined;
}

function parseQueryString(url: URL, key: string): string | undefined {
    const val = url.searchParams.get(key);
    return val !== null && val.trim() !== "" ? val.trim() : undefined;
}

function toUtcStartOfDayIso(now = new Date()): string {
    return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
}

function collectStringValues(value: unknown, out: Set<string>): void {
    if (typeof value === "string") {
        const trimmed = value.trim();
        if (trimmed !== "") out.add(trimmed);
        return;
    }
    if (Array.isArray(value)) {
        for (const item of value) collectStringValues(item, out);
        return;
    }
    if (value && typeof value === "object") {
        for (const item of Object.values(value as Record<string, unknown>)) collectStringValues(item, out);
    }
}

async function authenticateAdmin(request: Request, env: StagedGroupsEnv, clock: () => number): Promise<{ userId: number; role: string }> {
    const h = request.headers.get("authorization");
    if (!h) throw new AccessAuthError("UNAUTHORIZED", "Missing authorization header");
    const s = env.JWT_SECRET?.trim() ?? "";
    if (!s) throw new AccessAuthError("UNAUTHORIZED", "JWT secret not configured");
    const users = new D1AuthUserRepository(env.DB!);
    const sessions = new D1AuthSessionRepository(env.DB!);
    const signer = new Hs256JwtSigner(s, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 86400, 1, 604800), clock);
    const verifier = new Hs256JwtVerifier(s, clock);
    const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), clock);
    const auth = new AccessAuthService(users, verifier, tokens, clock);
    const subject = await auth.authenticateAuthorization(h);
    return { userId: subject.user.id, role: subject.user.role };
}

export async function routeStagedGroups(
    request: Request,
    env: StagedGroupsEnv,
    dependencies: { clock?: () => number } = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = GROUPS_ID.exec(path);
    const modelsCandidatesMatch = GROUPS_ID_MODELS_CANDIDATES.exec(path);
    const statsMatch = GROUPS_ID_STATS.exec(path);
    const rateMultipliersMatch = GROUPS_ID_RATE_MULTIPLIERS.exec(path);
    const rpmOverridesMatch = GROUPS_ID_RPM_OVERRIDES.exec(path);
    const apiKeysMatch = GROUPS_ID_API_KEYS.exec(path);

    const isKnown =
        path === GROUPS_PATH ||
        path === GROUPS_ALL ||
        path === GROUPS_USAGE_SUMMARY ||
        path === GROUPS_CAPACITY_SUMMARY ||
        path === GROUPS_SORT_ORDER ||
        idMatch !== null ||
        modelsCandidatesMatch !== null ||
        statsMatch !== null ||
        rateMultipliersMatch !== null ||
        rpmOverridesMatch !== null ||
        apiKeysMatch !== null;

    if (!isKnown) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1GroupService(env.DB);
        const pricingCatalog = new ChannelPricingCatalogService();

        // GET /api/v1/admin/groups/:id/models-list-candidates
        if (modelsCandidatesMatch !== null && request.method === "GET") {
            const id = Number(modelsCandidatesMatch[1]);
            const platform = parseQueryString(url, "platform");
            const group = await service.getById(id);
            const groupPlatform = (typeof group.platform === "string" ? group.platform : "").trim();
            const effectivePlatform = (platform ?? groupPlatform).trim() || "anthropic";

            const candidates = new Set<string>();
            for (const model of pricingCatalog.listModelNamesByPlatform(effectivePlatform)) {
                candidates.add(model);
            }
            const rawModelsListConfig = group.models_list_config;
            if (rawModelsListConfig && typeof rawModelsListConfig === "object") {
                collectStringValues(rawModelsListConfig, candidates);
            }
            return legacySuccess({ models: [...candidates] });
        }

        // GET /api/v1/admin/groups/usage-summary
        if (path === GROUPS_USAGE_SUMMARY && request.method === "GET") {
            const todayStart = toUtcStartOfDayIso();
            const rows = await env.DB.prepare(`
                SELECT
                    g.id AS group_id,
                    COALESCE(SUM(CASE WHEN ul.created_at >= ? THEN ul.actual_cost ELSE 0 END), 0) AS today_cost,
                    COALESCE(SUM(ul.actual_cost), 0) AS total_cost
                FROM groups g
                LEFT JOIN usage_logs ul ON ul.group_id = g.id
                GROUP BY g.id
                ORDER BY g.id ASC
            `).bind(todayStart).all() as { results?: Array<{ group_id: number; today_cost: number; total_cost: number }> };
            return legacySuccess((rows.results ?? []).map((row) => ({ group_id: row.group_id, today_cost: row.today_cost ?? 0, total_cost: row.total_cost ?? 0 })));
        }

        // GET /api/v1/admin/groups/capacity-summary
        if (path === GROUPS_CAPACITY_SUMMARY && request.method === "GET") {
            const rows = await env.DB.prepare(`
                SELECT
                    g.id AS group_id,
                    COALESCE(SUM(a.concurrency), 0) AS concurrency_max
                FROM groups g
                LEFT JOIN account_groups ag ON ag.group_id = g.id
                LEFT JOIN accounts a ON a.id = ag.account_id AND a.deleted_at IS NULL
                WHERE g.deleted_at IS NULL AND g.status = 'active'
                GROUP BY g.id
                ORDER BY g.id ASC
            `).all() as { results?: Array<{ group_id: number; concurrency_max: number }> };
            return legacySuccess((rows.results ?? []).map((row) => ({
                group_id: row.group_id,
                concurrency_used: 0,
                concurrency_max: row.concurrency_max ?? 0,
                sessions_used: 0,
                sessions_max: 0,
                rpm_used: 0,
                rpm_max: 0,
            })));
        }

        // GET /api/v1/admin/groups — list
        if (path === GROUPS_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const platform = parseQueryString(url, "platform");
            const status = parseQueryString(url, "status");
            const search = parseQueryString(url, "search");
            const isExclusiveStr = parseQueryString(url, "is_exclusive");
            const isExclusive = isExclusiveStr !== undefined ? isExclusiveStr === "true" : undefined;
            const sortBy = parseQueryString(url, "sort_by") ?? "sort_order";
            const sortOrder = parseQueryString(url, "sort_order") ?? "asc";

            const result = await service.list({ page, pageSize, platform, status, search, isExclusive, sortBy, sortOrder });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // POST /api/v1/admin/groups — create
        if (path === GROUPS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const created = await service.create(body as unknown as Parameters<typeof service.create>[0]);
            return legacySuccess(created);
        }

        // GET /api/v1/admin/groups/all — list all
        if (path === GROUPS_ALL && request.method === "GET") {
            const includeInactive = parseQueryString(url, "include_inactive") === "true";
            const platform = parseQueryString(url, "platform");

            let groups: Record<string, unknown>[];
            if (includeInactive) {
                groups = await service.listAllIncludingInactive();
            } else if (platform) {
                groups = await service.listActiveByPlatform(platform);
            } else {
                groups = await service.listActive();
            }
            return legacySuccess(groups);
        }

        // PUT /api/v1/admin/groups/sort-order
        if (path === GROUPS_SORT_ORDER && request.method === "PUT") {
            const body = await request.json() as { updates?: Array<{ id: number; sort_order?: number }> };
            if (!body?.updates || !Array.isArray(body.updates)) {
                return legacyError(400, "updates array is required", "INVALID_BODY");
            }
            await service.updateSortOrders(body.updates.map(u => ({ id: u.id, sortOrder: u.sort_order ?? 0 })));
            return legacySuccess({ message: "Sort order updated successfully" });
        }

        // GET /api/v1/admin/groups/:id/api-keys
        if (apiKeysMatch !== null && request.method === "GET") {
            const id = Number(apiKeysMatch[1]);
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const result = await service.getGroupApiKeys(id, page, pageSize);
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // GET /api/v1/admin/groups/:id/stats
        if (statsMatch !== null && request.method === "GET") {
            const id = Number(statsMatch[1]);
            const stats = await service.getGroupStats(id);
            return legacySuccess(stats);
        }

        // GET /api/v1/admin/groups/:id/rate-multipliers
        if (rateMultipliersMatch !== null && request.method === "GET") {
            const id = Number(rateMultipliersMatch[1]);
            const entries = await service.getRateMultipliers(id);
            return legacySuccess(entries);
        }

        // PUT /api/v1/admin/groups/:id/rate-multipliers
        if (rateMultipliersMatch !== null && request.method === "PUT") {
            const id = Number(rateMultipliersMatch[1]);
            const body = await request.json() as { entries?: Array<{ user_id: number; rate_multiplier: number }> };
            if (!body?.entries) return legacyError(400, "entries array is required", "INVALID_BODY");
            await service.batchSetRateMultipliers(id, body.entries.map(e => ({ userId: e.user_id, rateMultiplier: e.rate_multiplier })));
            return legacySuccess({ message: "Rate multipliers updated successfully" });
        }

        // DELETE /api/v1/admin/groups/:id/rate-multipliers
        if (rateMultipliersMatch !== null && request.method === "DELETE") {
            const id = Number(rateMultipliersMatch[1]);
            await service.clearRateMultipliers(id);
            return legacySuccess({ message: "Rate multipliers cleared successfully" });
        }

        // PUT /api/v1/admin/groups/:id/rpm-overrides
        if (rpmOverridesMatch !== null && request.method === "PUT") {
            const id = Number(rpmOverridesMatch[1]);
            const body = await request.json() as { entries?: Array<{ user_id: number; rpm_override: number | null }> };
            if (!body?.entries) return legacyError(400, "entries array is required", "INVALID_BODY");
            await service.batchSetRPMOverrides(id, body.entries.map(e => ({ userId: e.user_id, rpmOverride: e.rpm_override ?? null })));
            return legacySuccess({ message: "RPM overrides updated successfully" });
        }

        // DELETE /api/v1/admin/groups/:id/rpm-overrides
        if (rpmOverridesMatch !== null && request.method === "DELETE") {
            const id = Number(rpmOverridesMatch[1]);
            await service.clearRPMOverrides(id);
            return legacySuccess({ message: "RPM overrides cleared successfully" });
        }

        // GET /api/v1/admin/groups/:id
        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const group = await service.getById(id);
            return legacySuccess(group);
        }

        // PUT /api/v1/admin/groups/:id
        if (idMatch !== null && request.method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, body);
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/groups/:id
        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Group deleted successfully" });
        }

        return routerError(405, "method_not_allowed", "Method not allowed for this group route");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof GroupError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
