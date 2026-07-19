import { D1ChannelMonitorRepository } from "../repositories/channel-monitors.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { ChannelMonitorError, D1ChannelMonitorService } from "../services/channel-monitors.ts";
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

const MONITORS_PATH = "/api/v1/admin/channel-monitors";
const MONITOR_ID_HISTORY = /^\/api\/v1\/admin\/channel-monitors\/(\d+)\/history$/u;
const MONITOR_ID_RUN = /^\/api\/v1\/admin\/channel-monitors\/(\d+)\/run$/u;
const MONITOR_ID_PATH = /^\/api\/v1\/admin\/channel-monitors\/(\d+)$/u;

export interface StagedChannelMonitorsEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedChannelMonitorsDependencies {
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

function parseOptionalString(url: URL, key: string): string | undefined {
    const value = url.searchParams.get(key);
    return value !== null && value.trim() !== "" ? value.trim() : undefined;
}

async function runMonitorChecks(
    db: D1Database,
    monitorId: number,
    clock: () => number
): Promise<Array<Record<string, unknown>>> {
    const row = await db.prepare("SELECT * FROM channel_monitors WHERE id = ?").bind(monitorId).first() as {
        endpoint: string; api_key_encrypted: string; primary_model: string; extra_models: string;
        extra_headers: string; body_override_mode: string; body_override: string | null;
    } | null;
    if (!row) throw new ChannelMonitorError("CHANNEL_MONITOR_NOT_FOUND", 404, "Channel monitor not found");

    let extraModels: string[] = [];
    try {
        const parsed = JSON.parse(row.extra_models);
        if (Array.isArray(parsed)) extraModels = parsed.filter((item): item is string => typeof item === "string" && item.trim() !== "");
    } catch { /* use primary model only */ }
    let headers: Record<string, string> = {};
    try {
        const parsed = JSON.parse(row.extra_headers);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) headers = parsed as Record<string, string>;
    } catch { /* use default headers */ }
    let override: Record<string, unknown> = {};
    if (row.body_override) {
        try {
            const parsed = JSON.parse(row.body_override);
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) override = parsed as Record<string, unknown>;
        } catch { /* use default body */ }
    }

    const models = [row.primary_model, ...extraModels];
    const results: Array<Record<string, unknown>> = [];
    for (const model of models) {
        const started = clock();
        const checkedAt = new Date(started).toISOString();
        let status = "error";
        let message = "request failed";
        let latencyMs: number | null = null;
        try {
            const body = row.body_override_mode === "replace"
                ? { ...override, model }
                : { model, messages: [{ role: "user", content: "ping" }], max_tokens: 1, ...override };
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            const response = await fetch(row.endpoint, {
                method: "POST",
                headers: { authorization: `Bearer ${row.api_key_encrypted}`, "content-type": "application/json", ...headers },
                body: JSON.stringify(body),
                signal: controller.signal,
            });
            clearTimeout(timeout);
            latencyMs = Math.max(0, clock() - started);
            status = response.ok ? "operational" : response.status >= 500 ? "failed" : "degraded";
            message = response.ok ? "ok" : `upstream returned ${response.status}`;
        } catch (error) {
            latencyMs = Math.max(0, clock() - started);
            message = error instanceof Error ? error.message : "request failed";
        }
        await db.prepare(`
            INSERT INTO channel_monitor_histories (model, status, latency_ms, ping_latency_ms, message, checked_at, monitor_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(model, status, latencyMs, latencyMs, message, checkedAt, monitorId).run();
        results.push({ model, status, latency_ms: latencyMs, ping_latency_ms: latencyMs, message, checked_at: checkedAt });
    }
    await db.prepare("UPDATE channel_monitors SET last_checked_at = ?, updated_at = ? WHERE id = ?").bind(new Date(clock()).toISOString(), new Date(clock()).toISOString(), monitorId).run();
    return results;
}

async function authenticateAdmin(request: Request, env: StagedChannelMonitorsEnv, clock: () => number): Promise<{ userId: number; role: string }> {
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

export function isChannelMonitorPath(path: string): boolean {
    return path === MONITORS_PATH || path.startsWith(MONITORS_PATH + "/");
}

export async function routeStagedChannelMonitors(
    request: Request,
    env: StagedChannelMonitorsEnv,
    dependencies: StagedChannelMonitorsDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const historyMatch = MONITOR_ID_HISTORY.exec(path);
    const runMatch = MONITOR_ID_RUN.exec(path);
    const monitorIdMatch = historyMatch !== null || runMatch !== null ? null : MONITOR_ID_PATH.exec(path);

    const isKnownPath = path === MONITORS_PATH || historyMatch !== null || runMatch !== null || monitorIdMatch !== null;
    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repository = new D1ChannelMonitorRepository(env.DB);
        const service = new D1ChannelMonitorService(repository);

        // POST /api/v1/admin/channel-monitors/:id/run
        if (runMatch !== null && request.method === "POST") {
            const results = await runMonitorChecks(env.DB, Number(runMatch[1]), clock);
            return legacySuccess({ results });
        }

        // GET /api/v1/admin/channel-monitors — list
        if (path === MONITORS_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const provider = parseOptionalString(url, "provider");
            const search = parseOptionalString(url, "search");
            const enabledStr = url.searchParams.get("enabled");
            let enabled: boolean | undefined;
            if (enabledStr !== null && enabledStr.trim() !== "") {
                const v = enabledStr.trim().toLowerCase();
                enabled = v === "true" || v === "1" || v === "yes";
            }
            const result = await service.list({ page, pageSize, provider, enabled, search });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // POST /api/v1/admin/channel-monitors — create
        if (path === MONITORS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            if (typeof body.name !== "string" || !body.name) return legacyError(400, "name is required", "INVALID_BODY");
            if (typeof body.provider !== "string") return legacyError(400, "provider is required", "INVALID_BODY");
            if (typeof body.endpoint !== "string") return legacyError(400, "endpoint is required", "INVALID_BODY");
            if (typeof body.api_key !== "string") return legacyError(400, "api_key is required", "INVALID_BODY");
            if (typeof body.interval_seconds !== "number") return legacyError(400, "interval_seconds is required", "INVALID_BODY");

            const created = await service.create({
                name: body.name,
                provider: body.provider,
                apiMode: typeof body.api_mode === "string" ? body.api_mode : undefined,
                endpoint: body.endpoint,
                apiKey: body.api_key,
                primaryModel: typeof body.primary_model === "string" ? body.primary_model : undefined,
                extraModels: Array.isArray(body.extra_models) ? body.extra_models as string[] : undefined,
                groupName: typeof body.group_name === "string" ? body.group_name : undefined,
                enabled: typeof body.enabled === "boolean" ? body.enabled : undefined,
                intervalSeconds: body.interval_seconds,
                jitterSeconds: typeof body.jitter_seconds === "number" ? body.jitter_seconds : undefined,
                templateId: typeof body.template_id === "number" ? body.template_id : undefined,
                extraHeaders: typeof body.extra_headers === "object" && body.extra_headers !== null ? body.extra_headers as Record<string, string> : undefined,
                bodyOverrideMode: typeof body.body_override_mode === "string" ? body.body_override_mode : undefined,
                bodyOverride: typeof body.body_override === "object" ? body.body_override as Record<string, unknown> : undefined,
                createdBy: auth.userId,
            });
            return legacySuccess(created);
        }

        // GET /api/v1/admin/channel-monitors/:id
        if (monitorIdMatch !== null && request.method === "GET") {
            const id = Number(monitorIdMatch[1]);
            const monitor = await service.getById(id);
            return legacySuccess(monitor);
        }

        // PUT /api/v1/admin/channel-monitors/:id
        if (monitorIdMatch !== null && request.method === "PUT") {
            const id = Number(monitorIdMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, {
                name: typeof body.name === "string" ? body.name : undefined,
                provider: typeof body.provider === "string" ? body.provider : undefined,
                apiMode: typeof body.api_mode === "string" ? body.api_mode : undefined,
                endpoint: typeof body.endpoint === "string" ? body.endpoint : undefined,
                apiKey: typeof body.api_key === "string" ? body.api_key : undefined,
                primaryModel: typeof body.primary_model === "string" ? body.primary_model : undefined,
                extraModels: Array.isArray(body.extra_models) ? body.extra_models as string[] : undefined,
                groupName: typeof body.group_name === "string" ? body.group_name : undefined,
                enabled: typeof body.enabled === "boolean" ? body.enabled : undefined,
                intervalSeconds: typeof body.interval_seconds === "number" ? body.interval_seconds : undefined,
                jitterSeconds: typeof body.jitter_seconds === "number" ? body.jitter_seconds : undefined,
                templateId: typeof body.template_id === "number" ? body.template_id : undefined,
                clearTemplate: typeof body.clear_template === "boolean" ? body.clear_template : undefined,
                extraHeaders: typeof body.extra_headers === "object" && body.extra_headers !== null ? body.extra_headers as Record<string, string> : undefined,
                bodyOverrideMode: typeof body.body_override_mode === "string" ? body.body_override_mode : undefined,
                bodyOverride: typeof body.body_override === "object" ? body.body_override as Record<string, unknown> : undefined,
            });
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/channel-monitors/:id
        if (monitorIdMatch !== null && request.method === "DELETE") {
            const id = Number(monitorIdMatch[1]);
            await service.delete(id);
            return legacySuccess(null);
        }

        // GET /api/v1/admin/channel-monitors/:id/history
        if (historyMatch !== null && request.method === "GET") {
            const id = Number(historyMatch[1]);
            const limit = parseOptionalInt(url, "limit") ?? 100;
            const model = parseOptionalString(url, "model");
            const result = await service.listHistory(id, limit, model);
            return legacySuccess(result.items);
        }

        return legacyError(405, "method_not_allowed", "Method not allowed");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof ChannelMonitorError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
