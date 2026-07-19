import { D1ChannelMonitorTemplateRepository } from "../repositories/channel-monitor-templates.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { ChannelMonitorTemplateError, D1ChannelMonitorTemplateService } from "../services/channel-monitor-templates.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
} from "./responses.ts";

const ROOT = "/api/v1/admin/channel-monitor-templates";
const ROOT_RE = /^\/api\/v1\/admin\/channel-monitor-templates\/?$/;
const ID_RE = /^\/api\/v1\/admin\/channel-monitor-templates\/(\d+)\/?$/;
const MONITORS_RE = /^\/api\/v1\/admin\/channel-monitor-templates\/(\d+)\/monitors\/?$/;
const APPLY_RE = /^\/api\/v1\/admin\/channel-monitor-templates\/(\d+)\/apply\/?$/;

export interface StagedChannelMonitorTemplatesEnv {
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

export function isChannelMonitorTemplatePath(path: string): boolean {
    return path === ROOT || path.startsWith(ROOT + "/");
}

async function authenticateAdmin(request: Request, env: StagedChannelMonitorTemplatesEnv, clock: () => number): Promise<{ userId: number; role: string }> {
    const authHeader = request.headers.get("authorization");
    if (!authHeader) throw new AccessAuthError("UNAUTHORIZED", "Missing authorization header");
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) throw new AccessAuthError("UNAUTHORIZED", "JWT secret is not configured");

    const users = new D1AuthUserRepository(env.DB!);
    const sessions = new D1AuthSessionRepository(env.DB!);
    const signer = new Hs256JwtSigner(secret, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 7 * 24 * 60 * 60), Date.now);
    const verifier = new Hs256JwtVerifier(secret, Date.now);
    const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), Date.now);
    const auth = new AccessAuthService(users, verifier, tokens, Date.now);
    const subject = await auth.authenticateAuthorization(authHeader);
    return { userId: subject.user.id, role: subject.user.role };
}

export async function routeStagedChannelMonitorTemplates(
    request: Request,
    env: StagedChannelMonitorTemplatesEnv
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    const applyMatch = APPLY_RE.exec(pathname);
    const monitorsMatch = MONITORS_RE.exec(pathname);
    const idMatch = (applyMatch !== null || monitorsMatch !== null) ? null : ID_RE.exec(pathname);
    const isKnownPath = ROOT_RE.test(pathname) || applyMatch !== null || monitorsMatch !== null || idMatch !== null;
    if (!isKnownPath) return null;
    if (env.DB === undefined) return middlewareAuthError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, Date.now);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repo = new D1ChannelMonitorTemplateRepository(env.DB);
        const svc = new D1ChannelMonitorTemplateService(repo);

        // GET /admin/channel-monitor-templates — list
        if (ROOT_RE.test(pathname) && method === "GET") {
            const provider = url.searchParams.get("provider") ?? undefined;
            const apiMode = url.searchParams.get("api_mode") ?? undefined;
            const items = await svc.list({ provider, apiMode });
            return legacySuccess({ items });
        }

        // POST /admin/channel-monitor-templates — create
        if (ROOT_RE.test(pathname) && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            const created = await svc.create({
                name: body.name as string,
                provider: body.provider as string,
                apiMode: typeof body.api_mode === "string" ? body.api_mode : undefined,
                description: typeof body.description === "string" ? body.description : undefined,
                extraHeaders: typeof body.extra_headers === "object" && body.extra_headers !== null ? body.extra_headers as Record<string, string> : undefined,
                bodyOverrideMode: typeof body.body_override_mode === "string" ? body.body_override_mode : undefined,
                bodyOverride: typeof body.body_override === "object" ? body.body_override as Record<string, unknown> : undefined,
            });
            return legacySuccess(created);
        }

        // GET /admin/channel-monitor-templates/:id/monitors
        if (monitorsMatch !== null && method === "GET") {
            const items = await svc.listAssociatedMonitors(Number(monitorsMatch[1]));
            return legacySuccess({ items });
        }

        // POST /admin/channel-monitor-templates/:id/apply
        if (applyMatch !== null && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            const monitorIds = body.monitor_ids;
            if (!Array.isArray(monitorIds) || monitorIds.length === 0) {
                return legacyError(400, "monitor_ids must be a non-empty array", "CHANNEL_MONITOR_TEMPLATE_APPLY_EMPTY");
            }
            const affected = await svc.applyToMonitors(Number(applyMatch[1]), monitorIds.map(Number));
            return legacySuccess({ affected });
        }

        if (idMatch !== null) {
            const id = Number(idMatch[1]);

            // GET /admin/channel-monitor-templates/:id
            if (method === "GET") {
                const item = await svc.getById(id);
                return legacySuccess(item);
            }

            // PUT /admin/channel-monitor-templates/:id
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                const item = await svc.update(id, {
                    name: typeof body.name === "string" ? body.name : undefined,
                    apiMode: typeof body.api_mode === "string" ? body.api_mode : undefined,
                    description: typeof body.description === "string" ? body.description : undefined,
                    extraHeaders: typeof body.extra_headers === "object" && body.extra_headers !== null ? body.extra_headers as Record<string, string> : undefined,
                    bodyOverrideMode: typeof body.body_override_mode === "string" ? body.body_override_mode : undefined,
                    bodyOverride: typeof body.body_override === "object" ? body.body_override as Record<string, unknown> : undefined,
                });
                return legacySuccess(item);
            }

            // DELETE /admin/channel-monitor-templates/:id
            if (method === "DELETE") {
                await svc.delete(id);
                return legacySuccess(null);
            }
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof ChannelMonitorTemplateError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
