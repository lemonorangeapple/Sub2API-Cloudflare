import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AdminOAuthError, D1AdminOAuthService } from "../services/admin-oauth.ts";
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

const OPENAI_BASE = "/api/v1/admin/openai";
const GEMINI_BASE = "/api/v1/admin/gemini";
const ANTIGRAVITY_BASE = "/api/v1/admin/antigravity";
const GROK_BASE = "/api/v1/admin/grok";

const PATH_ACCOUNTS_ID = /^\/api\/v1\/admin\/(openai|grok)\/accounts\/(\d+)\/(refresh|quota|reset-quota)$/;

export type StagedAdminOAuthEnv = {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
};

function boundedIntegerEnv(value: string | undefined, defaultValue: number, min: number, max: number): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

async function authenticateAdmin(request: Request, env: StagedAdminOAuthEnv, clock: () => number): Promise<{ userId: number; role: string }> {
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

// Simple dispatch: url pattern -> (provider, action, paramsFn)
interface RouteDef {
    pattern: RegExp;
    provider: string;
    action: string;
    extractParams?: (match: RegExpExecArray, body: Record<string, unknown>) => Record<string, unknown>;
}

const ROUTES: RouteDef[] = [
    // OpenAI
    { pattern: /^\/api\/v1\/admin\/openai\/generate-auth-url$/, provider: "openai", action: "generate-auth-url" },
    { pattern: /^\/api\/v1\/admin\/openai\/exchange-code$/, provider: "openai", action: "exchange-code" },
    { pattern: /^\/api\/v1\/admin\/openai\/refresh-token$/, provider: "openai", action: "refresh-token" },
    { pattern: /^\/api\/v1\/admin\/openai\/accounts\/(\d+)\/refresh$/, provider: "openai", action: "refresh-account-token", extractParams: (m) => ({ accountId: Number(m[1]) }) },
    { pattern: /^\/api\/v1\/admin\/openai\/create-from-oauth$/, provider: "openai", action: "create-from-oauth" },
    { pattern: /^\/api\/v1\/admin\/openai\/create-from-codex-pat$/, provider: "openai", action: "create-from-codex-pat" },
    { pattern: /^\/api\/v1\/admin\/openai\/accounts\/(\d+)\/quota$/, provider: "openai", action: "query-quota", extractParams: (m) => ({ accountId: Number(m[1]) }) },
    { pattern: /^\/api\/v1\/admin\/openai\/accounts\/(\d+)\/reset-quota$/, provider: "openai", action: "reset-quota", extractParams: (m) => ({ accountId: Number(m[1]) }) },
    // Gemini
    { pattern: /^\/api\/v1\/admin\/gemini\/oauth\/capabilities$/, provider: "gemini", action: "get-capabilities" },
    { pattern: /^\/api\/v1\/admin\/gemini\/oauth\/auth-url$/, provider: "gemini", action: "generate-auth-url" },
    { pattern: /^\/api\/v1\/admin\/gemini\/oauth\/exchange-code$/, provider: "gemini", action: "exchange-code" },
    // Antigravity
    { pattern: /^\/api\/v1\/admin\/antigravity\/oauth\/auth-url$/, provider: "antigravity", action: "generate-auth-url" },
    { pattern: /^\/api\/v1\/admin\/antigravity\/oauth\/exchange-code$/, provider: "antigravity", action: "exchange-code" },
    { pattern: /^\/api\/v1\/admin\/antigravity\/oauth\/refresh-token$/, provider: "antigravity", action: "refresh-token" },
    // Grok
    { pattern: /^\/api\/v1\/admin\/grok\/oauth\/auth-url$/, provider: "grok", action: "generate-auth-url" },
    { pattern: /^\/api\/v1\/admin\/grok\/oauth\/exchange-code$/, provider: "grok", action: "exchange-code" },
    { pattern: /^\/api\/v1\/admin\/grok\/oauth\/refresh-token$/, provider: "grok", action: "refresh-token" },
    { pattern: /^\/api\/v1\/admin\/grok\/accounts\/(\d+)\/refresh$/, provider: "grok", action: "refresh-account-token", extractParams: (m) => ({ accountId: Number(m[1]) }) },
    { pattern: /^\/api\/v1\/admin\/grok\/oauth\/create-from-oauth$/, provider: "grok", action: "create-from-oauth" },
    { pattern: /^\/api\/v1\/admin\/grok\/sso-to-oauth$/, provider: "grok", action: "sso-to-oauth" },
    { pattern: /^\/api\/v1\/admin\/grok\/accounts\/(\d+)\/quota$/, provider: "grok", action: "query-quota", extractParams: (m) => ({ accountId: Number(m[1]) }) },
    { pattern: /^\/api\/v1\/admin\/grok\/accounts\/(\d+)\/reset-quota$/, provider: "grok", action: "reset-quota", extractParams: (m) => ({ accountId: Number(m[1]) }) },
    { pattern: /^\/api\/v1\/admin\/grok\/runtime-sanity$/, provider: "grok", action: "runtime-sanity" },
];

export function isAdminOAuthPath(pathname: string): boolean {
    return pathname.startsWith(OPENAI_BASE) || pathname.startsWith(GEMINI_BASE) || pathname.startsWith(ANTIGRAVITY_BASE) || pathname.startsWith(GROK_BASE);
}

export async function routeStagedAdminOAuth(
    request: Request,
    env: StagedAdminOAuthEnv,
    clock: () => number = Date.now
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (!isAdminOAuthPath(pathname)) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    let matched: RouteDef | null = null;
    let matchExec: RegExpExecArray | null = null;
    for (const route of ROUTES) {
        const m = route.pattern.exec(pathname);
        if (m !== null) {
            matched = route;
            matchExec = m;
            break;
        }
    }
    if (!matched) return routerError(404, "not_found", "Route not found");

    // Most admin OAuth routes are POST; capabilities and runtime-sanity are GET
    const getActions = new Set(["get-capabilities", "query-quota", "runtime-sanity"]);
    if (getActions.has(matched.action) && request.method !== "GET") {
        return routerError(405, "method_not_allowed", "Use GET");
    }
    if (!getActions.has(matched.action) && request.method !== "POST") {
        return routerError(405, "method_not_allowed", "Use POST");
    }

    const svc = new D1AdminOAuthService(env.DB);

    let body: Record<string, unknown> = {};
    if (request.method === "POST") {
        try {
            body = await request.json() as Record<string, unknown>;
        } catch {
            // Empty body is allowed (generate-auth-url, etc.)
        }
    }

    const routeParams = matchExec && matched.extractParams ? matched.extractParams(matchExec, body) : {};
    const params = { ...body, ...routeParams };

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const result = await svc.route(matched.provider as "openai" | "gemini" | "antigravity" | "grok", matched.action, params);
        return legacySuccess(result);
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AdminOAuthError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError(error instanceof Error ? error.message : "internal server error");
    }
}
