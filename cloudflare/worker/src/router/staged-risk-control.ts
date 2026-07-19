import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1RiskControlRepository } from "../repositories/risk-control.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1RiskControlService, RiskControlError } from "../services/risk-control.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const CONFIG_RE = /^\/api\/v1\/admin\/risk-control\/config\/?$/;
const API_KEYS_TEST_RE = /^\/api\/v1\/admin\/risk-control\/api-keys\/test\/?$/;
const STATUS_RE = /^\/api\/v1\/admin\/risk-control\/status\/?$/;
const LOGS_RE = /^\/api\/v1\/admin\/risk-control\/logs\/?$/;
const USERS_UNBAN_RE = /^\/api\/v1\/admin\/risk-control\/users\/(\d+)\/unban\/?$/;
const HASHES_RE = /^\/api\/v1\/admin\/risk-control\/hashes\/?$/;
const HASHES_ALL_RE = /^\/api\/v1\/admin\/risk-control\/hashes\/all\/?$/;

export function isRiskControlPath(path: string): boolean {
    return path.startsWith("/api/v1/admin/risk-control");
}

export interface StagedRiskControlEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    TOTP_ENCRYPTION_KEY?: string;
}

function boundedIntegerEnv(value: string | undefined, defaultValue: number, min: number, max: number): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

function parseOptionalInt(val: string | null | undefined): number | undefined {
    if (val === null || val === undefined || val.trim() === "") return undefined;
    const n = Number(val);
    return Number.isInteger(n) ? n : undefined;
}

async function authenticateAdmin(request: Request, env: StagedRiskControlEnv, clock: () => number): Promise<void> {
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
    if (subject.user.role !== "admin") throw new AccessAuthError("FORBIDDEN", "Admin access required");
}

export async function routeStagedRiskControl(
    request: Request,
    env: StagedRiskControlEnv,
    clock: () => number = Date.now
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (!isRiskControlPath(pathname)) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    const repo = new D1RiskControlRepository(env.DB);
    const svc = new D1RiskControlService(repo);

    try {
        await authenticateAdmin(request, env, clock);

        // GET /PUT / risk-control/config
        if (CONFIG_RE.test(pathname)) {
            if (method === "GET") return legacySuccess(await svc.getConfig());
            if (method !== "PUT") return routerError(405, "method_not_allowed", "Use GET or PUT");
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") return legacyError(400, "Invalid request body", "INVALID_BODY");
            return legacySuccess(await svc.updateConfig(body));
        }

        // POST / risk-control/api-keys/test
        if (API_KEYS_TEST_RE.test(pathname)) {
            if (method !== "POST") return routerError(405, "method_not_allowed", "Use POST");
            const body = await request.json() as Record<string, unknown>;
            return legacySuccess(await svc.testAPIKeys({
                api_keys: Array.isArray(body.api_keys) ? body.api_keys.map(String) : undefined,
                base_url: typeof body.base_url === "string" ? body.base_url : undefined,
                model: typeof body.model === "string" ? body.model : undefined,
                timeout_ms: typeof body.timeout_ms === "number" ? body.timeout_ms : undefined,
                prompt: typeof body.prompt === "string" ? body.prompt : undefined,
                images: Array.isArray(body.images) ? body.images.map(String) : undefined,
            }));
        }

        // GET / risk-control/status
        if (STATUS_RE.test(pathname)) {
            if (method !== "GET") return routerError(405, "method_not_allowed", "Use GET");
            return legacySuccess(await svc.getStatus());
        }

        // GET / risk-control/logs
        if (LOGS_RE.test(pathname)) {
            if (method !== "GET") return routerError(405, "method_not_allowed", "Use GET");
            const page = parseOptionalInt(url.searchParams.get("page")) ?? 1;
            const pageSize = Math.min(100, parseOptionalInt(url.searchParams.get("page_size")) ?? 20);
            const result = await svc.listLogs({
                result: url.searchParams.get("result") ?? undefined,
                groupId: parseOptionalInt(url.searchParams.get("group_id")),
                endpoint: url.searchParams.get("endpoint") ?? undefined,
                search: url.searchParams.get("search") ?? undefined,
                from: url.searchParams.get("from") ?? undefined,
                to: url.searchParams.get("to") ?? undefined,
                page, pageSize,
            });
            return legacySuccess({ items: result.items, total: result.total, page: result.page, page_size: result.pageSize });
        }

        // POST / risk-control/users/:id/unban
        const unbanMatch = USERS_UNBAN_RE.exec(pathname);
        if (unbanMatch !== null) {
            if (method !== "POST") return routerError(405, "method_not_allowed", "Use POST");
            return legacySuccess(await svc.unbanUser(Number(unbanMatch[1])));
        }

        // DELETE / risk-control/hashes/all
        if (HASHES_ALL_RE.test(pathname)) {
            if (method !== "DELETE") return routerError(405, "method_not_allowed", "Use DELETE");
            return legacySuccess(await svc.clearFlaggedHashes());
        }

        // DELETE / risk-control/hashes
        if (HASHES_RE.test(pathname)) {
            if (method !== "DELETE") return routerError(405, "method_not_allowed", "Use DELETE");
            const body = await request.json() as Record<string, unknown>;
            const inputHash = String(body.input_hash ?? "");
            if (!inputHash) return legacyError(400, "input_hash is required", "MISSING_HASH");
            return legacySuccess(await svc.deleteFlaggedHash(inputHash));
        }

        return routerError(405, "method_not_allowed", `${method} ${pathname} is not supported`);
    } catch (error) {
        if (error instanceof AccessAuthError) return middlewareAuthError(error.status, error.code, error.message);
        if (error instanceof RiskControlError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError(error instanceof Error ? error.message : "internal server error");
    }
}
