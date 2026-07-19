import { D1ErrorPassthroughRuleRepository } from "../repositories/error-passthrough-rules.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { RuleError, D1ErrorPassthroughRuleService } from "../services/error-passthrough-rules.ts";
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

const RULES_PATH = "/api/v1/admin/error-passthrough-rules";
const RULE_ID_PATH = /^\/api\/v1\/admin\/error-passthrough-rules\/(\d+)$/u;

export interface StagedErrorPassthroughRulesEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedErrorPassthroughRulesDependencies {
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

async function authenticateAdmin(
    request: Request,
    env: StagedErrorPassthroughRulesEnv,
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

export async function routeStagedErrorPassthroughRules(
    request: Request,
    env: StagedErrorPassthroughRulesEnv,
    dependencies: StagedErrorPassthroughRulesDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const ruleIdMatch = RULE_ID_PATH.exec(path);
    const isKnownPath = path === RULES_PATH || ruleIdMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repository = new D1ErrorPassthroughRuleRepository(env.DB);
        const service = new D1ErrorPassthroughRuleService(repository);

        // GET /api/v1/admin/error-passthrough-rules
        if (path === RULES_PATH && request.method === "GET") {
            const rules = await service.list();
            return legacySuccess(rules);
        }

        // POST /api/v1/admin/error-passthrough-rules
        if (path === RULES_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const created = await service.create({
                name: body.name as string ?? "",
                enabled: body.enabled as boolean | undefined,
                priority: body.priority as number | undefined,
                errorCodes: body.error_codes as number[] | undefined,
                keywords: body.keywords as string[] | undefined,
                matchMode: body.match_mode as string | undefined,
                platforms: body.platforms as string[] | undefined,
                passthroughCode: body.passthrough_code as boolean | undefined,
                responseCode: body.response_code as number | null | undefined,
                passthroughBody: body.passthrough_body as boolean | undefined,
                customMessage: body.custom_message as string | null | undefined,
                skipMonitoring: body.skip_monitoring as boolean | undefined,
                description: body.description as string | null | undefined,
            });
            return legacySuccess(created);
        }

        // GET /api/v1/admin/error-passthrough-rules/:id
        if (ruleIdMatch !== null && request.method === "GET") {
            const id = Number(ruleIdMatch[1]);
            const rule = await service.getById(id);
            return legacySuccess(rule);
        }

        // PUT /api/v1/admin/error-passthrough-rules/:id
        if (ruleIdMatch !== null && request.method === "PUT") {
            const id = Number(ruleIdMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, {
                name: body.name as string | undefined,
                enabled: body.enabled as boolean | undefined,
                priority: body.priority as number | undefined,
                errorCodes: body.error_codes as number[] | undefined,
                keywords: body.keywords as string[] | undefined,
                matchMode: body.match_mode as string | undefined,
                platforms: body.platforms as string[] | undefined,
                passthroughCode: body.passthrough_code as boolean | undefined,
                responseCode: body.response_code as number | null | undefined,
                passthroughBody: body.passthrough_body as boolean | undefined,
                customMessage: body.custom_message as string | null | undefined,
                skipMonitoring: body.skip_monitoring as boolean | undefined,
                description: body.description as string | null | undefined,
            });
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/error-passthrough-rules/:id
        if (ruleIdMatch !== null && request.method === "DELETE") {
            const id = Number(ruleIdMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Rule deleted successfully" });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof RuleError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
