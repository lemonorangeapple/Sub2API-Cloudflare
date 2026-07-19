import { D1ScheduledTestPlanRepository } from "../repositories/scheduled-test-plans.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { ScheduledTestError, D1ScheduledTestPlanService } from "../services/scheduled-test-plans.ts";
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

const PLANS_PATH = "/api/v1/admin/scheduled-test-plans";
const PLAN_ID_RESULTS = /^\/api\/v1\/admin\/scheduled-test-plans\/(\d+)\/results$/u;
const PLAN_ID_PATH = /^\/api\/v1\/admin\/scheduled-test-plans\/(\d+)$/u;
const ACCOUNT_PLANS = /^\/api\/v1\/admin\/accounts\/(\d+)\/scheduled-test-plans$/u;

export interface StagedScheduledTestPlansEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedScheduledTestPlansDependencies {
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

async function authenticateAdmin(
    request: Request,
    env: StagedScheduledTestPlansEnv,
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

export async function routeStagedScheduledTestPlans(
    request: Request,
    env: StagedScheduledTestPlansEnv,
    dependencies: StagedScheduledTestPlansDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const resultsMatch = PLAN_ID_RESULTS.exec(path);
    const planIdMatch = resultsMatch !== null ? null : PLAN_ID_PATH.exec(path);
    const accountPlansMatch = ACCOUNT_PLANS.exec(path);

    const isKnownPath =
        path === PLANS_PATH ||
        resultsMatch !== null ||
        planIdMatch !== null ||
        accountPlansMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repository = new D1ScheduledTestPlanRepository(env.DB);
        const service = new D1ScheduledTestPlanService(repository);

        // POST /api/v1/admin/scheduled-test-plans
        if (path === PLANS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            if (typeof body.account_id !== "number") {
                return legacyError(400, "account_id is required", "INVALID_BODY");
            }
            if (typeof body.cron_expression !== "string") {
                return legacyError(400, "cron_expression is required", "INVALID_BODY");
            }
            const created = await service.create({
                accountId: body.account_id,
                modelId: typeof body.model_id === "string" ? body.model_id : undefined,
                cronExpression: body.cron_expression,
                enabled: typeof body.enabled === "boolean" ? body.enabled : undefined,
                maxResults: typeof body.max_results === "number" ? body.max_results : undefined,
                autoRecover: typeof body.auto_recover === "boolean" ? body.auto_recover : undefined,
            });
            return legacySuccess(created);
        }

        // GET /api/v1/admin/scheduled-test-plans/:id/results
        if (resultsMatch !== null && request.method === "GET") {
            const id = Number(resultsMatch[1]);
            const limit = parseOptionalInt(url, "limit") ?? 50;
            const results = await service.listResults(id, limit);
            return legacySuccess(results);
        }

        // GET /api/v1/admin/scheduled-test-plans/:id
        if (planIdMatch !== null && request.method === "GET") {
            const id = Number(planIdMatch[1]);
            const plan = await service.getById(id);
            return legacySuccess(plan);
        }

        // PUT /api/v1/admin/scheduled-test-plans/:id
        if (planIdMatch !== null && request.method === "PUT") {
            const id = Number(planIdMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, {
                modelId: typeof body.model_id === "string" ? body.model_id : undefined,
                cronExpression: typeof body.cron_expression === "string" ? body.cron_expression : undefined,
                enabled: typeof body.enabled === "boolean" ? body.enabled : undefined,
                maxResults: typeof body.max_results === "number" ? body.max_results : undefined,
                autoRecover: typeof body.auto_recover === "boolean" ? body.auto_recover : undefined,
            });
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/scheduled-test-plans/:id
        if (planIdMatch !== null && request.method === "DELETE") {
            const id = Number(planIdMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "deleted" });
        }

        // GET /api/v1/admin/accounts/:id/scheduled-test-plans
        if (accountPlansMatch !== null && request.method === "GET") {
            const accountId = Number(accountPlansMatch[1]);
            const plans = await service.listByAccountId(accountId);
            return legacySuccess(plans);
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof ScheduledTestError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
