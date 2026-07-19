import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AdminComplianceError, D1AdminComplianceService } from "../services/admin-compliance.ts";
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

const COMPLIANCE_PATH = "/api/v1/admin/compliance";
const COMPLIANCE_ACCEPT_PATH = "/api/v1/admin/compliance/accept";

export interface StagedAdminComplianceEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedAdminComplianceDependencies {
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

export async function authenticateAdminForCompliance(
    request: Request,
    env: StagedAdminComplianceEnv,
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

export function isCompliancePath(path: string): boolean {
    return path === COMPLIANCE_PATH || path === COMPLIANCE_ACCEPT_PATH || path.startsWith(COMPLIANCE_PATH + "/");
}

export async function routeStagedAdminCompliance(
    request: Request,
    env: StagedAdminComplianceEnv,
    dependencies: StagedAdminComplianceDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    if (!isCompliancePath(path)) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdminForCompliance(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1AdminComplianceService(env.DB);

        // GET /api/v1/admin/compliance
        if (path === COMPLIANCE_PATH && request.method === "GET") {
            const status = await service.getStatus(auth.userId);
            return legacySuccess(status);
        }

        // POST /api/v1/admin/compliance/accept
        if (path === COMPLIANCE_ACCEPT_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            if (typeof body.phrase !== "string") {
                return legacyError(400, "phrase is required", "INVALID_BODY");
            }
            const status = await service.accept(
                auth.userId,
                body.phrase,
                typeof body.language === "string" ? body.language : "en",
                request.headers.get("x-forwarded-for") ?? request.headers.get("cf-connecting-ip") ?? undefined,
                request.headers.get("user-agent") ?? undefined
            );
            return legacySuccess(status);
        }

        return routerError(405, "method_not_allowed", "Method not allowed for this compliance route");
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof AdminComplianceError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
