import { D1UserAttributeRepository } from "../repositories/user-attributes.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { UserAttributeError, D1UserAttributeService } from "../services/user-attributes.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import type { D1Database } from "../types/d1.ts";
import { legacyError, legacyInternalError, legacySuccess, middlewareAuthError, routerError } from "./responses.ts";

const ATTRS_PATH = "/api/v1/admin/user-attributes";
const ATTRS_BATCH = "/api/v1/admin/user-attributes/batch";
const ATTRS_REORDER = "/api/v1/admin/user-attributes/reorder";
const ATTRS_ID = /^\/api\/v1\/admin\/user-attributes\/(\d+)$/u;
const USER_ATTRS = /^\/api\/v1\/admin\/users\/(\d+)\/attributes$/u;

export interface StagedUserAttributesEnv {
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

async function authAdmin(request: Request, env: StagedUserAttributesEnv, clock: () => number) {
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
    const subj = await auth.authenticateAuthorization(h);
    return { userId: subj.user.id, role: subj.user.role };
}

export async function routeStagedUserAttributes(
    request: Request,
    env: StagedUserAttributesEnv,
    deps: { clock?: () => number } = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = deps.clock ?? Date.now;

    const idMatch = ATTRS_ID.exec(path);
    const userAttrMatch = USER_ATTRS.exec(path);
    const isKnown = path === ATTRS_PATH || path === ATTRS_BATCH || path === ATTRS_REORDER || idMatch !== null || userAttrMatch !== null;

    if (!isKnown) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure D1 DB binding");

    try {
        const auth = await authAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const repo = new D1UserAttributeRepository(env.DB);
        const svc = new D1UserAttributeService(repo);

        if (path === ATTRS_PATH && request.method === "GET") {
            const enabledOnly = url.searchParams.get("enabled") === "true";
            return legacySuccess(await svc.listDefinitions(enabledOnly));
        }

        if (path === ATTRS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object" || Array.isArray(body)) return legacyError(400, "Invalid JSON body", "INVALID_BODY");
            return legacySuccess(await svc.createDefinition({
                key: body.key as string ?? "",
                name: body.name as string ?? "",
                description: body.description as string,
                type: body.type as string ?? "",
                options: body.options ? JSON.stringify(body.options) : undefined,
                required: body.required as boolean,
                validation: body.validation ? JSON.stringify(body.validation) : undefined,
                placeholder: body.placeholder as string,
                enabled: body.enabled as boolean
            }));
        }

        if (path === ATTRS_BATCH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") return legacyError(400, "Invalid JSON body", "INVALID_BODY");
            const userIds = body.user_ids;
            if (!Array.isArray(userIds)) return legacyError(400, "user_ids array is required", "user_ids_required");
            const ids = userIds.map((id: unknown) => typeof id === "number" ? id : Number(id)).filter((id: number) => Number.isFinite(id));
            const attrs = await svc.getBatchUserAttributes(ids);
            const result: Record<number, Record<number, string>> = {};
            for (const [uid, vals] of attrs) result[uid] = Object.fromEntries(vals);
            return legacySuccess({ attributes: result });
        }

        if (path === ATTRS_REORDER && request.method === "PUT") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") return legacyError(400, "Invalid JSON body", "INVALID_BODY");
            const ids = body.ids;
            if (!Array.isArray(ids)) return legacyError(400, "ids array is required", "ids_required");
            await svc.reorderDefinitions(ids.map((id: unknown) => Number(id)).filter((id: number) => Number.isFinite(id)));
            return legacySuccess({ message: "Reorder successful" });
        }

        if (idMatch !== null && request.method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object" || Array.isArray(body)) return legacyError(400, "Invalid JSON body", "INVALID_BODY");
            return legacySuccess(await svc.updateDefinition(id, {
                name: body.name as string,
                description: body.description as string,
                type: body.type as string,
                options: body.options ? JSON.stringify(body.options) : undefined,
                required: body.required as boolean,
                validation: body.validation ? JSON.stringify(body.validation) : undefined,
                placeholder: body.placeholder as string,
                enabled: body.enabled as boolean
            }));
        }

        if (idMatch !== null && request.method === "DELETE") {
            await svc.deleteDefinition(Number(idMatch[1]));
            return legacySuccess({ message: "Attribute definition deleted successfully" });
        }

        if (userAttrMatch !== null && request.method === "GET") {
            const userId = Number(userAttrMatch[1]);
            return legacySuccess(await svc.getUserAttributes(userId));
        }

        if (userAttrMatch !== null && request.method === "PUT") {
            const userId = Number(userAttrMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") return legacyError(400, "Invalid JSON body", "INVALID_BODY");
            const values = body.values;
            if (!values || typeof values !== "object" || Array.isArray(values)) return legacyError(400, "values map is required", "values_required");
            const parsed: Record<number, string> = {};
            for (const [k, v] of Object.entries(values)) parsed[Number(k)] = String(v ?? "");
            return legacySuccess(await svc.updateUserAttributes(userId, parsed));
        }

        return null;
    } catch (e: unknown) {
        if (e instanceof AccessAuthError) return middlewareAuthError(401, e.code, e.message);
        if (e instanceof UserAttributeError) return legacyError(e.status, e.message, e.code);
        return legacyInternalError();
    }
}
