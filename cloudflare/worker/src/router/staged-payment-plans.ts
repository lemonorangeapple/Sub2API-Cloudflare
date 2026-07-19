import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PaymentPlanService, PaymentPlanError } from "../services/payment-plans.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const PLANS_PATH = "/api/v1/admin/payment/plans";
const PLANS_ID = /^\/api\/v1\/admin\/payment\/plans\/(\d+)$/u;

export interface StagedPaymentPlansEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedPaymentPlansDependencies {
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
    env: StagedPaymentPlansEnv,
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

export async function routeStagedPaymentPlans(
    request: Request,
    env: StagedPaymentPlansEnv,
    dependencies: StagedPaymentPlansDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = PLANS_ID.exec(path);

    const isKnownPath =
        path === PLANS_PATH ||
        idMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1PaymentPlanService(env.DB);

        // GET /api/v1/admin/payment/plans — list
        if (path === PLANS_PATH && request.method === "GET") {
            const plans = await service.list();
            return legacySuccess(plans);
        }

        // POST /api/v1/admin/payment/plans — create
        if (path === PLANS_PATH && request.method === "POST") {
            const body = await request.json() as {
                group_id: number; name: string; description?: string;
                price: number; original_price?: number | null;
                validity_days?: number; validity_unit?: string;
                features?: string; product_name?: string;
                for_sale?: number; sort_order?: number;
            };
            if (!body || typeof body.name !== "string" || typeof body.price !== "number" || !body.group_id) {
                return legacyError(400, "name, price, and group_id are required", "INVALID_BODY");
            }
            const created = await service.create({
                groupId: body.group_id,
                name: body.name,
                description: body.description,
                price: body.price,
                originalPrice: body.original_price,
                validityDays: body.validity_days,
                validityUnit: body.validity_unit,
                features: body.features,
                productName: body.product_name,
                forSale: body.for_sale,
                sortOrder: body.sort_order,
            });
            return legacySuccess(created);
        }

        // GET /api/v1/admin/payment/plans/:id — get by id
        if (idMatch !== null && request.method === "GET") {
            const id = Number(idMatch[1]);
            const plan = await service.getById(id);
            return legacySuccess(plan);
        }

        // PUT /api/v1/admin/payment/plans/:id — update
        if (idMatch !== null && request.method === "PUT") {
            const id = Number(idMatch[1]);
            const body = await request.json() as {
                group_id?: number; name?: string; description?: string;
                price?: number; original_price?: number | null;
                validity_days?: number; validity_unit?: string;
                features?: string; product_name?: string;
                for_sale?: number; sort_order?: number;
            };
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const updated = await service.update(id, {
                groupId: body.group_id,
                name: body.name,
                description: body.description,
                price: body.price,
                originalPrice: body.original_price,
                validityDays: body.validity_days,
                validityUnit: body.validity_unit,
                features: body.features,
                productName: body.product_name,
                forSale: body.for_sale,
                sortOrder: body.sort_order,
            });
            return legacySuccess(updated);
        }

        // DELETE /api/v1/admin/payment/plans/:id — delete
        if (idMatch !== null && request.method === "DELETE") {
            const id = Number(idMatch[1]);
            await service.delete(id);
            return legacySuccess({ message: "Subscription plan deleted successfully" });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof PaymentPlanError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
