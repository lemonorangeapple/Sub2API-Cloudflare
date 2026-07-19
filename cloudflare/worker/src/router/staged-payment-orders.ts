import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PaymentOrderService, PaymentOrderError } from "../services/payment-orders.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const ORDERS_PATH = "/api/v1/admin/payment/orders";
const ORDERS_ID = /^\/api\/v1\/admin\/payment\/orders\/(\d+)$/u;
const ORDERS_ID_CANCEL = /^\/api\/v1\/admin\/payment\/orders\/(\d+)\/cancel$/u;
const ORDERS_ID_RETRY = /^\/api\/v1\/admin\/payment\/orders\/(\d+)\/retry$/u;

export interface StagedPaymentOrdersEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedPaymentOrdersDependencies {
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

function parseQueryString(url: URL, key: string): string | undefined {
    const value = url.searchParams.get(key);
    return value !== null && value.trim() !== "" ? value.trim() : undefined;
}

async function authenticateAdmin(
    request: Request,
    env: StagedPaymentOrdersEnv,
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

export async function routeStagedPaymentOrders(
    request: Request,
    env: StagedPaymentOrdersEnv,
    dependencies: StagedPaymentOrdersDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const cancelMatch = ORDERS_ID_CANCEL.exec(path);
    const retryMatch = ORDERS_ID_RETRY.exec(path);
    const idMatch = ORDERS_ID.exec(path);

    const isKnownPath =
        path === ORDERS_PATH ||
        cancelMatch !== null ||
        retryMatch !== null ||
        idMatch !== null;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") return middlewareAuthError(403, "FORBIDDEN", "Admin access required");

        const service = new D1PaymentOrderService(env.DB);

        // GET /api/v1/admin/payment/orders — list
        if (path === ORDERS_PATH && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const userId = parseOptionalInt(url, "user_id");
            const status = parseQueryString(url, "status");
            const orderType = parseQueryString(url, "order_type");
            const paymentType = parseQueryString(url, "payment_type");
            const keyword = parseQueryString(url, "keyword");
            const result = await service.list({ page, pageSize, userId, status, orderType, paymentType, keyword });
            return legacySuccess({ items: result.items, total: result.total, page, page_size: pageSize });
        }

        // GET /api/v1/admin/payment/orders/:id — get detail
        if (idMatch !== null && request.method === "GET" && !cancelMatch && !retryMatch) {
            const id = Number(idMatch[1]);
            const result = await service.getById(id);
            return legacySuccess(result);
        }

        // POST /api/v1/admin/payment/orders/:id/cancel — cancel order
        if (cancelMatch !== null && request.method === "POST") {
            const id = Number(cancelMatch[1]);
            const message = await service.cancelOrder(id);
            return legacySuccess({ message });
        }

        // POST /api/v1/admin/payment/orders/:id/retry — retry fulfillment
        if (retryMatch !== null && request.method === "POST") {
            const id = Number(retryMatch[1]);
            await service.retryFulfillment(id);
            return legacySuccess({ message: "fulfillment retried" });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof PaymentOrderError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
