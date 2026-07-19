import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PaymentUserService, PaymentUserError } from "../services/payment-user.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError,
} from "./responses.ts";

const CONFIG_PATH = "/api/v1/payment/config";
const PLANS_PATH = "/api/v1/payment/plans";
const LIMITS_PATH = "/api/v1/payment/limits";
const CHECKOUT_PATH = "/api/v1/payment/checkout-info";
const ORDERS_PATH = "/api/v1/payment/orders";
const ORDERS_VERIFY = "/api/v1/payment/orders/verify";
const ORDERS_MY = "/api/v1/payment/orders/my";
const ORDERS_REFUND_ELIGIBLE = "/api/v1/payment/orders/refund-eligible-providers";
const ORDERS_ID = /^\/api\/v1\/payment\/orders\/(\d+)$/u;
const ORDERS_ID_CANCEL = /^\/api\/v1\/payment\/orders\/(\d+)\/cancel$/u;
const ORDERS_ID_REFUND = /^\/api\/v1\/payment\/orders\/(\d+)\/refund-request$/u;
const PUBLIC_VERIFY = "/api/v1/payment/public/orders/verify";
const PUBLIC_RESOLVE = "/api/v1/payment/public/orders/resolve";

export interface StagedPaymentUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedPaymentUserDependencies {
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

function parseQueryString(url: URL, key: string): string | undefined {
    const value = url.searchParams.get(key);
    return value !== null && value.trim() !== "" ? value.trim() : undefined;
}

async function authenticateUser(
    request: Request,
    env: StagedPaymentUserEnv,
    clock: () => number
): Promise<{ userId: number; userEmail: string; userName: string; role: string }> {
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
    return {
        userId: subject.user.id,
        userEmail: subject.user.email,
        userName: subject.user.username || subject.user.email,
        role: subject.user.role,
    };
}

export async function routeStagedPaymentUser(
    request: Request,
    env: StagedPaymentUserEnv,
    dependencies: StagedPaymentUserDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const idMatch = ORDERS_ID.exec(path);
    const cancelMatch = ORDERS_ID_CANCEL.exec(path);
    const refundMatch = ORDERS_ID_REFUND.exec(path);

    const isKnownPath =
        path === CONFIG_PATH ||
        path === PLANS_PATH ||
        path === LIMITS_PATH ||
        path === CHECKOUT_PATH ||
        path === ORDERS_PATH ||
        path === ORDERS_VERIFY ||
        path === ORDERS_MY ||
        path === ORDERS_REFUND_ELIGIBLE ||
        idMatch !== null ||
        cancelMatch !== null ||
        refundMatch !== null ||
        path === PUBLIC_VERIFY ||
        path === PUBLIC_RESOLVE;

    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        // --- PUBLIC ROUTES (no auth) ---

        // POST /api/v1/payment/public/orders/verify — public order verify (DB only)
        if (path === PUBLIC_VERIFY && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body.out_trade_no !== "string") {
                return legacyError(400, "out_trade_no is required", "INVALID_BODY");
            }
            const service = new D1PaymentUserService(env.DB);
            const order = await service["orderRepo"].getByOutTradeNo(body.out_trade_no);
            if (!order) return legacyError(404, "Order not found", "NOT_FOUND");
            return legacySuccess({
                out_trade_no: order.outTradeNo,
                status: order.status,
                paid: order.status === "PAID" || order.status === "COMPLETED" || order.status === "PROCESSING",
                created_at: order.createdAt,
                expires_at: order.expiresAt,
                paid_at: order.paidAt,
                completed_at: order.completedAt,
            });
        }

        // GET /api/v1/payment/config — public config (no auth needed)
        if (path === CONFIG_PATH && request.method === "GET") {
            const service = new D1PaymentUserService(env.DB);
            const cfg = await service.getConfig();
            return legacySuccess(cfg);
        }

        // GET /api/v1/payment/plans — public plans (no auth needed)
        if (path === PLANS_PATH && request.method === "GET") {
            const service = new D1PaymentUserService(env.DB);
            const plans = await service.getPlans();
            return legacySuccess(plans);
        }

        // GET /api/v1/payment/limits — public limits (no auth needed)
        if (path === LIMITS_PATH && request.method === "GET") {
            const service = new D1PaymentUserService(env.DB);
            const limits = await service.getLimits();
            return legacySuccess(limits);
        }

        // GET /api/v1/payment/checkout-info — public checkout info (no auth needed)
        if (path === CHECKOUT_PATH && request.method === "GET") {
            const service = new D1PaymentUserService(env.DB);
            const info = await service.getCheckoutInfo();
            return legacySuccess(info);
        }

        // --- AUTHENTICATED ROUTES ---
        const auth = await authenticateUser(request, env, clock);
        const service = new D1PaymentUserService(env.DB);

        // POST /api/v1/payment/orders — create order
        if (path === ORDERS_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const paymentType = body.payment_type as string | undefined;
            if (!paymentType) return legacyError(400, "payment_type is required", "INVALID_BODY");

            const orderType = (body.order_type as string) ?? "balance";
            if (!["balance", "subscription"].includes(orderType)) {
                return legacyError(400, "order_type must be 'balance' or 'subscription'", "INVALID_BODY");
            }

            let amount = Number(body.amount);
            if (!Number.isFinite(amount) || amount <= 0) {
                return legacyError(400, "amount must be a positive number", "INVALID_BODY");
            }
            if (Math.round(amount * 100) !== amount * 100) {
                return legacyError(400, "amount must have at most two decimal places", "INVALID_BODY");
            }

            let returnUrl: string | null = null;
            if (body.return_url !== undefined && body.return_url !== null) {
                if (typeof body.return_url !== "string" || body.return_url.length > 2048) {
                    return legacyError(400, "return_url must be a valid URL", "INVALID_BODY");
                }
                try {
                    const parsed = new URL(body.return_url);
                    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("unsupported protocol");
                    returnUrl = parsed.toString();
                } catch {
                    return legacyError(400, "return_url must be a valid HTTP(S) URL", "INVALID_BODY");
                }
            }

            const ip = "127.0.0.1";

            const result = await service.createOrder({
                userId: auth.userId,
                userEmail: auth.userEmail,
                userName: auth.userName,
                amount,
                paymentType,
                orderType,
                planId: body.plan_id ? Number(body.plan_id) : null,
                clientIp: ip,
                srcHost: url.host,
                srcUrl: request.url,
                returnUrl,
            });
            return legacySuccess(result);
        }

        // POST /api/v1/payment/orders/verify — verify order by out_trade_no
        if (path === ORDERS_VERIFY && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body.out_trade_no !== "string") {
                return legacyError(400, "out_trade_no is required", "INVALID_BODY");
            }
            const order = await service.verifyOrder(body.out_trade_no, auth.userId);
            return legacySuccess(order);
        }

        // GET /api/v1/payment/orders/my — list my orders
        if (path === ORDERS_MY && request.method === "GET") {
            const page = parseOptionalInt(url, "page") ?? 1;
            const pageSize = parseOptionalInt(url, "page_size") ?? 20;
            const status = parseQueryString(url, "status");
            const orderType = parseQueryString(url, "order_type");
            const paymentType = parseQueryString(url, "payment_type");
            const result = await service.getMyOrders({ userId: auth.userId, page, pageSize, status, orderType, paymentType });
            return legacySuccess({
                items: result.items,
                total: result.total,
                page: result.page,
                page_size: result.pageSize,
            });
        }

        // GET /api/v1/payment/orders/:id — get order detail
        if (idMatch !== null && request.method === "GET" && !cancelMatch && !refundMatch) {
            const id = Number(idMatch[1]);
            const order = await service.getOrder(id, auth.userId);
            return legacySuccess(order);
        }

        // POST /api/v1/payment/orders/:id/cancel — cancel order
        if (cancelMatch !== null && request.method === "POST") {
            const id = Number(cancelMatch[1]);
            const message = await service.cancelOrder(id, auth.userId);
            return legacySuccess({ message });
        }

        // POST /api/v1/payment/orders/:id/refund-request — request refund
        if (refundMatch !== null && request.method === "POST") {
            const id = Number(refundMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            const reason = (body.reason as string) ?? "";
            await service.requestRefund(id, auth.userId, reason);
            return legacySuccess({ message: "refund requested" });
        }

        // GET /api/v1/payment/orders/refund-eligible-providers
        if (path === ORDERS_REFUND_ELIGIBLE && request.method === "GET") {
            const ids = await service.getRefundEligibleProviders();
            return legacySuccess({ provider_instance_ids: ids });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof PaymentUserError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
