import type { D1Database } from "../types/d1.ts";
import { D1PaymentWebhookService, PaymentWebhookError } from "../services/payment-webhook.ts";
import { legacyError, legacyInternalError, legacySuccess, routerError } from "./responses.ts";

export interface StagedPaymentWebhookEnv { DB?: D1Database; }

export async function routeStagedPaymentWebhook(request: Request, env: StagedPaymentWebhookEnv): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    if (path !== "/api/v1/payment/webhook/stripe" && path !== "/api/v1/payment/webhook/airwallex") return null;
    if (request.method !== "POST") return legacyError(405, "Method not allowed", "METHOD_NOT_ALLOWED");
    if (!env.DB) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    try {
        const service = new D1PaymentWebhookService(env.DB);
        const rawBody = await request.text();
        const result = path.endsWith("/stripe")
            ? await service.handleStripe(rawBody, request.headers.get("stripe-signature"))
            : await service.handleAirwallex(rawBody, request.headers.get("x-timestamp"), request.headers.get("x-signature"));
        return legacySuccess(result);
    } catch (error) {
        if (error instanceof PaymentWebhookError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
