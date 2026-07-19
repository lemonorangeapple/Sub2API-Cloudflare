import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow } from "../repositories/d1.ts";
import { D1PaymentOrderRepository, type PaymentOrderRecord } from "../repositories/payment-orders.ts";
import { D1SubscriptionPlanRepository, type SubscriptionPlanRecord } from "../repositories/payment-plans.ts";
import { D1PaymentProviderRepository, type PaymentProviderRecord } from "../repositories/payment-providers.ts";
import { D1PaymentConfigDashboardService } from "./payment-config-dashboard.ts";

export class PaymentUserError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "PaymentUserError";
        this.status = status;
        this.code = code;
    }
}

function errNotFound(msg = "Not found"): PaymentUserError {
    return new PaymentUserError(404, msg, "NOT_FOUND");
}

function errBadRequest(msg: string): PaymentUserError {
    return new PaymentUserError(400, msg, "BAD_REQUEST");
}

function errForbidden(msg = "Forbidden"): PaymentUserError {
    return new PaymentUserError(403, msg, "FORBIDDEN");
}

function errUpstream(msg: string): PaymentUserError {
    return new PaymentUserError(502, msg, "PAYMENT_PROVIDER_ERROR");
}

function nowISO(): string {
    return new Date().toISOString();
}

function generateOutTradeNo(): string {
    const ts = new Date();
    const dateStr = ts.getFullYear().toString() +
        String(ts.getMonth() + 1).padStart(2, "0") +
        String(ts.getDate()).padStart(2, "0");
    const rand = Math.random().toString(36).substring(2, 10);
    return `sub2_${dateStr}${rand}`;
}

interface GroupInfo {
    id: number;
    name: string;
    platform: string;
    rateMultiplier: number;
    peakRateEnabled: number;
    peakStart: string;
    peakEnd: string;
    peakRateMultiplier: number;
    dailyLimitUsd: number | null;
    weeklyLimitUsd: number | null;
    monthlyLimitUsd: number | null;
    modelScopes: string;
}

interface PlanWithGroup extends SubscriptionPlanRecord {
    groupPlatform: string;
    groupName: string;
    rateMultiplier: number;
    peakRateEnabled: boolean;
    peakStart: string;
    peakEnd: string;
    peakRateMultiplier: number;
    dailyLimitUsd: number | null;
    weeklyLimitUsd: number | null;
    monthlyLimitUsd: number | null;
    modelScopes: string;
}

interface MethodLimits {
    paymentType: string;
    currency: string;
    feeRate: number;
    dailyLimit: number;
    singleMin: number;
    singleMax: number;
    enabled: boolean;
}

interface CheckoutPlan extends PlanWithGroup {
    featuresList: string[];
}

export interface CheckoutInfo {
    methods: Record<string, MethodLimits>;
    globalMin: number;
    globalMax: number;
    plans: CheckoutPlan[];
    balanceDisabled: boolean;
    balanceRechargeMultiplier: number;
    subscriptionUsdToCnyRate: number;
    rechargeFeeRate: number;
    helpText: string;
    helpImageUrl: string;
    stripePublishableKey: string;
    alipayForceQrcode: boolean;
}

export interface UserOrderResult {
    id: number;
    amount: number;
    payAmount: number;
    feeRate: number;
    paymentType: string;
    outTradeNo: string;
    status: string;
    orderType: string;
    createdAt: string;
    expiresAt: string;
    paidAt: string | null;
    completedAt: string | null;
    refundAmount: number;
    refundReason: string | null;
    refundRequestedAt: string | null;
    refundRequestReason: string | null;
    planId: number | null;
    providerInstanceId: string | null;
    payUrl: string | null;
    qrCode: string | null;
}

function toUserOrderResult(o: PaymentOrderRecord): UserOrderResult {
    return {
        id: o.id,
        amount: o.amount,
        payAmount: o.payAmount,
        feeRate: o.feeRate,
        paymentType: o.paymentType,
        outTradeNo: o.outTradeNo,
        status: o.status,
        orderType: o.orderType,
        createdAt: o.createdAt,
        expiresAt: o.expiresAt,
        paidAt: o.paidAt,
        completedAt: o.completedAt,
        refundAmount: o.refundAmount,
        refundReason: o.refundReason,
        refundRequestedAt: o.refundRequestedAt,
        refundRequestReason: o.refundRequestReason,
        planId: o.planId,
        providerInstanceId: o.providerInstanceId,
        payUrl: o.payUrl,
        qrCode: o.qrCode,
    };
}

export class D1PaymentUserService {
    private db: D1Database;
    private configService: D1PaymentConfigDashboardService;
    private orderRepo: D1PaymentOrderRepository;
    private planRepo: D1SubscriptionPlanRepository;
    private providerRepo: D1PaymentProviderRepository;

    constructor(db: D1Database) {
        this.db = db;
        this.configService = new D1PaymentConfigDashboardService(db);
        this.orderRepo = new D1PaymentOrderRepository(db);
        this.planRepo = new D1SubscriptionPlanRepository(db);
        this.providerRepo = new D1PaymentProviderRepository(db);
    }

    private async getGroupInfoMap(): Promise<Map<number, GroupInfo>> {
        const rows = await allRows<{
            id: number; name: string; platform: string;
            rate_multiplier: number; peak_rate_enabled: number;
            peak_start: string; peak_end: string; peak_rate_multiplier: number;
            daily_limit_usd: number | null; weekly_limit_usd: number | null;
            monthly_limit_usd: number | null;
            supported_model_scopes: string;
        }>(this.db, `SELECT id, name, platform, rate_multiplier, peak_rate_enabled, peak_start, peak_end, peak_rate_multiplier, daily_limit_usd, weekly_limit_usd, monthly_limit_usd, supported_model_scopes FROM groups WHERE deleted_at IS NULL`, []);
        const map = new Map<number, GroupInfo>();
        for (const r of rows) {
            map.set(r.id, {
                id: r.id,
                name: r.name,
                platform: r.platform,
                rateMultiplier: r.rate_multiplier,
                peakRateEnabled: r.peak_rate_enabled,
                peakStart: r.peak_start,
                peakEnd: r.peak_end,
                peakRateMultiplier: r.peak_rate_multiplier,
                dailyLimitUsd: r.daily_limit_usd,
                weeklyLimitUsd: r.weekly_limit_usd,
                monthlyLimitUsd: r.monthly_limit_usd,
                modelScopes: r.supported_model_scopes,
            });
        }
        return map;
    }

    private enrichPlans(plans: SubscriptionPlanRecord[], groupMap: Map<number, GroupInfo>): PlanWithGroup[] {
        return plans.map(p => {
            const g = groupMap.get(p.groupId);
            return {
                ...p,
                groupPlatform: g?.platform ?? "",
                groupName: g?.name ?? "",
                rateMultiplier: g?.rateMultiplier ?? 1,
                peakRateEnabled: (g?.peakRateEnabled ?? 0) !== 0,
                peakStart: g?.peakStart ?? "",
                peakEnd: g?.peakEnd ?? "",
                peakRateMultiplier: g?.peakRateMultiplier ?? 1,
                dailyLimitUsd: g?.dailyLimitUsd ?? null,
                weeklyLimitUsd: g?.weeklyLimitUsd ?? null,
                monthlyLimitUsd: g?.monthlyLimitUsd ?? null,
                modelScopes: g?.modelScopes ?? "",
            };
        });
    }

    async getConfig(): Promise<Record<string, unknown>> {
        const cfg = await this.configService.getConfig();
        const providers = await this.providerRepo.list();
        const stripeProvider = providers.find(p => p.providerKey === "stripe" && p.enabled === 1);
        return {
            enabled: cfg.enabled,
            min_amount: cfg.minAmount,
            max_amount: cfg.maxAmount,
            daily_limit: cfg.dailyLimit,
            order_timeout_minutes: cfg.orderTimeoutMinutes,
            max_pending_orders: cfg.maxPendingOrders,
            enabled_payment_types: cfg.enabledPaymentTypes,
            balance_disabled: cfg.balanceDisabled,
            balance_recharge_multiplier: cfg.balanceRechargeMultiplier,
            subscription_usd_to_cny_rate: cfg.subscriptionUsdToCnyRate,
            recharge_fee_rate: cfg.rechargeFeeRate,
            load_balance_strategy: cfg.loadBalanceStrategy,
            alipay_force_qrcode: cfg.alipayForceQrcode,
            cancel_rate_limit_enabled: cfg.cancelRateLimitEnabled,
            cancel_rate_limit_max: cfg.cancelRateLimitMax,
            cancel_rate_limit_window: cfg.cancelRateLimitWindow,
            cancel_rate_limit_unit: cfg.cancelRateLimitUnit,
            cancel_rate_limit_window_mode: cfg.cancelRateLimitMode,
            stripe_publishable_key: stripeProvider ? this.extractStripePublishableKey(stripeProvider.config) : "",
            help_text: "",
            help_image_url: "",
        };
    }

    private extractStripePublishableKey(config: string): string {
        try {
            const parsed = JSON.parse(config);
            return parsed.publishable_key ?? parsed.publishableKey ?? "";
        } catch {
            return "";
        }
    }

    async getPlans(): Promise<PlanWithGroup[]> {
        const allPlans = await this.planRepo.list();
        const forSale = allPlans.filter(p => p.forSale === 1);
        const groupMap = await this.getGroupInfoMap();
        return this.enrichPlans(forSale, groupMap);
    }

    async getLimits(): Promise<{ methods: Record<string, MethodLimits>; globalMin: number; globalMax: number }> {
        const providers = await this.providerRepo.list();
        const enabled = providers.filter(p => p.enabled === 1);
        const cfg = await this.configService.getConfig();

        const pmtTypeMap = new Map<string, PaymentProviderRecord[]>();
        for (const p of enabled) {
            const types = p.supportedTypes ? p.supportedTypes.split(",").map(s => s.trim()).filter(Boolean) : [p.providerKey];
            for (const t of types) {
                if (!pmtTypeMap.has(t)) pmtTypeMap.set(t, []);
                pmtTypeMap.get(t)!.push(p);
            }
        }

        const methods: Record<string, MethodLimits> = {};
        let globalMin = Infinity;
        let globalMax = 0;

        for (const [pmtType, instances] of pmtTypeMap) {
            let dailyLimit = 0;
            let singleMin = Infinity;
            let singleMax = 0;
            for (const inst of instances) {
                let instLimits: Record<string, unknown> = {};
                try { instLimits = JSON.parse(inst.limits || "{}"); } catch { /* ignore */ }
                const dl = Number(instLimits.daily_limit ?? instLimits.dailyLimit ?? 0);
                if (dl > dailyLimit) dailyLimit = dl;
                const smin = Number(instLimits.single_min ?? instLimits.singleMin ?? 1);
                if (smin < singleMin) singleMin = smin;
                const smax = Number(instLimits.single_max ?? instLimits.singleMax ?? 0);
                if (smax > singleMax) singleMax = smax;
            }

            const currency = pmtType === "alipay" || pmtType === "wxpay" ? "CNY" : "USD";
            const feeRate = pmtType === "alipay" ? 0.006 : pmtType === "wxpay" ? 0.006 : 0.02;

            if (singleMin < globalMin) globalMin = singleMin;
            if (singleMax > globalMax) globalMax = singleMax;

            methods[pmtType] = {
                paymentType: pmtType,
                currency,
                feeRate,
                dailyLimit,
                singleMin: singleMin === Infinity ? cfg.minAmount : singleMin,
                singleMax: singleMax === 0 ? cfg.maxAmount : singleMax,
                enabled: true,
            };
        }

        if (globalMin === Infinity) globalMin = cfg.minAmount;
        if (globalMax === 0) globalMax = cfg.maxAmount;

        return { methods, globalMin, globalMax };
    }

    async getCheckoutInfo(): Promise<CheckoutInfo> {
        const cfg = await this.configService.getConfig();
        const { methods, globalMin, globalMax } = await this.getLimits();
        const plans = await this.getPlans();
        const providers = await this.providerRepo.list();
        const stripeProvider = providers.find(p => p.providerKey === "stripe" && p.enabled === 1);

        const checkoutPlans: CheckoutPlan[] = plans.map(p => ({
            ...p,
            featuresList: p.features ? p.features.split("\n").map(s => s.trim()).filter(Boolean) : [],
        }));

        return {
            methods,
            globalMin,
            globalMax,
            plans: checkoutPlans,
            balanceDisabled: cfg.balanceDisabled,
            balanceRechargeMultiplier: cfg.balanceRechargeMultiplier,
            subscriptionUsdToCnyRate: cfg.subscriptionUsdToCnyRate,
            rechargeFeeRate: cfg.rechargeFeeRate,
            helpText: "",
            helpImageUrl: "",
            stripePublishableKey: stripeProvider ? this.extractStripePublishableKey(stripeProvider.config) : "",
            alipayForceQrcode: cfg.alipayForceQrcode,
        };
    }

    async createOrder(input: {
        userId: number; userEmail: string; userName: string;
        amount: number; paymentType: string;
        orderType: string; planId?: number | null;
        clientIp: string; srcHost: string; srcUrl?: string | null;
        returnUrl?: string | null;
    }): Promise<Record<string, unknown>> {
        const cfg = await this.configService.getConfig();
        if (!cfg.enabled) throw errBadRequest("Payment system is disabled");

        const providers = await this.providerRepo.list();
        const enabledProviders = providers.filter(p =>
            p.enabled === 1 &&
            (p.supportedTypes.includes(input.paymentType) || p.providerKey === input.paymentType)
        );
        if (enabledProviders.length === 0) throw errBadRequest("No enabled payment provider for this payment type");

        const provider = enabledProviders[0];
        const pendingCount = await this.orderRepo.countPendingByUserId(input.userId);
        if (pendingCount >= cfg.maxPendingOrders) throw errBadRequest("Too many pending orders");

        if (input.amount < cfg.minAmount || (cfg.maxAmount > 0 && input.amount > cfg.maxAmount)) {
            throw errBadRequest("Amount out of allowed range");
        }

        if (input.orderType === "subscription") {
            if (!input.planId) throw errBadRequest("Plan ID required for subscription orders");
            const plan = await this.planRepo.getById(input.planId);
            if (!plan || plan.forSale !== 1) throw errBadRequest("Plan not available");
        }

        const feeRate = input.paymentType === "alipay" || input.paymentType === "wxpay" ? 0.006 : 0.02;
        const payAmount = input.orderType === "subscription"
            ? input.amount * (cfg.subscriptionUsdToCnyRate || 1) * (1 + feeRate)
            : input.amount * (1 + feeRate);

        const outTradeNo = generateOutTradeNo();
        const timeoutMinutes = cfg.orderTimeoutMinutes || 30;
        const expiresAt = new Date(Date.now() + timeoutMinutes * 60000).toISOString();

        const order = await this.orderRepo.create({
            userId: input.userId,
            userEmail: input.userEmail,
            userName: input.userName,
            amount: input.orderType === "subscription" ? input.amount * (cfg.subscriptionUsdToCnyRate || 1) : input.amount,
            payAmount: Math.round(payAmount * 100) / 100,
            feeRate,
            outTradeNo,
            paymentType: input.paymentType,
            orderType: input.orderType,
            planId: input.planId ?? null,
            providerInstanceId: String(provider.id),
            providerKey: provider.providerKey,
            providerSnapshot: JSON.stringify({
                provider_instance_id: provider.id,
                provider_key: provider.providerKey,
                payment_mode: provider.paymentMode,
            }),
            clientIp: input.clientIp,
            srcHost: input.srcHost,
            srcUrl: input.srcUrl ?? null,
            expiresAt,
            payUrl: null,
            qrCode: null,
        });

        await this.orderRepo.writeAuditLog(String(order.id), "ORDER_CREATED", `User created ${input.orderType} order via ${input.paymentType}`, "user");

        const external = await createExternalPayment(provider, order, input.paymentType, input.returnUrl);
        if (external !== null) {
            await this.orderRepo.updateStatus(order.id, order.status, {
                payment_trade_no: external.tradeNo,
                pay_url: external.payUrl ?? null,
                qr_code: external.qrCode ?? null,
            });
        }

        return {
            order_id: order.id,
            amount: order.amount,
            pay_amount: order.payAmount,
            fee_rate: order.feeRate,
            status: order.status,
            out_trade_no: order.outTradeNo,
            payment_type: order.paymentType,
            order_type: order.orderType,
            expires_at: order.expiresAt,
            created_at: order.createdAt,
            pay_url: external?.payUrl ?? null,
            qr_code: external?.qrCode ?? null,
            client_secret: external?.clientSecret ?? null,
            intent_id: external?.intentId ?? null,
            plan_id: order.planId,
            provider_key: provider.providerKey,
            result_type: "order_created",
        };
    }

    async getMyOrders(params: {
        userId: number; page: number; pageSize: number;
        status?: string; orderType?: string; paymentType?: string;
    }): Promise<{ items: UserOrderResult[]; total: number; page: number; pageSize: number }> {
        const result = await this.orderRepo.list({
            page: params.page, pageSize: params.pageSize,
            userId: params.userId, status: params.status,
            orderType: params.orderType, paymentType: params.paymentType,
        });
        return {
            items: result.items.map(toUserOrderResult),
            total: result.total,
            page: params.page,
            pageSize: params.pageSize,
        };
    }

    async getOrder(orderId: number, userId: number): Promise<UserOrderResult> {
        const order = await this.orderRepo.getById(orderId);
        if (!order) throw errNotFound("Order not found");
        if (order.userId !== userId) throw errForbidden("This order does not belong to you");
        return toUserOrderResult(order);
    }

    async cancelOrder(orderId: number, userId: number): Promise<string> {
        const order = await this.orderRepo.getById(orderId);
        if (!order) throw errNotFound("Order not found");
        if (order.userId !== userId) throw errForbidden("This order does not belong to you");
        if (order.status !== "PENDING") throw errBadRequest("Only pending orders can be cancelled");
        await this.orderRepo.updateStatus(orderId, "CANCELLED", { failed_reason: "Cancelled by user" });
        await this.orderRepo.writeAuditLog(String(orderId), "ORDER_CANCELLED", "User cancelled pending order", "user");
        return "cancelled";
    }

    async verifyOrder(outTradeNo: string, userId: number): Promise<UserOrderResult> {
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(outTradeNo)) throw errBadRequest("Invalid out_trade_no format");
        const order = await this.orderRepo.getByOutTradeNo(outTradeNo);
        if (!order) throw errNotFound("Order not found");
        if (order.userId !== userId) throw errForbidden("This order does not belong to you");
        return toUserOrderResult(order);
    }

    async requestRefund(orderId: number, userId: number, reason: string): Promise<void> {
        const order = await this.orderRepo.getById(orderId);
        if (!order) throw errNotFound("Order not found");
        if (order.userId !== userId) throw errForbidden("This order does not belong to you");
        if (order.status !== "COMPLETED") throw errBadRequest("Only completed orders can request refund");
        if (order.orderType !== "balance") throw errBadRequest("Only balance orders can request refund");

        const provider = order.providerInstanceId
            ? await this.providerRepo.getById(Number(order.providerInstanceId))
            : null;
        if (!provider || provider.allowUserRefund !== 1) throw errBadRequest("This provider does not allow user refunds");

        const ts = nowISO();
        await this.orderRepo.updateStatus(orderId, "REFUND_REQUESTED", {
            refund_requested_at: ts,
            refund_request_reason: reason,
            refund_requested_by: "user",
        });
        await this.orderRepo.writeAuditLog(String(orderId), "REFUND_REQUESTED", `User requested refund: ${reason}`, "user");
    }

    async getRefundEligibleProviders(): Promise<string[]> {
        const providers = await this.providerRepo.list();
        return providers
            .filter(p => p.refundEnabled === 1 && p.allowUserRefund === 1)
            .map(p => String(p.id));
    }
}

async function createExternalPayment(
    provider: PaymentProviderRecord,
    order: PaymentOrderRecord,
    paymentType: string,
    returnUrl: string | null | undefined,
): Promise<{ tradeNo: string; clientSecret?: string; intentId?: string; payUrl?: string | null; qrCode?: string | null } | null> {
    const config = parseObject(provider.config);
    if (provider.providerKey === "stripe") {
        const secret = stringValue(config.secretKey, config.secret_key);
        if (!secret) throw errBadRequest("Stripe secretKey is not configured");
        const currency = (stringValue(config.currency) || "USD").toLowerCase();
        const body = new URLSearchParams();
        body.set("amount", String(toMinorUnits(order.payAmount, currency)));
        body.set("currency", currency);
        body.set("description", `${order.orderType} ${order.outTradeNo}`);
        body.set("metadata[order_id]", order.outTradeNo);
        const method = paymentType === "alipay" ? "alipay" : paymentType === "wxpay" ? "wechat_pay" : "card";
        body.append("payment_method_types[]", method);
        const response = await fetch("https://api.stripe.com/v1/payment_intents", {
            method: "POST",
            headers: { authorization: `Basic ${base64(`${secret}:`)}`, "content-type": "application/x-www-form-urlencoded", "idempotency-key": `payment-${order.outTradeNo}` },
            body,
        });
        const payload = await response.json() as Record<string, unknown>;
        if (!response.ok || typeof payload.id !== "string" || typeof payload.client_secret !== "string") {
            throw errUpstream(typeof payload.error === "object" && payload.error !== null && "message" in payload.error ? String(payload.error.message) : "Stripe payment creation failed");
        }
        return { tradeNo: payload.id, intentId: payload.id, clientSecret: payload.client_secret, payUrl: null, qrCode: null };
    }
    if (provider.providerKey === "airwallex") {
        const clientId = stringValue(config.clientId, config.client_id);
        const apiKey = stringValue(config.apiKey, config.api_key);
        const apiBase = stringValue(config.apiBase, config.api_base) || "https://api.airwallex.com/api/v1";
        let base: URL;
        try { base = new URL(apiBase); } catch { throw errBadRequest("Airwallex apiBase is invalid"); }
        if (base.protocol !== "https:" || !["api.airwallex.com", "api-demo.airwallex.com"].includes(base.hostname)) {
            throw errBadRequest("Airwallex apiBase must be an official HTTPS endpoint");
        }
        if (!clientId || !apiKey) throw errBadRequest("Airwallex clientId and apiKey are not configured");
        const authResponse = await fetch(joinProviderUrl(base, "authentication/login"), {
            method: "POST", headers: { "content-type": "application/json", "x-client-id": clientId, "x-api-key": apiKey, ...(stringValue(config.accountId) ? { "x-login-as": stringValue(config.accountId) } : {}) },
        });
        const authPayload = await authResponse.json() as Record<string, unknown>;
        const token = stringValue(authPayload.token);
        if (!authResponse.ok || !token) throw errUpstream("Airwallex authentication failed");
        const intentResponse = await fetch(joinProviderUrl(base, "pa/payment_intents/create"), {
            method: "POST",
            headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...(stringValue(config.accountId) ? { "x-on-behalf-of": stringValue(config.accountId) } : {}) },
            body: JSON.stringify({ request_id: `payment-${order.outTradeNo}`, amount: order.payAmount, currency: (stringValue(config.currency) || "CNY").toUpperCase(), merchant_order_id: order.outTradeNo, return_url: returnUrl || undefined, metadata: { order_id: order.outTradeNo } }),
        });
        const intent = await intentResponse.json() as Record<string, unknown>;
        const intentId = stringValue(intent.id);
        const clientSecret = stringValue(intent.client_secret, intent.clientSecret);
        if (!intentResponse.ok || !intentId || !clientSecret) throw errUpstream("Airwallex payment intent creation failed");
        return { tradeNo: intentId, intentId, clientSecret, payUrl: null, qrCode: null };
    }
    return null;
}

function parseObject(value: string): Record<string, unknown> {
    try { const parsed = JSON.parse(value); return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}; } catch { return {}; }
}

function stringValue(...values: unknown[]): string {
    for (const value of values) if (typeof value === "string" && value.trim()) return value.trim();
    return "";
}

function base64(value: string): string {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function toMinorUnits(amount: number, currency: string): number {
    const zeroDecimal = new Set(["bif", "clp", "djf", "gnf", "isk", "jpy", "kmf", "krw", "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf"]);
    return Math.round(amount * (zeroDecimal.has(currency) ? 1 : 100));
}

function joinProviderUrl(base: URL, path: string): string {
    return new URL(`${base.pathname.replace(/\/$/, "")}/${path.replace(/^\//, "")}`, base.origin).toString();
}
