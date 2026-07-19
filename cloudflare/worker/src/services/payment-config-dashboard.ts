import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow } from "../repositories/d1.ts";

export class PaymentConfigDashboardError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "PaymentConfigDashboardError";
        this.status = status;
        this.code = code;
    }
}

export interface PaymentDashboardStats {
    totalOrders: number;
    totalRevenue: number;
    totalRefund: number;
    pendingOrders: number;
    paidOrders: number;
    completedOrders: number;
    cancelledOrders: number;
    failedOrders: number;
    periodDays: number;
}

export interface PaymentConfigResponse {
    enabled: boolean;
    minAmount: number;
    maxAmount: number;
    dailyLimit: number;
    orderTimeoutMinutes: number;
    maxPendingOrders: number;
    balanceDisabled: boolean;
    balanceRechargeMultiplier: number;
    subscriptionUsdToCnyRate: number;
    rechargeFeeRate: number;
    loadBalanceStrategy: string;
    enabledPaymentTypes: string[];
    alipayForceQrcode: boolean;
    cancelRateLimitEnabled: boolean;
    cancelRateLimitMax: number;
    cancelRateLimitWindow: number;
    cancelRateLimitUnit: string;
    cancelRateLimitMode: string;
}

export interface UpdatePaymentConfigInput {
    enabled?: boolean;
    minAmount?: number;
    maxAmount?: number;
    dailyLimit?: number;
    orderTimeoutMinutes?: number;
    maxPendingOrders?: number;
    balanceDisabled?: boolean;
    balanceRechargeMultiplier?: number;
    subscriptionUsdToCnyRate?: number;
    rechargeFeeRate?: number;
    loadBalanceStrategy?: string;
    enabledPaymentTypes?: string[];
    alipayForceQrcode?: boolean;
    cancelRateLimitEnabled?: boolean;
    cancelRateLimitMax?: number;
    cancelRateLimitWindow?: number;
    cancelRateLimitUnit?: string;
    cancelRateLimitMode?: string;
}

export class D1PaymentConfigDashboardService {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async getConfig(): Promise<PaymentConfigResponse> {
        const rows = await allRows<{ key: string; value: string }>(this.db, `SELECT key, value FROM settings WHERE key LIKE 'payment_%'`, []);
        const map = new Map<string, string>();
        for (const r of rows) map.set(r.key, r.value);

        const getBool = (k: string, def: boolean): boolean => map.has(k) ? map.get(k) === "true" : def;
        const getNum = (k: string, def: number): number => map.has(k) ? Number(map.get(k)) : def;
        const getStr = (k: string, def: string): string => map.get(k) ?? def;

        const typesStr = getStr("payment_enabled_types", "");
        const enabledTypes = typesStr ? typesStr.split(",").map(s => s.trim()).filter(Boolean) : [];

        return {
            enabled: getBool("payment_enabled", false),
            minAmount: getNum("payment_min_amount", 1),
            maxAmount: getNum("payment_max_amount", 0),
            dailyLimit: getNum("payment_daily_limit", 0),
            orderTimeoutMinutes: getNum("payment_order_timeout_minutes", 30),
            maxPendingOrders: getNum("payment_max_pending_orders", 10),
            balanceDisabled: getBool("payment_balance_disabled", false),
            balanceRechargeMultiplier: getNum("payment_balance_recharge_multiplier", 1),
            subscriptionUsdToCnyRate: getNum("payment_subscription_usd_to_cny_rate", 0),
            rechargeFeeRate: getNum("payment_recharge_fee_rate", 0),
            loadBalanceStrategy: getStr("payment_load_balance_strategy", "round_robin"),
            enabledPaymentTypes: enabledTypes,
            alipayForceQrcode: getBool("payment_alipay_force_qrcode", false),
            cancelRateLimitEnabled: getBool("payment_cancel_rate_limit_enabled", false),
            cancelRateLimitMax: getNum("payment_cancel_rate_limit_max", 10),
            cancelRateLimitWindow: getNum("payment_cancel_rate_limit_window", 1),
            cancelRateLimitUnit: getStr("payment_cancel_rate_limit_unit", "hour"),
            cancelRateLimitMode: getStr("payment_cancel_rate_limit_window_mode", "sliding"),
        };
    }

    async updateConfig(input: UpdatePaymentConfigInput): Promise<void> {
        const updates: Record<string, string> = {};
        if (input.enabled !== undefined) updates.payment_enabled = input.enabled ? "true" : "false";
        if (input.minAmount !== undefined) updates.payment_min_amount = String(input.minAmount);
        if (input.maxAmount !== undefined) updates.payment_max_amount = String(input.maxAmount);
        if (input.dailyLimit !== undefined) updates.payment_daily_limit = String(input.dailyLimit);
        if (input.orderTimeoutMinutes !== undefined) updates.payment_order_timeout_minutes = String(input.orderTimeoutMinutes);
        if (input.maxPendingOrders !== undefined) updates.payment_max_pending_orders = String(input.maxPendingOrders);
        if (input.balanceDisabled !== undefined) updates.payment_balance_disabled = input.balanceDisabled ? "true" : "false";
        if (input.balanceRechargeMultiplier !== undefined) updates.payment_balance_recharge_multiplier = String(input.balanceRechargeMultiplier);
        if (input.subscriptionUsdToCnyRate !== undefined) updates.payment_subscription_usd_to_cny_rate = String(input.subscriptionUsdToCnyRate);
        if (input.rechargeFeeRate !== undefined) updates.payment_recharge_fee_rate = String(input.rechargeFeeRate);
        if (input.loadBalanceStrategy !== undefined) updates.payment_load_balance_strategy = input.loadBalanceStrategy;
        if (input.enabledPaymentTypes !== undefined) updates.payment_enabled_types = input.enabledPaymentTypes.join(",");
        if (input.alipayForceQrcode !== undefined) updates.payment_alipay_force_qrcode = input.alipayForceQrcode ? "true" : "false";
        if (input.cancelRateLimitEnabled !== undefined) updates.payment_cancel_rate_limit_enabled = input.cancelRateLimitEnabled ? "true" : "false";
        if (input.cancelRateLimitMax !== undefined) updates.payment_cancel_rate_limit_max = String(input.cancelRateLimitMax);
        if (input.cancelRateLimitWindow !== undefined) updates.payment_cancel_rate_limit_window = String(input.cancelRateLimitWindow);
        if (input.cancelRateLimitUnit !== undefined) updates.payment_cancel_rate_limit_unit = input.cancelRateLimitUnit;
        if (input.cancelRateLimitMode !== undefined) updates.payment_cancel_rate_limit_window_mode = input.cancelRateLimitMode;

        const ts = new Date().toISOString();
        for (const [key, value] of Object.entries(updates)) {
            await firstRow(this.db, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at RETURNING id`, [key, value, ts]);
        }
    }

    async getDashboardStats(days: number = 30): Promise<PaymentDashboardStats> {
        const since = new Date(Date.now() - days * 86400000).toISOString();

        const totals = await firstRow<{
            total: number; revenue: number; refund: number;
            pending: number; paid: number; completed: number;
            cancelled: number; failed: number;
        }>(this.db, `
            SELECT
                COUNT(*) as total,
                COALESCE(SUM(CASE WHEN status IN ('PAID','COMPLETED') THEN pay_amount ELSE 0 END), 0) as revenue,
                COALESCE(SUM(CASE WHEN status = 'REFUNDED' THEN refund_amount ELSE 0 END), 0) as refund,
                SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'PAID' THEN 1 ELSE 0 END) as paid,
                SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'CANCELLED' THEN 1 ELSE 0 END) as cancelled,
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed
            FROM payment_orders WHERE created_at >= ?
        `, [since]);

        return {
            totalOrders: totals?.total ?? 0,
            totalRevenue: totals?.revenue ?? 0,
            totalRefund: totals?.refund ?? 0,
            pendingOrders: totals?.pending ?? 0,
            paidOrders: totals?.paid ?? 0,
            completedOrders: totals?.completed ?? 0,
            cancelledOrders: totals?.cancelled ?? 0,
            failedOrders: totals?.failed ?? 0,
            periodDays: days,
        };
    }
}
