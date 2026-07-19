import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface PaymentOrderRecord {
    id: number;
    userId: number;
    userEmail: string;
    userName: string;
    userNotes: string | null;
    amount: number;
    payAmount: number;
    feeRate: number;
    rechargeCode: string;
    outTradeNo: string;
    paymentType: string;
    paymentTradeNo: string;
    payUrl: string | null;
    qrCode: string | null;
    qrCodeImg: string | null;
    orderType: string;
    planId: number | null;
    subscriptionGroupId: number | null;
    subscriptionDays: number | null;
    providerInstanceId: string | null;
    providerKey: string | null;
    providerSnapshot: string | null;
    status: string;
    refundAmount: number;
    refundReason: string | null;
    refundAt: string | null;
    forceRefund: number;
    refundRequestedAt: string | null;
    refundRequestReason: string | null;
    refundRequestedBy: string | null;
    expiresAt: string;
    paidAt: string | null;
    completedAt: string | null;
    failedAt: string | null;
    failedReason: string | null;
    clientIp: string;
    srcHost: string;
    srcUrl: string | null;
    createdAt: string;
    updatedAt: string;
}

interface PaymentOrderRow {
    id: number;
    user_id: number;
    user_email: string;
    user_name: string;
    user_notes: string | null;
    amount: number;
    pay_amount: number;
    fee_rate: number;
    recharge_code: string;
    out_trade_no: string;
    payment_type: string;
    payment_trade_no: string;
    pay_url: string | null;
    qr_code: string | null;
    qr_code_img: string | null;
    order_type: string;
    plan_id: number | null;
    subscription_group_id: number | null;
    subscription_days: number | null;
    provider_instance_id: string | null;
    provider_key: string | null;
    provider_snapshot: string | null;
    status: string;
    refund_amount: number;
    refund_reason: string | null;
    refund_at: string | null;
    force_refund: number;
    refund_requested_at: string | null;
    refund_request_reason: string | null;
    refund_requested_by: string | null;
    expires_at: string;
    paid_at: string | null;
    completed_at: string | null;
    failed_at: string | null;
    failed_reason: string | null;
    client_ip: string;
    src_host: string;
    src_url: string | null;
    created_at: string;
    updated_at: string;
}

function rowToRecord(row: PaymentOrderRow): PaymentOrderRecord {
    return {
        id: row.id,
        userId: row.user_id,
        userEmail: row.user_email,
        userName: row.user_name,
        userNotes: row.user_notes,
        amount: row.amount,
        payAmount: row.pay_amount,
        feeRate: row.fee_rate,
        rechargeCode: row.recharge_code,
        outTradeNo: row.out_trade_no,
        paymentType: row.payment_type,
        paymentTradeNo: row.payment_trade_no,
        payUrl: row.pay_url,
        qrCode: row.qr_code,
        qrCodeImg: row.qr_code_img,
        orderType: row.order_type,
        planId: row.plan_id,
        subscriptionGroupId: row.subscription_group_id,
        subscriptionDays: row.subscription_days,
        providerInstanceId: row.provider_instance_id,
        providerKey: row.provider_key,
        providerSnapshot: row.provider_snapshot,
        status: row.status,
        refundAmount: row.refund_amount,
        refundReason: row.refund_reason,
        refundAt: row.refund_at,
        forceRefund: row.force_refund,
        refundRequestedAt: row.refund_requested_at,
        refundRequestReason: row.refund_request_reason,
        refundRequestedBy: row.refund_requested_by,
        expiresAt: row.expires_at,
        paidAt: row.paid_at,
        completedAt: row.completed_at,
        failedAt: row.failed_at,
        failedReason: row.failed_reason,
        clientIp: row.client_ip,
        srcHost: row.src_host,
        srcUrl: row.src_url,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

export interface PaymentAuditLogRecord {
    id: number;
    orderId: string;
    action: string;
    detail: string;
    operator: string;
    createdAt: string;
}

interface PaymentAuditLogRow {
    id: number;
    order_id: string;
    action: string;
    detail: string;
    operator: string;
    created_at: string;
}

function auditRowToRecord(row: PaymentAuditLogRow): PaymentAuditLogRecord {
    return {
        id: row.id,
        orderId: row.order_id,
        action: row.action,
        detail: row.detail,
        operator: row.operator,
        createdAt: row.created_at,
    };
}

function nowISO(): string {
    return new Date().toISOString();
}

export class D1PaymentOrderRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: {
        userId: number; userEmail: string; userName: string; userNotes?: string | null;
        amount: number; payAmount: number; feeRate: number;
        outTradeNo: string; paymentType: string;
        orderType: string; planId?: number | null;
        subscriptionGroupId?: number | null; subscriptionDays?: number | null;
        providerInstanceId?: string | null; providerKey?: string | null;
        providerSnapshot?: string | null;
        payUrl?: string | null; qrCode?: string | null;
        clientIp: string; srcHost: string; srcUrl?: string | null;
        expiresAt: string;
    }): Promise<PaymentOrderRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO payment_orders (user_id, user_email, user_name, user_notes, amount, pay_amount, fee_rate, recharge_code, out_trade_no, payment_type, payment_trade_no, pay_url, qr_code, order_type, plan_id, subscription_group_id, subscription_days, provider_instance_id, provider_key, provider_snapshot, status, client_ip, src_host, src_url, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`;
        const vals: D1Value[] = [
            input.userId, input.userEmail, input.userName, input.userNotes ?? null,
            input.amount, input.payAmount, input.feeRate, "",
            input.outTradeNo, input.paymentType, "", input.payUrl ?? null, input.qrCode ?? null,
            input.orderType, input.planId ?? null, input.subscriptionGroupId ?? null,
            input.subscriptionDays ?? null, input.providerInstanceId ?? null,
            input.providerKey ?? null, input.providerSnapshot ?? null,
            "PENDING", input.clientIp, input.srcHost, input.srcUrl ?? null,
            input.expiresAt, ts, ts,
        ];
        const row = await firstRow<PaymentOrderRow>(this.db, sql, vals);
        return rowToRecord(row!);
    }

    async getByOutTradeNo(outTradeNo: string): Promise<PaymentOrderRecord | null> {
        const row = await firstRow<PaymentOrderRow>(this.db, `SELECT * FROM payment_orders WHERE out_trade_no = ?`, [outTradeNo]);
        return row ? rowToRecord(row) : null;
    }

    async countPendingByUserId(userId: number): Promise<number> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM payment_orders WHERE user_id = ? AND status = 'PENDING'`, [userId]);
        return row?.c ?? 0;
    }

    async writeAuditLog(orderId: string, action: string, detail: string = "", operator: string = "system"): Promise<void> {
        await runStatement(this.db, `INSERT INTO payment_audit_logs (order_id, action, detail, operator, created_at) VALUES (?, ?, ?, ?, ?)`, [orderId, action, detail, operator, nowISO()]);
    }

    async getById(id: number): Promise<PaymentOrderRecord | null> {
        const row = await firstRow<PaymentOrderRow>(this.db, `SELECT * FROM payment_orders WHERE id = ?`, [id]);
        return row ? rowToRecord(row) : null;
    }

    async list(params: {
        page: number; pageSize: number;
        userId?: number; status?: string; orderType?: string;
        paymentType?: string; keyword?: string;
    }): Promise<{ items: PaymentOrderRecord[]; total: number }> {
        const where: string[] = [];
        const values: D1Value[] = [];

        if (params.userId) { where.push("user_id = ?"); values.push(params.userId); }
        if (params.status) { where.push("status = ?"); values.push(params.status); }
        if (params.orderType) { where.push("order_type = ?"); values.push(params.orderType); }
        if (params.paymentType) { where.push("payment_type = ?"); values.push(params.paymentType); }
        if (params.keyword) {
            where.push("(user_email LIKE ? OR user_name LIKE ? OR out_trade_no LIKE ?)");
            const like = `%${params.keyword}%`;
            values.push(like, like, like);
        }

        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

        const countRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM payment_orders ${whereClause}`, values);
        const total = countRow?.c ?? 0;

        const offset = (params.page - 1) * params.pageSize;
        const rows = await allRows<PaymentOrderRow>(this.db, `
            SELECT * FROM payment_orders ${whereClause}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
        `, [...values, params.pageSize, offset]);

        return { items: rows.map(rowToRecord), total };
    }

    async getAuditLogs(orderId: string): Promise<PaymentAuditLogRecord[]> {
        const rows = await allRows<PaymentAuditLogRow>(this.db, `SELECT * FROM payment_audit_logs WHERE order_id = ? ORDER BY id`, [orderId]);
        return rows.map(auditRowToRecord);
    }

    async updateStatus(id: number, status: string, extra?: Record<string, D1Value>): Promise<boolean> {
        const setClauses: string[] = ["status = ?", "updated_at = ?"];
        const values: D1Value[] = [status, nowISO()];
        if (extra) {
            for (const [key, value] of Object.entries(extra)) {
                setClauses.push(`${key} = ?`);
                values.push(value ?? null);
            }
        }
        values.push(id);
        const result = await runStatement(this.db, `UPDATE payment_orders SET ${setClauses.join(", ")} WHERE id = ?`, values);
        return result.success;
    }

    async markPaidIfPending(id: number, tradeNo: string, paidAt: string): Promise<boolean> {
        const result = await runStatement(this.db, `
            UPDATE payment_orders
            SET status = 'PAID', payment_trade_no = ?, paid_at = ?, updated_at = ?
            WHERE id = ? AND status = 'PENDING'
        `, [tradeNo, paidAt, paidAt, id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }
}
