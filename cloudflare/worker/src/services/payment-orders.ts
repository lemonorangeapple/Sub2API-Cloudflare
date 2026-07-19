import type { D1Database } from "../types/d1.ts";
import { D1PaymentOrderRepository, type PaymentOrderRecord, type PaymentAuditLogRecord } from "../repositories/payment-orders.ts";

export class PaymentOrderError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "PaymentOrderError";
        this.status = status;
        this.code = code;
    }
}

function errNotFound(): PaymentOrderError {
    return new PaymentOrderError(404, "Payment order not found", "ORDER_NOT_FOUND");
}

function errBadRequest(msg: string): PaymentOrderError {
    return new PaymentOrderError(400, msg, "BAD_REQUEST");
}

export class D1PaymentOrderService {
    private repo: D1PaymentOrderRepository;
    constructor(db: D1Database) {
        this.repo = new D1PaymentOrderRepository(db);
    }

    async list(params: {
        page: number; pageSize: number;
        userId?: number; status?: string; orderType?: string;
        paymentType?: string; keyword?: string;
    }): Promise<{ items: PaymentOrderRecord[]; total: number }> {
        return this.repo.list(params);
    }

    async getById(id: number): Promise<{ order: PaymentOrderRecord; auditLogs: PaymentAuditLogRecord[] }> {
        const order = await this.repo.getById(id);
        if (!order) throw errNotFound();
        const auditLogs = await this.repo.getAuditLogs(String(id));
        return { order, auditLogs };
    }

    async cancelOrder(id: number): Promise<string> {
        const order = await this.repo.getById(id);
        if (!order) throw errNotFound();
        if (order.status !== "PENDING") throw errBadRequest("Only pending orders can be cancelled");
        await this.repo.updateStatus(id, "CANCELLED", { failed_reason: "Cancelled by admin" });
        return "Order cancelled successfully";
    }

    async retryFulfillment(id: number): Promise<void> {
        const order = await this.repo.getById(id);
        if (!order) throw errNotFound();
        if (order.status !== "PAID") throw errBadRequest("Only paid orders can be retried");
        await this.repo.updateStatus(id, "PROCESSING");
    }
}
