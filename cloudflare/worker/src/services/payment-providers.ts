import type { D1Database, D1Value } from "../types/d1.ts";
import { D1PaymentProviderRepository, type PaymentProviderRecord } from "../repositories/payment-providers.ts";

export class PaymentProviderError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "PaymentProviderError";
        this.status = status;
        this.code = code;
    }
}

function errNotFound(): PaymentProviderError {
    return new PaymentProviderError(404, "Payment provider not found", "PROVIDER_NOT_FOUND");
}

function errBadRequest(msg: string): PaymentProviderError {
    return new PaymentProviderError(400, msg, "BAD_REQUEST");
}

export class D1PaymentProviderService {
    private repo: D1PaymentProviderRepository;
    constructor(db: D1Database) {
        this.repo = new D1PaymentProviderRepository(db);
    }

    async list(): Promise<PaymentProviderRecord[]> {
        return this.repo.list();
    }

    async getById(id: number): Promise<PaymentProviderRecord> {
        const record = await this.repo.getById(id);
        if (!record) throw errNotFound();
        return record;
    }

    async create(input: {
        providerKey: string; name?: string; config: string;
        supportedTypes?: string; enabled?: number; paymentMode?: string;
        sortOrder?: number; limits?: string; refundEnabled?: number; allowUserRefund?: number;
    }): Promise<PaymentProviderRecord> {
        if (!input.providerKey?.trim()) throw errBadRequest("provider_key is required");
        if (!input.config?.trim()) throw errBadRequest("config is required");
        return this.repo.create(input);
    }

    async update(id: number, input: {
        providerKey?: string; name?: string; config?: string;
        supportedTypes?: string; enabled?: number; paymentMode?: string;
        sortOrder?: number; limits?: string; refundEnabled?: number; allowUserRefund?: number;
    }): Promise<PaymentProviderRecord> {
        const existing = await this.repo.getById(id);
        if (!existing) throw errNotFound();

        const updates: Record<string, D1Value> = {};
        if (input.providerKey !== undefined) {
            if (!input.providerKey.trim()) throw errBadRequest("provider_key cannot be empty");
            updates.provider_key = input.providerKey;
        }
        if (input.name !== undefined) updates.name = input.name;
        if (input.config !== undefined) {
            if (!input.config.trim()) throw errBadRequest("config cannot be empty");
            updates.config = input.config;
        }
        if (input.supportedTypes !== undefined) updates.supported_types = input.supportedTypes;
        if (input.enabled !== undefined) updates.enabled = input.enabled;
        if (input.paymentMode !== undefined) updates.payment_mode = input.paymentMode;
        if (input.sortOrder !== undefined) updates.sort_order = input.sortOrder;
        if (input.limits !== undefined) updates.limits = input.limits;
        if (input.refundEnabled !== undefined) updates.refund_enabled = input.refundEnabled;
        if (input.allowUserRefund !== undefined) updates.allow_user_refund = input.allowUserRefund;

        const updated = await this.repo.update(id, updates);
        if (!updated) throw errNotFound();
        return updated;
    }

    async delete(id: number): Promise<void> {
        const existing = await this.repo.getById(id);
        if (!existing) throw errNotFound();
        await this.repo.delete(id);
    }
}
