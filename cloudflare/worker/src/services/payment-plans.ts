import type { D1Database, D1Value } from "../types/d1.ts";
import { D1SubscriptionPlanRepository, type SubscriptionPlanRecord } from "../repositories/payment-plans.ts";

export class PaymentPlanError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "PaymentPlanError";
        this.status = status;
        this.code = code;
    }
}

function errNotFound(): PaymentPlanError {
    return new PaymentPlanError(404, "Subscription plan not found", "PLAN_NOT_FOUND");
}

function errBadRequest(msg: string): PaymentPlanError {
    return new PaymentPlanError(400, msg, "BAD_REQUEST");
}

export class D1PaymentPlanService {
    private repo: D1SubscriptionPlanRepository;
    constructor(db: D1Database) {
        this.repo = new D1SubscriptionPlanRepository(db);
    }

    async list(): Promise<SubscriptionPlanRecord[]> {
        return this.repo.list();
    }

    async getById(id: number): Promise<SubscriptionPlanRecord> {
        const record = await this.repo.getById(id);
        if (!record) throw errNotFound();
        return record;
    }

    async create(input: {
        groupId: number; name: string; description?: string;
        price: number; originalPrice?: number | null;
        validityDays?: number; validityUnit?: string;
        features?: string; productName?: string;
        forSale?: number; sortOrder?: number;
    }): Promise<SubscriptionPlanRecord> {
        if (!input.name?.trim()) throw errBadRequest("name is required");
        if (typeof input.price !== "number" || input.price < 0) throw errBadRequest("price must be a non-negative number");
        if (!input.groupId) throw errBadRequest("group_id is required");
        return this.repo.create(input);
    }

    async update(id: number, input: {
        groupId?: number; name?: string; description?: string;
        price?: number; originalPrice?: number | null;
        validityDays?: number; validityUnit?: string;
        features?: string; productName?: string;
        forSale?: number; sortOrder?: number;
    }): Promise<SubscriptionPlanRecord> {
        const existing = await this.repo.getById(id);
        if (!existing) throw errNotFound();

        const updates: Record<string, D1Value> = {};
        if (input.groupId !== undefined) updates.group_id = input.groupId;
        if (input.name !== undefined) {
            if (!input.name.trim()) throw errBadRequest("name cannot be empty");
            updates.name = input.name;
        }
        if (input.description !== undefined) updates.description = input.description;
        if (input.price !== undefined) {
            if (input.price < 0) throw errBadRequest("price must be non-negative");
            updates.price = input.price;
        }
        if (input.originalPrice !== undefined) updates.original_price = input.originalPrice;
        if (input.validityDays !== undefined) updates.validity_days = input.validityDays;
        if (input.validityUnit !== undefined) updates.validity_unit = input.validityUnit;
        if (input.features !== undefined) updates.features = input.features;
        if (input.productName !== undefined) updates.product_name = input.productName;
        if (input.forSale !== undefined) updates.for_sale = input.forSale;
        if (input.sortOrder !== undefined) updates.sort_order = input.sortOrder;

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
