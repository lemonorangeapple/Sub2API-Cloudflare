import type { D1Database, D1Value } from "../types/d1.ts";
import {
    D1PromoCodeRepository,
    type PromoCodeRecord,
    type PromoCodeUsageWithUserRecord,
} from "../repositories/promo-codes.ts";

export class PromoCodeError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "PromoCodeError";
        this.status = status;
        this.code = code;
    }
}

function errNotFound(): PromoCodeError {
    return new PromoCodeError(404, "Promo code not found", "PROMO_CODE_NOT_FOUND");
}

function errBadRequest(msg: string): PromoCodeError {
    return new PromoCodeError(400, msg, "BAD_REQUEST");
}

function generateRandomCode(): string {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let code = "";
    for (let i = 0; i < 16; i++) {
        if (i > 0 && i % 4 === 0) code += "-";
        code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
}

export class D1PromoCodeService {
    private repo: D1PromoCodeRepository;
    constructor(db: D1Database) {
        this.repo = new D1PromoCodeRepository(db);
    }

    async list(params: {
        page: number; pageSize: number; status?: string;
        search?: string; sortBy?: string; sortOrder?: string;
    }): Promise<{ items: PromoCodeRecord[]; total: number }> {
        return this.repo.list(params);
    }

    async getById(id: number): Promise<PromoCodeRecord> {
        const record = await this.repo.getById(id);
        if (!record) throw errNotFound();
        return record;
    }

    async create(input: {
        code?: string; bonusAmount: number; maxUses?: number;
        expiresAt?: string | null; notes?: string | null;
    }): Promise<PromoCodeRecord> {
        const code = (input.code ?? "").trim() !== "" ? input.code!.trim().toUpperCase() : generateRandomCode();
        const existing = await this.repo.getByCode(code);
        if (existing) throw errBadRequest("Promo code already exists");
        return this.repo.create({
            code,
            bonusAmount: input.bonusAmount,
            maxUses: input.maxUses,
            expiresAt: input.expiresAt,
            notes: input.notes,
        });
    }

    async update(id: number, input: {
        code?: string; bonusAmount?: number; maxUses?: number;
        status?: string; expiresAt?: string | null; notes?: string | null;
    }): Promise<PromoCodeRecord> {
        const existing = await this.repo.getById(id);
        if (!existing) throw errNotFound();

        const updates: Record<string, D1Value> = {};
        if (input.code !== undefined) {
            const newCode = input.code.trim().toUpperCase();
            if (newCode === "") throw errBadRequest("Code cannot be empty");
            const dup = await this.repo.getByCode(newCode);
            if (dup && dup.id !== id) throw errBadRequest("Promo code already exists");
            updates.code = newCode;
        }
        if (input.bonusAmount !== undefined) updates.bonus_amount = input.bonusAmount;
        if (input.maxUses !== undefined) updates.max_uses = input.maxUses;
        if (input.status !== undefined) {
            if (!["active", "disabled"].includes(input.status)) {
                throw errBadRequest("Status must be 'active' or 'disabled'");
            }
            updates.status = input.status;
        }
        if (input.expiresAt !== undefined) updates.expires_at = input.expiresAt;
        if (input.notes !== undefined) updates.notes = input.notes;

        const updated = await this.repo.update(id, updates);
        if (!updated) throw errNotFound();
        return updated;
    }

    async delete(id: number): Promise<void> {
        const existing = await this.repo.getById(id);
        if (!existing) throw errNotFound();
        await this.repo.delete(id);
    }

    async listUsages(promoCodeId: number, params: {
        page: number; pageSize: number;
    }): Promise<{ items: PromoCodeUsageWithUserRecord[]; total: number }> {
        const existing = await this.repo.getById(promoCodeId);
        if (!existing) throw errNotFound();
        return this.repo.listUsages(promoCodeId, params);
    }
}
