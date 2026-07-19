import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1SubscriptionRepository } from "../repositories/subscriptions.ts";
import type { RedeemCodeRecord, RedeemCodeWithRelationsRecord } from "../repositories/redeem-codes.ts";
import { D1RedeemCodeRepository } from "../repositories/redeem-codes.ts";
import type { D1Database, D1Value } from "../types/d1.ts";

export class RedeemCodeError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "RedeemCodeError";
        this.status = status;
        this.code = code;
    }
}

export function errNotFound(): RedeemCodeError {
    return new RedeemCodeError(404, "Redeem code not found", "REDEEM_CODE_NOT_FOUND");
}

export function errBadRequest(msg: string): RedeemCodeError {
    return new RedeemCodeError(400, msg, "BAD_REQUEST");
}

export function errConflict(msg: string): RedeemCodeError {
    return new RedeemCodeError(409, msg, "CONFLICT");
}

function nowISO(): string {
    return new Date().toISOString();
}

function generateRandomCode(): string {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const segments: string[] = [];
    for (let s = 0; s < 4; s++) {
        let seg = "";
        for (let i = 0; i < 4; i++) {
            const idx = Math.floor(Math.random() * chars.length);
            seg += chars[idx];
        }
        segments.push(seg);
    }
    return segments.join("-");
}

function resolveExpiresAt(expiresAt?: string | null, expiresInDays?: number | null): string | null {
    if (expiresAt && expiresInDays !== null && expiresInDays !== undefined) {
        throw errBadRequest("expires_at and expires_in_days cannot both be set");
    }
    if (expiresInDays !== null && expiresInDays !== undefined) {
        if (expiresInDays <= 0) throw errBadRequest("expires_in_days must be greater than zero");
        const d = new Date();
        d.setUTCDate(d.getUTCDate() + expiresInDays);
        return d.toISOString();
    }
    if (expiresAt) {
        const exp = new Date(expiresAt);
        if (exp <= new Date()) throw errBadRequest("expires_at must be in the future");
        return exp.toISOString();
    }
    return null;
}

export interface GenerateInput {
    count: number;
    type: string;
    value: number;
    groupId?: number | null;
    validityDays?: number;
    expiresAt?: string | null;
    expiresInDays?: number | null;
}

export interface CreateAndRedeemInput {
    code: string;
    type?: string;
    value: number;
    userId: number;
    groupId?: number | null;
    validityDays?: number;
    notes?: string;
    expiresAt?: string | null;
    expiresInDays?: number | null;
}

export interface BatchUpdateInput {
    ids: number[];
    fields: {
        status?: string;
        expiresAt?: string | null;
        notes?: string | null;
        groupId?: number | null;
    };
}

export class D1RedeemCodeService {
    private repo: D1RedeemCodeRepository;
    private db: D1Database;

    constructor(db: D1Database) {
        this.repo = new D1RedeemCodeRepository(db);
        this.db = db;
    }

    private toJson(r: RedeemCodeWithRelationsRecord): Record<string, unknown> {
        return {
            id: r.id, code: r.code, type: r.type, value: r.value, status: r.status,
            used_by: r.usedBy, used_at: r.usedAt, notes: r.notes,
            created_at: r.createdAt, expires_at: r.expiresAt, validity_days: r.validityDays,
            group_id: r.groupId,
            used_by_name: r.usedByName, used_by_email: r.usedByEmail,
            group_name: r.groupName,
        };
    }

    private toJsonSimple(r: RedeemCodeRecord): Record<string, unknown> {
        return {
            id: r.id, code: r.code, type: r.type, value: r.value, status: r.status,
            used_by: r.usedBy, used_at: r.usedAt, notes: r.notes,
            created_at: r.createdAt, expires_at: r.expiresAt, validity_days: r.validityDays,
            group_id: r.groupId,
        };
    }

    async list(params: {
        page: number; pageSize: number; type?: string; status?: string;
        search?: string; sortBy?: string; sortOrder?: string;
    }): Promise<{ items: Record<string, unknown>[]; total: number }> {
        const result = await this.repo.list(params);
        return { items: result.items.map(r => this.toJson(r)), total: result.total };
    }

    async getById(id: number): Promise<Record<string, unknown>> {
        const code = await this.repo.getById(id);
        if (!code) throw errNotFound();
        return this.toJson(code);
    }

    async generate(input: GenerateInput): Promise<Record<string, unknown>[]> {
        if (input.count < 1 || input.count > 100) throw errBadRequest("count must be between 1 and 100");
        if (!["balance", "concurrency", "subscription", "invitation"].includes(input.type)) {
            throw errBadRequest("type must be one of: balance, concurrency, subscription, invitation");
        }
        const expiresAt = resolveExpiresAt(input.expiresAt, input.expiresInDays);

        if (input.type === "subscription") {
            if (!input.groupId) throw errBadRequest("group_id is required for subscription type");
            const groupExists = await this.repo.getByCode("___check_group___");
        }

        const created: Record<string, unknown>[] = [];
        for (let i = 0; i < input.count; i++) {
            let codeValue = generateRandomCode();
            while (await this.repo.codeExists(codeValue)) {
                codeValue = generateRandomCode();
            }
            const rec = await this.repo.create({
                code: codeValue,
                type: input.type,
                value: input.value,
                expiresAt,
                validityDays: input.type === "subscription" ? (input.validityDays ?? 30) : 30,
                groupId: input.type === "subscription" ? (input.groupId ?? null) : null,
            });
            created.push(this.toJsonSimple(rec));
        }
        return created;
    }

    async createAndRedeem(input: CreateAndRedeemInput): Promise<Record<string, unknown>> {
        if (!input.code || input.code.length < 3 || input.code.length > 128) {
            throw errBadRequest("code must be between 3 and 128 characters");
        }
        if (input.userId < 1) throw errBadRequest("user_id must be greater than 0");
        if (!["balance", "concurrency", "subscription", "invitation"].includes(input.type ?? "balance")) {
            throw errBadRequest("type must be one of: balance, concurrency, subscription, invitation");
        }
        const type = input.type ?? "balance";
        if (type === "subscription") {
            if (!input.groupId) throw errBadRequest("group_id is required for subscription type");
            if (!input.validityDays) throw errBadRequest("validity_days must not be zero for subscription type");
        }

        const userExists = await this.repo.userExists(input.userId);
        if (!userExists) throw errBadRequest("User not found");

        const expiresAt = resolveExpiresAt(input.expiresAt, input.expiresInDays);
        const existing = await this.repo.getByCode(input.code.trim());

        if (existing) {
            if (existing.status === "expired") throw errBadRequest("Redeem code is expired");
            if (existing.status === "used") {
                if (existing.usedBy === input.userId) {
                    return this.toJsonSimple(existing);
                }
                throw errConflict("Redeem code already used by another user");
            }
            if (existing.status === "unused") {
                if (existing.expiresAt && new Date(existing.expiresAt) <= new Date()) {
                    throw errBadRequest("Redeem code is expired");
                }
                const updated = await this.repo.update(existing.id, {
                    status: "used",
                    used_by: input.userId,
                    used_at: nowISO(),
                });
                return this.toJsonSimple(updated!);
            }
        }

        const created = await this.repo.create({
            code: input.code.trim(),
            type,
            value: input.value,
            notes: input.notes ?? null,
            expiresAt,
            validityDays: input.validityDays ?? 30,
            groupId: input.groupId ?? null,
        });

        const redeemed = await this.repo.update(created.id, {
            status: "used",
            used_by: input.userId,
            used_at: nowISO(),
        });

        return this.toJsonSimple(redeemed!);
    }

    async batchUpdate(input: BatchUpdateInput): Promise<{ updated: number }> {
        if (input.ids.length === 0) throw errBadRequest("ids array is required");
        let updated = 0;
        for (const id of input.ids) {
            const existing = await this.repo.getById(id);
            if (!existing) continue;
            const updates: Record<string, D1Value> = {};
            if (input.fields.status !== undefined) updates.status = input.fields.status;
            if (input.fields.expiresAt !== undefined) updates.expires_at = input.fields.expiresAt;
            if (input.fields.notes !== undefined) updates.notes = input.fields.notes;
            if (input.fields.groupId !== undefined) updates.group_id = input.fields.groupId;
            if (Object.keys(updates).length > 0) {
                await this.repo.update(id, updates);
                updated++;
            }
        }
        return { updated };
    }

    async delete(id: number): Promise<void> {
        const code = await this.repo.getById(id);
        if (!code) throw errNotFound();
        if (code.status === "used") throw errBadRequest("Cannot delete a used redeem code");
        await this.repo.delete(id);
    }

    async batchDelete(ids: number[]): Promise<number> {
        let deleted = 0;
        for (const id of ids) {
            try {
                await this.delete(id);
                deleted++;
            } catch {
                // skip codes that can't be deleted
            }
        }
        return deleted;
    }

    async expire(id: number): Promise<Record<string, unknown>> {
        const code = await this.repo.getById(id);
        if (!code) throw errNotFound();
        if (code.status !== "unused") throw errBadRequest("Only unused codes can be expired");
        const updated = await this.repo.update(id, { status: "expired" });
        const full = await this.repo.getById(updated!.id);
        return this.toJson(full!);
    }

    async getStats(): Promise<Record<string, unknown>> {
        return this.repo.getStats();
    }

    async listByUser(userId: number, limit = 25): Promise<Record<string, unknown>[]> {
        const codes = await this.repo.listByUser(userId, limit);
        return codes.map(r => this.toJsonSimple(r));
    }

    async redeem(userId: number, codeStr: string): Promise<Record<string, unknown>> {
        const code = await this.repo.getByCode(codeStr.trim());
        if (!code) throw errBadRequest("Redeem code not found");

        if (code.status !== "unused") {
            if (code.status === "used") throw errBadRequest("Redeem code already used");
            if (code.status === "expired") throw errBadRequest("Redeem code is expired");
            throw errBadRequest(`Redeem code is ${code.status}`);
        }

        if (code.expiresAt && new Date(code.expiresAt) <= new Date()) {
            throw errBadRequest("Redeem code is expired");
        }

        switch (code.type) {
            case "balance":
            case "concurrency":
                break;
            case "subscription":
                if (!code.groupId) throw errBadRequest("Invalid subscription redeem code: missing group_id");
                break;
            default:
                throw errBadRequest(`Unsupported redeem code type: ${code.type}`);
        }

        const userRepo = new D1AuthUserRepository(this.db);
        const user = await userRepo.findById(userId);
        if (!user) throw errBadRequest("User not found");

        const now = nowISO();

        const marked = await this.repo.markUsed(code.id, userId, now);
        if (!marked) throw errBadRequest("Redeem code was already used by another user");

        try {
            if (code.type === "balance") {
                const newBalance = user.balance + code.value;
                await this.db.prepare(
                    "UPDATE users SET balance = ?, updated_at = ? WHERE id = ?"
                ).bind(newBalance, now, userId).run();
            } else if (code.type === "concurrency") {
                const newConcurrency = Math.max(0, user.concurrency + code.value);
                await this.db.prepare(
                    "UPDATE users SET concurrency = ?, updated_at = ? WHERE id = ?"
                ).bind(newConcurrency, now, userId).run();
            } else if (code.type === "subscription" && code.groupId) {
                const subRepo = new D1SubscriptionRepository(this.db);
                const validityDays = code.validityDays > 0 ? code.validityDays : 30;
                await subRepo.create({
                    user_id: userId,
                    group_id: code.groupId,
                    starts_at: now,
                    expires_at: new Date(Date.now() + validityDays * 86400000).toISOString(),
                    status: "active",
                    assigned_at: now,
                    assigned_by: null,
                    notes: `Redeemed via code ${code.code}`,
                    daily_window_start: now,
                    weekly_window_start: now,
                    monthly_window_start: now,
                    daily_usage_usd: 0,
                    weekly_usage_usd: 0,
                    monthly_usage_usd: 0,
                });
            }
        } catch {
            await this.db.prepare(
                "UPDATE redeem_codes SET status = 'unused', used_by = NULL, used_at = NULL WHERE id = ?"
            ).bind(code.id).run();
            throw errBadRequest("Failed to apply redeem code benefits");
        }

        const updated = await this.repo.getByCode(code.code);
        return this.toJsonSimple(updated ?? code);
    }

    async export(params: { type?: string; status?: string; search?: string; sortBy?: string; sortOrder?: string }): Promise<string> {
        const codes = await this.repo.export(params);
        const header = "id,code,type,value,status,used_by,used_by_email,used_at,expires_at,created_at";
        const rows = codes.map(r =>
            [r.id, r.code, r.type, r.value, r.status, r.usedBy ?? "", r.usedByEmail ?? "", r.usedAt ?? "", r.expiresAt ?? "", r.createdAt].join(",")
        );
        return [header, ...rows].join("\n");
    }
}
