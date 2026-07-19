import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface PromoCodeRecord {
    id: number;
    code: string;
    bonusAmount: number;
    maxUses: number;
    usedCount: number;
    status: string;
    expiresAt: string | null;
    notes: string | null;
    createdAt: string;
    updatedAt: string;
}

export interface PromoCodeUsageRecord {
    id: number;
    promoCodeId: number;
    userId: number;
    bonusAmount: number;
    usedAt: string;
}

export interface PromoCodeUsageWithUserRecord extends PromoCodeUsageRecord {
    username: string | null;
    email: string | null;
}

interface PromoCodeRow {
    id: number;
    code: string;
    bonus_amount: number;
    max_uses: number;
    used_count: number;
    status: string;
    expires_at: string | null;
    notes: string | null;
    created_at: string;
    updated_at: string;
}

interface PromoCodeUsageRow {
    id: number;
    promo_code_id: number;
    user_id: number;
    bonus_amount: number;
    used_at: string;
}

interface PromoCodeUsageWithUserRow extends PromoCodeUsageRow {
    username: string | null;
    email: string | null;
}

function rowToRecord(row: PromoCodeRow): PromoCodeRecord {
    return {
        id: row.id,
        code: row.code,
        bonusAmount: row.bonus_amount,
        maxUses: row.max_uses,
        usedCount: row.used_count,
        status: row.status,
        expiresAt: row.expires_at,
        notes: row.notes,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

function usageRowToRecord(row: PromoCodeUsageRow): PromoCodeUsageRecord {
    return {
        id: row.id,
        promoCodeId: row.promo_code_id,
        userId: row.user_id,
        bonusAmount: row.bonus_amount,
        usedAt: row.used_at,
    };
}

function usageRowToRecordWithUser(row: PromoCodeUsageWithUserRow): PromoCodeUsageWithUserRecord {
    return {
        ...usageRowToRecord(row),
        username: row.username,
        email: row.email,
    };
}

function nowISO(): string {
    return new Date().toISOString();
}

export class D1PromoCodeRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: { code: string; bonusAmount: number; maxUses?: number; expiresAt?: string | null; notes?: string | null }): Promise<PromoCodeRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO promo_codes (code, bonus_amount, max_uses, used_count, status, expires_at, notes, created_at, updated_at) VALUES (?, ?, ?, 0, 'active', ?, ?, ?, ?) RETURNING *`;
        const vals: D1Value[] = [input.code, input.bonusAmount, input.maxUses ?? 0, input.expiresAt ?? null, input.notes ?? null, ts, ts];
        const row = await firstRow<PromoCodeRow>(this.db, sql, vals);
        return rowToRecord(row!);
    }

    async getById(id: number): Promise<PromoCodeRecord | null> {
        const row = await firstRow<PromoCodeRow>(this.db, `SELECT * FROM promo_codes WHERE id = ?`, [id]);
        return row ? rowToRecord(row) : null;
    }

    async getByCode(code: string): Promise<PromoCodeRecord | null> {
        const row = await firstRow<PromoCodeRow>(this.db, `SELECT * FROM promo_codes WHERE LOWER(code) = LOWER(?)`, [code]);
        return row ? rowToRecord(row) : null;
    }

    async update(id: number, input: Record<string, D1Value>): Promise<PromoCodeRecord | null> {
        const setClauses: string[] = [];
        const values: D1Value[] = [];
        for (const [key, value] of Object.entries(input)) {
            if (key === "id" || key === "created_at") continue;
            setClauses.push(`${key} = ?`);
            values.push(value ?? null);
        }
        if (setClauses.length === 0) return this.getById(id);
        setClauses.push("updated_at = ?");
        values.push(nowISO());
        values.push(id);
        const sql = `UPDATE promo_codes SET ${setClauses.join(", ")} WHERE id = ? RETURNING *`;
        const row = await firstRow<PromoCodeRow>(this.db, sql, values);
        return row ? rowToRecord(row) : null;
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(this.db, `DELETE FROM promo_codes WHERE id = ?`, [id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }

    async incrementUsedCount(id: number): Promise<void> {
        await runStatement(this.db, `UPDATE promo_codes SET used_count = used_count + 1, updated_at = ? WHERE id = ?`, [nowISO(), id]);
    }

    async list(params: {
        page: number; pageSize: number; status?: string; search?: string;
        sortBy?: string; sortOrder?: string;
    }): Promise<{ items: PromoCodeRecord[]; total: number }> {
        const where: string[] = [];
        const values: D1Value[] = [];

        if (params.status) { where.push("status = ?"); values.push(params.status); }
        if (params.search) { where.push("code LIKE ?"); values.push(`%${params.search}%`); }

        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
        const sortBy = params.sortBy ?? "created_at";
        const sortOrder = params.sortOrder ?? "desc";
        const safeSortBy = ["id", "code", "bonus_amount", "max_uses", "used_count", "status", "created_at", "expires_at"].includes(sortBy) ? sortBy : "created_at";
        const safeSortOrder = sortOrder === "asc" ? "ASC" : "DESC";

        const countRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM promo_codes ${whereClause}`, values);
        const total = countRow?.c ?? 0;

        const offset = (params.page - 1) * params.pageSize;
        const rows = await allRows<PromoCodeRow>(this.db, `
            SELECT * FROM promo_codes ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}, id DESC
            LIMIT ? OFFSET ?
        `, [...values, params.pageSize, offset]);

        return { items: rows.map(rowToRecord), total };
    }

    async createUsage(input: { promoCodeId: number; userId: number; bonusAmount: number }): Promise<PromoCodeUsageRecord> {
        const sql = `INSERT INTO promo_code_usages (promo_code_id, user_id, bonus_amount, used_at) VALUES (?, ?, ?, ?) RETURNING *`;
        const vals: D1Value[] = [input.promoCodeId, input.userId, input.bonusAmount, nowISO()];
        const row = await firstRow<PromoCodeUsageRow>(this.db, sql, vals);
        return usageRowToRecord(row!);
    }

    async getUsageByPromoCodeAndUser(promoCodeId: number, userId: number): Promise<PromoCodeUsageRecord | null> {
        const row = await firstRow<PromoCodeUsageRow>(this.db, `SELECT * FROM promo_code_usages WHERE promo_code_id = ? AND user_id = ? LIMIT 1`, [promoCodeId, userId]);
        return row ? usageRowToRecord(row) : null;
    }

    async listUsages(promoCodeId: number, params: { page: number; pageSize: number }): Promise<{ items: PromoCodeUsageWithUserRecord[]; total: number }> {
        const countRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM promo_code_usages WHERE promo_code_id = ?`, [promoCodeId]);
        const total = countRow?.c ?? 0;

        const offset = (params.page - 1) * params.pageSize;
        const rows = await allRows<PromoCodeUsageWithUserRow>(this.db, `
            SELECT pcu.id, pcu.promo_code_id, pcu.user_id, pcu.bonus_amount, pcu.used_at,
                   u.username, u.email
            FROM promo_code_usages pcu
            LEFT JOIN users u ON u.id = pcu.user_id
            WHERE pcu.promo_code_id = ?
            ORDER BY pcu.id DESC
            LIMIT ? OFFSET ?
        `, [promoCodeId, params.pageSize, offset]);

        return { items: rows.map(usageRowToRecordWithUser), total };
    }
}
