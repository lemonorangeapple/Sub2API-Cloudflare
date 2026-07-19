import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface RedeemCodeRecord {
    id: number;
    code: string;
    type: string;
    value: number;
    status: string;
    usedAt: string | null;
    notes: string | null;
    createdAt: string;
    expiresAt: string | null;
    validityDays: number;
    groupId: number | null;
    usedBy: number | null;
}

export interface RedeemCodeWithRelationsRecord extends RedeemCodeRecord {
    usedByName: string | null;
    usedByEmail: string | null;
    groupName: string | null;
}

interface RedeemCodeRow {
    id: number;
    code: string;
    type: string;
    value: number;
    status: string;
    used_at: string | null;
    notes: string | null;
    created_at: string;
    expires_at: string | null;
    validity_days: number;
    group_id: number | null;
    used_by: number | null;
}

interface RedeemCodeWithRelationsRow extends RedeemCodeRow {
    used_by_name: string | null;
    used_by_email: string | null;
    group_name: string | null;
}

function rowToRecord(row: RedeemCodeRow): RedeemCodeRecord {
    return {
        id: row.id,
        code: row.code,
        type: row.type,
        value: row.value,
        status: row.status,
        usedAt: row.used_at,
        notes: row.notes,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        validityDays: row.validity_days,
        groupId: row.group_id,
        usedBy: row.used_by,
    };
}

function rowToRecordWithRelations(row: RedeemCodeWithRelationsRow): RedeemCodeWithRelationsRecord {
    return {
        ...rowToRecord(row),
        usedByName: row.used_by_name,
        usedByEmail: row.used_by_email,
        groupName: row.group_name,
    };
}

function nowISO(): string {
    return new Date().toISOString();
}

const WITH_RELATIONS_SELECT = `
    rc.id, rc.code, rc.type, rc.value, rc.status, rc.used_at, rc.notes,
    rc.created_at, rc.expires_at, rc.validity_days, rc.group_id, rc.used_by,
    u.username as used_by_name,
    u.email as used_by_email,
    g.name as group_name
`;

const WITH_RELATIONS_JOIN = `
    LEFT JOIN users u ON u.id = rc.used_by
    LEFT JOIN groups g ON g.id = rc.group_id
`;

export class D1RedeemCodeRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: { code: string; type: string; value: number; notes?: string | null; expiresAt?: string | null; validityDays?: number; groupId?: number | null }): Promise<RedeemCodeRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO redeem_codes (code, type, value, status, notes, created_at, expires_at, validity_days, group_id) VALUES (?, ?, ?, 'unused', ?, ?, ?, ?, ?) RETURNING *`;
        const vals: D1Value[] = [input.code, input.type, input.value, input.notes ?? null, ts, input.expiresAt ?? null, input.validityDays ?? 30, input.groupId ?? null];
        const row = await firstRow<RedeemCodeRow>(this.db, sql, vals);
        return rowToRecord(row!);
    }

    async batchCreate(inputs: { code: string; type: string; value: number; notes?: string | null; expiresAt?: string | null; validityDays?: number; groupId?: number | null }[]): Promise<RedeemCodeRecord[]> {
        const ts = nowISO();
        const results: RedeemCodeRecord[] = [];
        for (const input of inputs) {
            const sql = `INSERT INTO redeem_codes (code, type, value, status, notes, created_at, expires_at, validity_days, group_id) VALUES (?, ?, ?, 'unused', ?, ?, ?, ?, ?) RETURNING *`;
            const vals: D1Value[] = [input.code, input.type, input.value, input.notes ?? null, ts, input.expiresAt ?? null, input.validityDays ?? 30, input.groupId ?? null];
            const row = await firstRow<RedeemCodeRow>(this.db, sql, vals);
            results.push(rowToRecord(row!));
        }
        return results;
    }

    async getById(id: number): Promise<RedeemCodeWithRelationsRecord | null> {
        const sql = `SELECT ${WITH_RELATIONS_SELECT} FROM redeem_codes rc ${WITH_RELATIONS_JOIN} WHERE rc.id = ?`;
        const row = await firstRow<RedeemCodeWithRelationsRow>(this.db, sql, [id]);
        return row ? rowToRecordWithRelations(row) : null;
    }

    async getByCode(code: string): Promise<RedeemCodeRecord | null> {
        const row = await firstRow<RedeemCodeRow>(this.db, `SELECT * FROM redeem_codes WHERE code = ?`, [code]);
        return row ? rowToRecord(row) : null;
    }

    async update(id: number, input: Record<string, D1Value>): Promise<RedeemCodeRecord | null> {
        const setClauses: string[] = [];
        const values: D1Value[] = [];
        for (const [key, value] of Object.entries(input)) {
            if (key === "id" || key === "created_at") continue;
            setClauses.push(`${key} = ?`);
            values.push(value ?? null);
        }
        values.push(id);
        const sql = `UPDATE redeem_codes SET ${setClauses.join(", ")} WHERE id = ? RETURNING *`;
        const row = await firstRow<RedeemCodeRow>(this.db, sql, values);
        return row ? rowToRecord(row) : null;
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(this.db, `DELETE FROM redeem_codes WHERE id = ?`, [id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }

    async batchDelete(ids: number[]): Promise<number> {
        let deleted = 0;
        for (const id of ids) {
            if (await this.delete(id)) deleted++;
        }
        return deleted;
    }

    async list(params: {
        page: number; pageSize: number; type?: string; status?: string;
        search?: string; sortBy?: string; sortOrder?: string;
    }): Promise<{ items: RedeemCodeWithRelationsRecord[]; total: number }> {
        const where: string[] = [];
        const values: D1Value[] = [];

        if (params.type) { where.push("rc.type = ?"); values.push(params.type); }
        if (params.status) { where.push("rc.status = ?"); values.push(params.status); }
        if (params.search) { where.push("rc.code LIKE ?"); values.push(`%${params.search}%`); }

        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
        const sortBy = params.sortBy ?? "id";
        const sortOrder = params.sortOrder ?? "desc";
        const safeSortBy = ["id", "code", "type", "value", "status", "created_at", "expires_at"].includes(sortBy) ? `rc.${sortBy}` : "rc.id";
        const safeSortOrder = sortOrder === "asc" ? "ASC" : "DESC";

        const countRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM redeem_codes rc ${whereClause}`, values);
        const total = countRow?.c ?? 0;

        const offset = (params.page - 1) * params.pageSize;
        const rows = await allRows<RedeemCodeWithRelationsRow>(this.db, `
            SELECT ${WITH_RELATIONS_SELECT} FROM redeem_codes rc
            ${WITH_RELATIONS_JOIN}
            ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `, [...values, params.pageSize, offset]);

        return { items: rows.map(rowToRecordWithRelations), total };
    }

    async getStats(): Promise<{ totalCodes: number; activeCodes: number; usedCodes: number; expiredCodes: number; byType: Record<string, number> }> {
        const totalRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM redeem_codes`);
        const unusedRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM redeem_codes WHERE status = 'unused'`);
        const usedRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM redeem_codes WHERE status = 'used'`);
        const expiredRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM redeem_codes WHERE status = 'expired'`);
        const typeRows = await allRows<{ type: string; c: number }>(this.db, `SELECT type, COUNT(*) as c FROM redeem_codes GROUP BY type`);

        const byType: Record<string, number> = {};
        for (const row of typeRows) {
            byType[row.type] = row.c;
        }

        return {
            totalCodes: totalRow?.c ?? 0,
            activeCodes: unusedRow?.c ?? 0,
            usedCodes: usedRow?.c ?? 0,
            expiredCodes: expiredRow?.c ?? 0,
            byType,
        };
    }

    async codeExists(code: string): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM redeem_codes WHERE code = ?`, [code]);
        return row !== null && row.c > 0;
    }

    async listByUser(userId: number, limit: number): Promise<RedeemCodeRecord[]> {
        const rows = await allRows<RedeemCodeRow>(this.db, `
            SELECT * FROM redeem_codes WHERE used_by = ? ORDER BY used_at DESC, created_at DESC LIMIT ?
        `, [userId, limit]);
        return rows.map(rowToRecord);
    }

    async markUsed(id: number, userId: number, usedAt: string): Promise<boolean> {
        const result = await runStatement(this.db,
            `UPDATE redeem_codes SET status = 'used', used_by = ?, used_at = ? WHERE id = ? AND status = 'unused'`,
            [userId, usedAt, id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async userExists(id: number): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM users WHERE id = ?`, [id]);
        return row !== null && row.c > 0;
    }

    async export(params: { type?: string; status?: string; search?: string; sortBy?: string; sortOrder?: string }): Promise<RedeemCodeWithRelationsRecord[]> {
        const where: string[] = [];
        const values: D1Value[] = [];

        if (params.type) { where.push("rc.type = ?"); values.push(params.type); }
        if (params.status) { where.push("rc.status = ?"); values.push(params.status); }
        if (params.search) { where.push("rc.code LIKE ?"); values.push(`%${params.search}%`); }

        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
        const sortBy = params.sortBy ?? "id";
        const sortOrder = params.sortOrder ?? "desc";
        const safeSortBy = ["id", "code", "type", "value", "status", "created_at", "expires_at"].includes(sortBy) ? `rc.${sortBy}` : "rc.id";
        const safeSortOrder = sortOrder === "asc" ? "ASC" : "DESC";

        const rows = await allRows<RedeemCodeWithRelationsRow>(this.db, `
            SELECT ${WITH_RELATIONS_SELECT} FROM redeem_codes rc
            ${WITH_RELATIONS_JOIN}
            ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT 10000
        `, values);
        return rows.map(rowToRecordWithRelations);
    }
}
