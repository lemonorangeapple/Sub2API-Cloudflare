import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface PaymentProviderRecord {
    id: number;
    providerKey: string;
    name: string;
    config: string;
    supportedTypes: string;
    enabled: number;
    paymentMode: string;
    sortOrder: number;
    limits: string;
    refundEnabled: number;
    allowUserRefund: number;
    createdAt: string;
    updatedAt: string;
}

interface PaymentProviderRow {
    id: number;
    provider_key: string;
    name: string;
    config: string;
    supported_types: string;
    enabled: number;
    payment_mode: string;
    sort_order: number;
    limits: string;
    refund_enabled: number;
    allow_user_refund: number;
    created_at: string;
    updated_at: string;
}

function rowToRecord(row: PaymentProviderRow): PaymentProviderRecord {
    return {
        id: row.id,
        providerKey: row.provider_key,
        name: row.name,
        config: row.config,
        supportedTypes: row.supported_types,
        enabled: row.enabled,
        paymentMode: row.payment_mode,
        sortOrder: row.sort_order,
        limits: row.limits,
        refundEnabled: row.refund_enabled,
        allowUserRefund: row.allow_user_refund,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

function nowISO(): string {
    return new Date().toISOString();
}

export class D1PaymentProviderRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: {
        providerKey: string; name?: string; config: string;
        supportedTypes?: string; enabled?: number; paymentMode?: string;
        sortOrder?: number; limits?: string; refundEnabled?: number; allowUserRefund?: number;
    }): Promise<PaymentProviderRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO payment_provider_instances (provider_key, name, config, supported_types, enabled, payment_mode, sort_order, limits, refund_enabled, allow_user_refund, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`;
        const vals: D1Value[] = [
            input.providerKey, input.name ?? "", input.config, input.supportedTypes ?? "",
            input.enabled ?? 1, input.paymentMode ?? "", input.sortOrder ?? 0,
            input.limits ?? "", input.refundEnabled ?? 0, input.allowUserRefund ?? 0, ts, ts,
        ];
        const row = await firstRow<PaymentProviderRow>(this.db, sql, vals);
        return rowToRecord(row!);
    }

    async getById(id: number): Promise<PaymentProviderRecord | null> {
        const row = await firstRow<PaymentProviderRow>(this.db, `SELECT * FROM payment_provider_instances WHERE id = ?`, [id]);
        return row ? rowToRecord(row) : null;
    }

    async list(): Promise<PaymentProviderRecord[]> {
        const rows = await allRows<PaymentProviderRow>(this.db, `SELECT * FROM payment_provider_instances ORDER BY sort_order, id`, []);
        return rows.map(rowToRecord);
    }

    async update(id: number, input: Record<string, D1Value>): Promise<PaymentProviderRecord | null> {
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
        const sql = `UPDATE payment_provider_instances SET ${setClauses.join(", ")} WHERE id = ? RETURNING *`;
        const row = await firstRow<PaymentProviderRow>(this.db, sql, values);
        return row ? rowToRecord(row) : null;
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(this.db, `DELETE FROM payment_provider_instances WHERE id = ?`, [id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }
}
