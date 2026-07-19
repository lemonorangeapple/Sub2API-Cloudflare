import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface SubscriptionPlanRecord {
    id: number;
    groupId: number;
    name: string;
    description: string;
    price: number;
    originalPrice: number | null;
    validityDays: number;
    validityUnit: string;
    features: string;
    productName: string;
    forSale: number;
    sortOrder: number;
    createdAt: string;
    updatedAt: string;
}

interface SubscriptionPlanRow {
    id: number;
    group_id: number;
    name: string;
    description: string;
    price: number;
    original_price: number | null;
    validity_days: number;
    validity_unit: string;
    features: string;
    product_name: string;
    for_sale: number;
    sort_order: number;
    created_at: string;
    updated_at: string;
}

function rowToRecord(row: SubscriptionPlanRow): SubscriptionPlanRecord {
    return {
        id: row.id,
        groupId: row.group_id,
        name: row.name,
        description: row.description,
        price: row.price,
        originalPrice: row.original_price,
        validityDays: row.validity_days,
        validityUnit: row.validity_unit,
        features: row.features,
        productName: row.product_name,
        forSale: row.for_sale,
        sortOrder: row.sort_order,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

function nowISO(): string {
    return new Date().toISOString();
}

export class D1SubscriptionPlanRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: {
        groupId: number; name: string; description?: string;
        price: number; originalPrice?: number | null;
        validityDays?: number; validityUnit?: string;
        features?: string; productName?: string;
        forSale?: number; sortOrder?: number;
    }): Promise<SubscriptionPlanRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO subscription_plans (group_id, name, description, price, original_price, validity_days, validity_unit, features, product_name, for_sale, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`;
        const vals: D1Value[] = [
            input.groupId, input.name, input.description ?? "", input.price,
            input.originalPrice ?? null, input.validityDays ?? 30, input.validityUnit ?? "day",
            input.features ?? "", input.productName ?? "", input.forSale ?? 1,
            input.sortOrder ?? 0, ts, ts,
        ];
        const row = await firstRow<SubscriptionPlanRow>(this.db, sql, vals);
        return rowToRecord(row!);
    }

    async getById(id: number): Promise<SubscriptionPlanRecord | null> {
        const row = await firstRow<SubscriptionPlanRow>(this.db, `SELECT * FROM subscription_plans WHERE id = ?`, [id]);
        return row ? rowToRecord(row) : null;
    }

    async list(): Promise<SubscriptionPlanRecord[]> {
        const rows = await allRows<SubscriptionPlanRow>(this.db, `SELECT * FROM subscription_plans ORDER BY sort_order, id`, []);
        return rows.map(rowToRecord);
    }

    async update(id: number, input: Record<string, D1Value>): Promise<SubscriptionPlanRecord | null> {
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
        const sql = `UPDATE subscription_plans SET ${setClauses.join(", ")} WHERE id = ? RETURNING *`;
        const row = await firstRow<SubscriptionPlanRow>(this.db, sql, values);
        return row ? rowToRecord(row) : null;
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(this.db, `DELETE FROM subscription_plans WHERE id = ?`, [id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }
}
