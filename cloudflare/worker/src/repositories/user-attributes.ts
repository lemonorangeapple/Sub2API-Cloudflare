import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement, runBatchTransaction } from "./d1.ts";

export interface UserAttributeDefinitionRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    deletedAt: string | null;
    key: string;
    name: string;
    description: string;
    type: string;
    options: string;
    required: boolean;
    validation: string;
    placeholder: string;
    displayOrder: number;
    enabled: boolean;
}

export interface UserAttributeValueRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    value: string;
    userId: number;
    attributeId: number;
}

interface DefRow {
    id: number;
    created_at: string;
    updated_at: string;
    deleted_at: string | null;
    key: string;
    name: string;
    description: string;
    type: string;
    options: string;
    required: number;
    validation: string;
    placeholder: string;
    display_order: number;
    enabled: number;
}

interface ValRow {
    id: number;
    created_at: string;
    updated_at: string;
    value: string;
    user_id: number;
    attribute_id: number;
}

function defRowToRecord(row: DefRow): UserAttributeDefinitionRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        deletedAt: row.deleted_at,
        key: row.key,
        name: row.name,
        description: row.description,
        type: row.type,
        options: row.options,
        required: row.required === 1,
        validation: row.validation,
        placeholder: row.placeholder,
        displayOrder: row.display_order,
        enabled: row.enabled === 1
    };
}

function valRowToRecord(row: ValRow): UserAttributeValueRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        value: row.value,
        userId: row.user_id,
        attributeId: row.attribute_id
    };
}

export interface CreateDefInput {
    key: string;
    name: string;
    description?: string;
    type: string;
    options?: string;
    required?: boolean;
    validation?: string;
    placeholder?: string;
    enabled?: boolean;
}

export interface UpdateDefInput {
    name?: string;
    description?: string;
    type?: string;
    options?: string;
    required?: boolean;
    validation?: string;
    placeholder?: string;
    enabled?: boolean;
}

export interface UpdateUserAttrInput {
    attributeId: number;
    value: string;
}

export class D1UserAttributeRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async listDefinitions(enabledOnly: boolean): Promise<UserAttributeDefinitionRecord[]> {
        const conditions = ["deleted_at IS NULL"];
        if (enabledOnly) conditions.push("enabled = 1");
        const rows = await allRows<DefRow>(
            this.#db,
            `SELECT * FROM user_attribute_definitions WHERE ${conditions.join(" AND ")} ORDER BY display_order ASC, id ASC`
        );
        return rows.map(defRowToRecord);
    }

    async findDefById(id: number): Promise<UserAttributeDefinitionRecord | null> {
        const row = await firstRow<DefRow>(
            this.#db,
            "SELECT * FROM user_attribute_definitions WHERE id = ? AND deleted_at IS NULL",
            [id]
        );
        return row === null ? null : defRowToRecord(row);
    }

    async findDefByKey(key: string): Promise<UserAttributeDefinitionRecord | null> {
        const row = await firstRow<DefRow>(
            this.#db,
            "SELECT * FROM user_attribute_definitions WHERE key = ? AND deleted_at IS NULL",
            [key]
        );
        return row === null ? null : defRowToRecord(row);
    }

    async existsByKey(key: string): Promise<boolean> {
        const row = await firstRow<{ count: number }>(
            this.#db,
            "SELECT COUNT(*) AS count FROM user_attribute_definitions WHERE key = ? AND deleted_at IS NULL",
            [key]
        );
        return (row?.count ?? 0) > 0;
    }

    async createDef(input: CreateDefInput): Promise<UserAttributeDefinitionRecord> {
        const now = new Date().toISOString();
        const maxOrder = await firstRow<{ max: number | null }>(
            this.#db,
            "SELECT MAX(display_order) AS max FROM user_attribute_definitions WHERE deleted_at IS NULL"
        );
        const displayOrder = (maxOrder?.max ?? -1) + 1;

        const result = await runStatement(
            this.#db,
            `INSERT INTO user_attribute_definitions (
                created_at, updated_at, key, name, description, type, options,
                required, validation, placeholder, display_order, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                now, now,
                input.key, input.name, input.description ?? "",
                input.type, input.options ?? "[]",
                input.required ? 1 : 0,
                input.validation ?? "{}",
                input.placeholder ?? "",
                displayOrder,
                (input.enabled ?? true) ? 1 : 0
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findDefById(id))!;
    }

    async updateDef(id: number, input: UpdateDefInput): Promise<UserAttributeDefinitionRecord | null> {
        const existing = await this.findDefById(id);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.name !== undefined) { sets.push("name = ?"); values.push(input.name); }
        if (input.description !== undefined) { sets.push("description = ?"); values.push(input.description); }
        if (input.type !== undefined) { sets.push("type = ?"); values.push(input.type); }
        if (input.options !== undefined) { sets.push("options = ?"); values.push(input.options); }
        if (input.required !== undefined) { sets.push("required = ?"); values.push(input.required ? 1 : 0); }
        if (input.validation !== undefined) { sets.push("validation = ?"); values.push(input.validation); }
        if (input.placeholder !== undefined) { sets.push("placeholder = ?"); values.push(input.placeholder); }
        if (input.enabled !== undefined) { sets.push("enabled = ?"); values.push(input.enabled ? 1 : 0); }

        if (sets.length === 1) return existing;

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE user_attribute_definitions SET ${sets.join(", ")} WHERE id = ? AND deleted_at IS NULL`,
            values
        );
        return this.findDefById(id);
    }

    async deleteDef(id: number): Promise<boolean> {
        const now = new Date().toISOString();
        await runBatchTransaction(this.#db, [
            { sql: "DELETE FROM user_attribute_values WHERE attribute_id = ?", values: [id] },
            { sql: "UPDATE user_attribute_definitions SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL", values: [now, now, id] }
        ]);
        return true;
    }

    async reorderDefs(orders: Map<number, number>): Promise<void> {
        const now = new Date().toISOString();
        const stmts: Array<{ sql: string; values: D1Value[] }> = [];
        for (const [id, order] of orders) {
            stmts.push({
                sql: "UPDATE user_attribute_definitions SET display_order = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
                values: [order, now, id]
            });
        }
        if (stmts.length > 0) await runBatchTransaction(this.#db, stmts);
    }

    async getUserAttributes(userId: number): Promise<UserAttributeValueRecord[]> {
        const rows = await allRows<ValRow>(
            this.#db,
            "SELECT * FROM user_attribute_values WHERE user_id = ?",
            [userId]
        );
        return rows.map(valRowToRecord);
    }

    async getBatchUserAttributes(userIds: number[]): Promise<Map<number, Map<number, string>>> {
        if (userIds.length === 0) return new Map();

        const placeholders = userIds.map(() => "?").join(",");
        const rows = await allRows<ValRow>(
            this.#db,
            `SELECT * FROM user_attribute_values WHERE user_id IN (${placeholders})`,
            userIds.map((id) => id as D1Value)
        );

        const result = new Map<number, Map<number, string>>();
        for (const row of rows) {
            if (!result.has(row.user_id)) result.set(row.user_id, new Map());
            result.get(row.user_id)!.set(row.attribute_id, row.value);
        }
        return result;
    }

    async upsertUserAttributes(userId: number, inputs: UpdateUserAttrInput[]): Promise<void> {
        const now = new Date().toISOString();
        const stmts: Array<{ sql: string; values: D1Value[] }> = [];

        for (const input of inputs) {
            stmts.push({
                sql: `INSERT INTO user_attribute_values (created_at, updated_at, value, user_id, attribute_id)
                      VALUES (?, ?, ?, ?, ?)
                      ON CONFLICT(user_id, attribute_id) DO UPDATE SET value = ?, updated_at = ?`,
                values: [now, now, input.value, userId, input.attributeId, input.value, now]
            });
        }

        if (stmts.length > 0) await runBatchTransaction(this.#db, stmts);
    }
}
