import type { D1Database, D1PreparedStatement } from "../types/d1.ts";
import { prepareStatement, requireSuccess } from "./d1.ts";

export interface DingTalkAttributeSyncMutation {
    usernameOnRegistration: boolean;
    username: string;
    attributes: readonly { key: string; value: string }[];
}

export class D1DingTalkAttributeRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async sync(
        userId: number,
        input: DingTalkAttributeSyncMutation,
        registration: boolean,
        updatedAt: string
    ): Promise<void> {
        if (!Number.isSafeInteger(userId) || userId <= 0) return;
        const statements: D1PreparedStatement[] = [];
        const username = bounded(input.username, 100);
        if (registration && input.usernameOnRegistration && username !== "") {
            statements.push(prepareStatement(this.#db, `
                UPDATE users SET username = ?, updated_at = ?
                WHERE id = ? AND deleted_at IS NULL
            `, [username, updatedAt, userId]));
        }
        for (const field of input.attributes) {
            const key = normalizedKey(field.key);
            if (key === "") continue;
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_attribute_values (
                    created_at, updated_at, value, user_id, attribute_id
                )
                SELECT ?, ?, ?, ?, definition.id
                FROM user_attribute_definitions AS definition
                WHERE definition.key = ? AND definition.deleted_at IS NULL AND definition.enabled = 1
                    AND EXISTS (SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL)
                ORDER BY definition.id LIMIT 1
                ON CONFLICT(user_id, attribute_id) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    value = excluded.value
            `, [updatedAt, updatedAt, bounded(field.value, 2048), userId, key, userId]));
        }
        if (statements.length === 0) return;
        const results = await this.#db.batch(statements);
        results.forEach((result, index) => {
            requireSuccess(result, `D1 dingtalk attribute sync statement ${index + 1} failed`);
        });
    }
}

function normalizedKey(value: string): string {
    const key = value.trim().toLowerCase();
    return /^[a-z][a-z0-9_-]{0,63}$/u.test(key) ? key : "";
}

function bounded(value: string, maximum: number): string {
    return [...value.trim()].slice(0, maximum).join("");
}
