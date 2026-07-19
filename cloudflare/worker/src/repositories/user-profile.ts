import type { D1Database, D1PreparedStatement, D1Value } from "../types/d1.ts";
import { prepareStatement, requireSuccess } from "./d1.ts";

export interface UserAvatarMutation {
    storageProvider: "remote_url" | "inline";
    url: string;
    contentType: string;
    byteSize: number;
    sha256: string;
}

export interface UserProfileMutation {
    userId: number;
    updatedAt: string;
    username?: string;
    balanceNotifyEnabled?: boolean;
    balanceNotifyThreshold?: number | null;
    avatar?: UserAvatarMutation | null;
}

export class D1UserProfileRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async update(input: UserProfileMutation): Promise<void> {
        const assignments = ["updated_at = ?"];
        const values: D1Value[] = [input.updatedAt];
        if (input.username !== undefined) {
            assignments.push("username = ?");
            values.push(input.username);
        }
        if (input.balanceNotifyEnabled !== undefined) {
            assignments.push("balance_notify_enabled = ?");
            values.push(input.balanceNotifyEnabled ? 1 : 0);
        }
        if (input.balanceNotifyThreshold !== undefined) {
            assignments.push("balance_notify_threshold = ?");
            values.push(input.balanceNotifyThreshold);
        }
        values.push(input.userId);
        const statements: D1PreparedStatement[] = [prepareStatement(this.#db, `
            UPDATE users SET ${assignments.join(", ")}
            WHERE id = ? AND deleted_at IS NULL AND status = 'active'
        `, values)];
        if (input.avatar === null) {
            statements.push(prepareStatement(this.#db, `DELETE FROM user_avatars WHERE user_id = ?`, [input.userId]));
        } else if (input.avatar !== undefined) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_avatars (
                    user_id, storage_provider, storage_key, url,
                    content_type, byte_size, sha256, created_at, updated_at
                ) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    storage_provider = excluded.storage_provider,
                    storage_key = '',
                    url = excluded.url,
                    content_type = excluded.content_type,
                    byte_size = excluded.byte_size,
                    sha256 = excluded.sha256,
                    updated_at = excluded.updated_at
            `, [
                input.userId,
                input.avatar.storageProvider,
                input.avatar.url,
                input.avatar.contentType,
                input.avatar.byteSize,
                input.avatar.sha256,
                input.updatedAt,
                input.updatedAt
            ]));
        }
        const results = await this.#db.batch(statements);
        results.forEach((result, index) => requireSuccess(result, `D1 user profile statement ${index + 1} failed`));
        if ((results[0]?.meta?.changes ?? 0) !== 1) throw new Error("user profile update target is unavailable");
    }

    async updateNotificationEmails(
        userId: number,
        expectedUpdatedAt: string,
        entries: readonly unknown[],
        updatedAt: string
    ): Promise<boolean> {
        const result = await prepareStatement(this.#db, `
            UPDATE users
            SET balance_notify_extra_emails = ?, updated_at = ?
            WHERE id = ? AND updated_at = ? AND deleted_at IS NULL AND status = 'active'
        `, [JSON.stringify(entries), updatedAt, userId, expectedUpdatedAt]).run();
        requireSuccess(result, "D1 notification email update failed");
        return (result.meta?.changes ?? 0) === 1;
    }

    async consumeNotificationVerification(
        userId: number,
        expectedUpdatedAt: string,
        entries: readonly unknown[],
        stateKey: string,
        expectedStateJson: string,
        now: number
    ): Promise<boolean> {
        const updatedAt = new Date(now).toISOString();
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET balance_notify_extra_emails = ?, updated_at = ?
                WHERE id = ? AND updated_at = ? AND deleted_at IS NULL AND status = 'active'
                    AND EXISTS (
                        SELECT 1 FROM runtime_expiring_values
                        WHERE state_key = ? AND value_json = ? AND expires_at > ?
                    )
            `, [JSON.stringify(entries), updatedAt, userId, expectedUpdatedAt, stateKey, expectedStateJson, now]),
            prepareStatement(this.#db, `
                DELETE FROM runtime_expiring_values
                WHERE state_key = ? AND value_json = ? AND expires_at > ?
                    AND EXISTS (
                        SELECT 1 FROM users
                        WHERE id = ? AND updated_at = ?
                    )
            `, [stateKey, expectedStateJson, now, userId, updatedAt])
        ]);
        results.forEach((result, index) => {
            requireSuccess(result, `D1 notification verification statement ${index + 1} failed`);
        });
        return (results[0]?.meta?.changes ?? 0) === 1 && (results[1]?.meta?.changes ?? 0) === 1;
    }
}
