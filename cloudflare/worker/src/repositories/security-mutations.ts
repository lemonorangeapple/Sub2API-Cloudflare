import type { D1Database } from "../types/d1.ts";
import { prepareStatement, requireSuccess } from "./d1.ts";

export interface PasswordChangeMutation {
    userId: number;
    expectedPasswordHash: string;
    newPasswordHash: string;
    updatedAt: string;
    revokedAt: number;
}

export interface PasswordResetMutation {
    normalizedEmail: string;
    stateKey: string;
    expectedStateJson: string;
    newPasswordHash: string;
    updatedAt: string;
    now: number;
}

export interface AdminSecurityUpdateMutation {
    actorAdminId: number;
    targetUserId: number;
    expectedUpdatedAt: string;
    newEmail: string | null;
    newPasswordHash: string | null;
    newRole: "admin" | "user" | null;
    newStatus: "active" | "disabled" | null;
    updatedAt: string;
    revokedAt: number;
    blockDisableAdmin: boolean;
    blockSelfDemotion: boolean;
    requireOtherAdmin: boolean;
}

export interface TotpEnableMutation {
    userId: number;
    expectedPasswordHash: string;
    encryptedSecret: string;
    setupStateKey: string;
    expectedStateJson: string;
    enabledAt: string;
    updatedAt: string;
    now: number;
}

export interface TotpDisableMutation {
    userId: number;
    expectedPasswordHash: string;
    updatedAt: string;
    revokedAt: number;
}

export class D1SecurityMutationRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async changePassword(input: PasswordChangeMutation): Promise<boolean> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET
                    password_hash = ?,
                    token_version = token_version + 1,
                    updated_at = ?
                WHERE id = ?
                    AND deleted_at IS NULL
                    AND password_hash = ?
            `, [
                input.newPasswordHash,
                input.updatedAt,
                input.userId,
                input.expectedPasswordHash
            ]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ?
                    AND revoked_at IS NULL
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE id = ?
                            AND deleted_at IS NULL
                            AND password_hash = ?
                            AND updated_at = ?
                    )
            `, [
                input.revokedAt,
                input.userId,
                input.userId,
                input.newPasswordHash,
                input.updatedAt
            ])
        ]);
        requireBatchSuccess(results, "password change");
        return changed(results[0]) === 1;
    }

    async resetPassword(input: PasswordResetMutation): Promise<boolean> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET
                    password_hash = ?,
                    token_version = token_version + 1,
                    updated_at = ?
                WHERE id = (
                    SELECT MIN(id)
                    FROM users
                    WHERE deleted_at IS NULL
                        AND status = 'active'
                        AND lower(trim(email)) = ?
                    HAVING COUNT(*) = 1
                )
                    AND EXISTS (
                        SELECT 1
                        FROM runtime_expiring_values
                        WHERE state_key = ?
                            AND value_json = ?
                            AND expires_at > ?
                    )
            `, [
                input.newPasswordHash,
                input.updatedAt,
                input.normalizedEmail,
                input.stateKey,
                input.expectedStateJson,
                input.now
            ]),
            prepareStatement(this.#db, `
                DELETE FROM runtime_expiring_values
                WHERE state_key = ?
                    AND value_json = ?
                    AND expires_at > ?
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE deleted_at IS NULL
                            AND status = 'active'
                            AND lower(trim(email)) = ?
                            AND password_hash = ?
                            AND updated_at = ?
                    )
            `, [
                input.stateKey,
                input.expectedStateJson,
                input.now,
                input.normalizedEmail,
                input.newPasswordHash,
                input.updatedAt
            ]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE revoked_at IS NULL
                    AND user_id = (
                        SELECT id
                        FROM users
                        WHERE deleted_at IS NULL
                            AND status = 'active'
                            AND lower(trim(email)) = ?
                            AND password_hash = ?
                            AND updated_at = ?
                    )
            `, [
                input.now,
                input.normalizedEmail,
                input.newPasswordHash,
                input.updatedAt
            ])
        ]);
        requireBatchSuccess(results, "password reset");
        const userChanged = changed(results[0]);
        const stateConsumed = changed(results[1]);
        if (userChanged === 0 && stateConsumed === 0) {
            return false;
        }
        if (userChanged !== 1 || stateConsumed !== 1) {
            throw new Error(
                `inconsistent password reset result: users=${userChanged}, state=${stateConsumed}`
            );
        }
        return true;
    }

    async updateAdminSecurity(input: AdminSecurityUpdateMutation): Promise<boolean> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET
                    email = COALESCE(?, email),
                    password_hash = COALESCE(?, password_hash),
                    role = COALESCE(?, role),
                    status = COALESCE(?, status),
                    token_version = token_version + 1,
                    updated_at = ?
                WHERE id = ?
                    AND deleted_at IS NULL
                    AND updated_at = ?
                    AND ? = 0
                    AND ? = 0
                    AND (
                        ? = 0
                        OR EXISTS (
                            SELECT 1
                            FROM users AS other_admin
                            WHERE other_admin.id <> users.id
                                AND other_admin.deleted_at IS NULL
                                AND other_admin.role = 'admin'
                                AND other_admin.status = 'active'
                        )
                    )
                    AND (
                        ? IS NULL
                        OR NOT EXISTS (
                            SELECT 1
                            FROM users AS email_owner
                            WHERE email_owner.id <> users.id
                                AND email_owner.deleted_at IS NULL
                                AND lower(trim(email_owner.email)) = lower(trim(?))
                        )
                    )
            `, [
                input.newEmail,
                input.newPasswordHash,
                input.newRole,
                input.newStatus,
                input.updatedAt,
                input.targetUserId,
                input.expectedUpdatedAt,
                input.blockDisableAdmin ? 1 : 0,
                input.blockSelfDemotion ? 1 : 0,
                input.requireOtherAdmin ? 1 : 0,
                input.newEmail,
                input.newEmail
            ]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ?
                    AND revoked_at IS NULL
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE id = ?
                            AND deleted_at IS NULL
                            AND updated_at = ?
                    )
            `, [
                input.revokedAt,
                input.targetUserId,
                input.targetUserId,
                input.updatedAt
            ])
        ]);
        requireBatchSuccess(results, "admin security update");
        return changed(results[0]) === 1;
    }

    async softDeleteUser(targetUserId: number, deletedAt: string, revokedAt: number): Promise<boolean> {
        const eligibleUser = `
            EXISTS (
                SELECT 1
                FROM users
                WHERE id = ?
                    AND deleted_at IS NULL
                    AND role <> 'admin'
            )
        `;
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE identity_adoption_decisions
                SET identity_id = NULL, updated_at = ?
                WHERE identity_id IN (
                    SELECT id FROM auth_identities WHERE user_id = ?
                )
                    AND ${eligibleUser}
            `, [deletedAt, targetUserId, targetUserId]),
            prepareStatement(this.#db, `
                DELETE FROM auth_identity_channels
                WHERE identity_id IN (
                    SELECT id FROM auth_identities WHERE user_id = ?
                )
                    AND ${eligibleUser}
            `, [targetUserId, targetUserId]),
            prepareStatement(this.#db, `
                DELETE FROM auth_identities
                WHERE user_id = ?
                    AND ${eligibleUser}
            `, [targetUserId, targetUserId]),
            prepareStatement(this.#db, `
                UPDATE api_keys
                SET deleted_at = ?, updated_at = ?, status = 'disabled'
                WHERE user_id = ?
                    AND deleted_at IS NULL
                    AND ${eligibleUser}
            `, [deletedAt, deletedAt, targetUserId, targetUserId]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ?
                    AND revoked_at IS NULL
                    AND ${eligibleUser}
            `, [revokedAt, targetUserId, targetUserId]),
            prepareStatement(this.#db, `
                UPDATE users
                SET
                    deleted_at = ?,
                    token_version = token_version + 1,
                    updated_at = ?
                WHERE id = ?
                    AND deleted_at IS NULL
                    AND role <> 'admin'
            `, [deletedAt, deletedAt, targetUserId])
        ]);
        requireBatchSuccess(results, "user soft delete");
        return changed(results[5]) === 1;
    }

    async restoreUser(targetUserId: number, restoredAt: string): Promise<boolean> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET
                    deleted_at = NULL,
                    token_version = token_version + 1,
                    updated_at = ?
                WHERE id = ?
                    AND deleted_at IS NOT NULL
            `, [restoredAt, targetUserId]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ? AND revoked_at IS NULL
            `, [Date.parse(restoredAt), targetUserId])
        ]);
        requireBatchSuccess(results, "user restore");
        return changed(results[0]) === 1;
    }

    async enableTotp(input: TotpEnableMutation): Promise<boolean> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET
                    totp_secret_encrypted = ?,
                    totp_enabled = 1,
                    totp_enabled_at = ?,
                    token_version = token_version + 1,
                    updated_at = ?
                WHERE id = ?
                    AND deleted_at IS NULL
                    AND status = 'active'
                    AND password_hash = ?
                    AND totp_enabled = 0
                    AND EXISTS (
                        SELECT 1
                        FROM runtime_expiring_values
                        WHERE state_key = ?
                            AND value_json = ?
                            AND expires_at > ?
                    )
            `, [
                input.encryptedSecret,
                input.enabledAt,
                input.updatedAt,
                input.userId,
                input.expectedPasswordHash,
                input.setupStateKey,
                input.expectedStateJson,
                input.now
            ]),
            prepareStatement(this.#db, `
                DELETE FROM runtime_expiring_values
                WHERE state_key = ?
                    AND value_json = ?
                    AND expires_at > ?
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE id = ?
                            AND deleted_at IS NULL
                            AND totp_enabled = 1
                            AND totp_secret_encrypted = ?
                            AND updated_at = ?
                    )
            `, [
                input.setupStateKey,
                input.expectedStateJson,
                input.now,
                input.userId,
                input.encryptedSecret,
                input.updatedAt
            ]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ?
                    AND revoked_at IS NULL
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE id = ?
                            AND totp_enabled = 1
                            AND updated_at = ?
                    )
            `, [input.now, input.userId, input.userId, input.updatedAt])
        ]);
        requireBatchSuccess(results, "TOTP enable");
        const userChanged = changed(results[0]);
        const stateConsumed = changed(results[1]);
        if (userChanged === 0 && stateConsumed === 0) {
            return false;
        }
        if (userChanged !== 1 || stateConsumed !== 1) {
            throw new Error(
                `inconsistent TOTP enable result: users=${userChanged}, state=${stateConsumed}`
            );
        }
        return true;
    }

    async disableTotp(input: TotpDisableMutation): Promise<boolean> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET
                    totp_secret_encrypted = NULL,
                    totp_enabled = 0,
                    totp_enabled_at = NULL,
                    token_version = token_version + 1,
                    updated_at = ?
                WHERE id = ?
                    AND deleted_at IS NULL
                    AND status = 'active'
                    AND password_hash = ?
                    AND totp_enabled = 1
            `, [input.updatedAt, input.userId, input.expectedPasswordHash]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ?
                    AND revoked_at IS NULL
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE id = ?
                            AND totp_enabled = 0
                            AND updated_at = ?
                    )
            `, [input.revokedAt, input.userId, input.userId, input.updatedAt])
        ]);
        requireBatchSuccess(results, "TOTP disable");
        return changed(results[0]) === 1;
    }
}

function changed(result: { meta?: { changes?: number } }): number {
    return result.meta?.changes ?? 0;
}

function requireBatchSuccess(
    results: Array<{ success: boolean; error?: string }>,
    operation: string
): void {
    results.forEach((result, index) => {
        requireSuccess(result, `${operation} statement ${index + 1} failed`);
    });
}
