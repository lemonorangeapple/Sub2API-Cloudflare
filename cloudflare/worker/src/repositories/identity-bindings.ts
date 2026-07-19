import type { D1Database, D1PreparedStatement } from "../types/d1.ts";
import { prepareStatement, requireSuccess } from "./d1.ts";

export interface FirstBindSubscriptionMutation {
    groupId: number;
    validityDays: number;
    startsAt: string;
    expiresAt: string;
    windowStart: string;
}

export interface BindEmailIdentityMutation {
    userId: number;
    expectedUpdatedAt: string;
    email: string;
    passwordHash: string;
    verificationKey: string;
    verificationJson: string;
    now: number;
    updatedAt: string;
    firstBindGrant?: {
        balance: number;
        concurrency: number;
        subscriptions: readonly FirstBindSubscriptionMutation[];
    };
}

export class IdentityBindingMutationRejectedError extends Error {
    constructor(message = "identity binding mutation was rejected by a database guard") {
        super(message);
        this.name = "IdentityBindingMutationRejectedError";
    }
}

export class D1IdentityBindingRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async bindEmail(input: BindEmailIdentityMutation): Promise<void> {
        const statements: D1PreparedStatement[] = [];
        const grant = input.firstBindGrant;
        const grantGroupIds = [...new Set(grant?.subscriptions.map((item) => item.groupId) ?? [])];
        const grantGroupGuards = grantGroupIds.map(() => `
                AND EXISTS (
                    SELECT 1 FROM groups
                    WHERE id = ? AND deleted_at IS NULL AND subscription_type = 'subscription'
                )
        `).join("");
        statements.push(prepareStatement(this.#db, `
            UPDATE users
            SET
                email = ?,
                password_hash = ?,
                token_version = token_version + 1,
                updated_at = ?
            WHERE id = ?
                AND deleted_at IS NULL
                AND updated_at = ?
                AND EXISTS (
                    SELECT 1
                    FROM runtime_expiring_values
                    WHERE state_key = ?
                        AND value_json = ?
                        AND expires_at > ?
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM users AS owner
                    WHERE owner.id <> users.id
                        AND owner.deleted_at IS NULL
                        AND lower(trim(owner.email)) = lower(trim(?))
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM auth_identities AS identity
                    WHERE identity.user_id <> users.id
                        AND identity.provider_type = 'email'
                        AND identity.provider_key = 'email'
                        AND lower(trim(identity.provider_subject)) = lower(trim(?))
                )
                ${grantGroupGuards}
            RETURNING id
        `, [
            input.email,
            input.passwordHash,
            input.updatedAt,
            input.userId,
            input.expectedUpdatedAt,
            input.verificationKey,
            input.verificationJson,
            input.now,
            input.email,
            input.email,
            ...grantGroupIds
        ]));
        statements.push(prepareStatement(this.#db, `
            DELETE FROM runtime_expiring_values
            WHERE state_key = ?
                AND value_json = ?
                AND expires_at > ?
                AND EXISTS (
                    SELECT 1 FROM users
                    WHERE id = ? AND updated_at = ? AND lower(trim(email)) = lower(trim(?))
                )
        `, [
            input.verificationKey,
            input.verificationJson,
            input.now,
            input.userId,
            input.updatedAt,
            input.email
        ]));
        statements.push(prepareStatement(this.#db, `
            DELETE FROM auth_identities
            WHERE user_id = ?
                AND provider_type = 'email'
                AND provider_key = 'email'
                AND EXISTS (
                    SELECT 1 FROM users
                    WHERE id = ? AND updated_at = ? AND lower(trim(email)) = lower(trim(?))
                )
        `, [input.userId, input.userId, input.updatedAt, input.email]));
        statements.push(prepareStatement(this.#db, `
            INSERT INTO auth_identities (
                created_at, updated_at, provider_type, provider_key,
                provider_subject, verified_at, issuer, metadata, user_id
            )
            SELECT ?, ?, 'email', 'email', ?, ?, NULL, ?, id
            FROM users
            WHERE id = ? AND updated_at = ? AND lower(trim(email)) = lower(trim(?))
        `, [
            input.updatedAt,
            input.updatedAt,
            input.email,
            input.updatedAt,
            JSON.stringify({ source: "auth_service_email_bind" }),
            input.userId,
            input.updatedAt,
            input.email
        ]));

        if (grant !== undefined) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_provider_default_grants (
                    user_id, provider_type, grant_reason, granted_at, created_at
                )
                SELECT id, 'email', 'first_bind', ?, ?
                FROM users
                WHERE id = ? AND updated_at = ?
                ON CONFLICT(user_id, provider_type, grant_reason) DO NOTHING
            `, [input.updatedAt, input.updatedAt, input.userId, input.updatedAt]));
            statements.push(prepareStatement(this.#db, `
                UPDATE users
                SET
                    balance = balance + ?,
                    concurrency = concurrency + ?
                WHERE id = ?
                    AND updated_at = ?
                    AND EXISTS (
                        SELECT 1
                        FROM user_provider_default_grants
                        WHERE user_id = ?
                            AND provider_type = 'email'
                            AND grant_reason = 'first_bind'
                            AND created_at = ?
                    )
            `, [
                grant.balance,
                grant.concurrency,
                input.userId,
                input.updatedAt,
                input.userId,
                input.updatedAt
            ]));
            for (const subscription of grant.subscriptions) {
                statements.push(prepareStatement(this.#db, `
                    UPDATE user_subscriptions
                    SET
                        updated_at = ?,
                        starts_at = CASE WHEN expires_at <= ? THEN ? ELSE starts_at END,
                        expires_at = CASE
                            WHEN expires_at > ?
                                THEN strftime('%Y-%m-%dT%H:%M:%fZ', julianday(expires_at) + ?)
                            ELSE ?
                        END,
                        status = 'active',
                        daily_window_start = CASE WHEN expires_at <= ? THEN ? ELSE daily_window_start END,
                        weekly_window_start = CASE WHEN expires_at <= ? THEN ? ELSE weekly_window_start END,
                        monthly_window_start = CASE WHEN expires_at <= ? THEN ? ELSE monthly_window_start END,
                        daily_usage_usd = CASE WHEN expires_at <= ? THEN 0 ELSE daily_usage_usd END,
                        weekly_usage_usd = CASE WHEN expires_at <= ? THEN 0 ELSE weekly_usage_usd END,
                        monthly_usage_usd = CASE WHEN expires_at <= ? THEN 0 ELSE monthly_usage_usd END,
                        notes = CASE
                            WHEN trim(COALESCE(notes, '')) = '' THEN ?
                            ELSE notes || char(10) || ?
                        END
                    WHERE id = (
                        SELECT id
                        FROM user_subscriptions
                        WHERE user_id = ? AND group_id = ? AND deleted_at IS NULL
                        ORDER BY id
                        LIMIT 1
                    )
                        AND EXISTS (
                            SELECT 1
                            FROM user_provider_default_grants
                            WHERE user_id = ?
                                AND provider_type = 'email'
                                AND grant_reason = 'first_bind'
                                AND created_at = ?
                        )
                `, [
                    input.updatedAt,
                    subscription.startsAt,
                    subscription.startsAt,
                    subscription.startsAt,
                    subscription.validityDays,
                    subscription.expiresAt,
                    subscription.startsAt,
                    subscription.windowStart,
                    subscription.startsAt,
                    subscription.windowStart,
                    subscription.startsAt,
                    subscription.windowStart,
                    subscription.startsAt,
                    subscription.startsAt,
                    subscription.startsAt,
                    "auto assigned by first bind defaults",
                    "auto assigned by first bind defaults",
                    input.userId,
                    subscription.groupId,
                    input.userId,
                    input.updatedAt
                ]));
                statements.push(prepareStatement(this.#db, `
                    INSERT INTO user_subscriptions (
                        created_at, updated_at, deleted_at, starts_at, expires_at,
                        status, assigned_at, notes, group_id, user_id, assigned_by
                    )
                    SELECT ?, ?, NULL, ?, ?, 'active', ?, ?, ?, ?, NULL
                    WHERE EXISTS (
                        SELECT 1
                        FROM user_provider_default_grants
                        WHERE user_id = ?
                            AND provider_type = 'email'
                            AND grant_reason = 'first_bind'
                            AND created_at = ?
                    )
                        AND NOT EXISTS (
                            SELECT 1 FROM user_subscriptions
                            WHERE user_id = ? AND group_id = ? AND deleted_at IS NULL
                        )
                `, [
                    input.updatedAt,
                    input.updatedAt,
                    subscription.startsAt,
                    subscription.expiresAt,
                    input.updatedAt,
                    "auto assigned by first bind defaults",
                    subscription.groupId,
                    input.userId,
                    input.userId,
                    input.updatedAt,
                    input.userId,
                    subscription.groupId
                ]));
            }
        }

        statements.push(prepareStatement(this.#db, `
            UPDATE auth_refresh_sessions
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE user_id = ?
                AND revoked_at IS NULL
                AND EXISTS (
                    SELECT 1 FROM users
                    WHERE id = ? AND updated_at = ?
                )
        `, [input.now, input.userId, input.userId, input.updatedAt]));

        const results = await this.#db.batch(statements);
        results.forEach((result, index) => requireSuccess(result, `D1 identity binding statement ${index + 1} failed`));
        if (changed(results[0]) !== 1 || changed(results[1]) !== 1 || changed(results[3]) !== 1) {
            throw new IdentityBindingMutationRejectedError();
        }
    }

    async unbindProvider(
        userId: number,
        provider: string,
        expectedUpdatedAt: string,
        updatedAt: string,
        revokedAt: number
    ): Promise<void> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE users
                SET token_version = token_version + 1, updated_at = ?
                WHERE id = ?
                    AND deleted_at IS NULL
                    AND updated_at = ?
                    AND EXISTS (
                        SELECT 1 FROM auth_identities
                        WHERE user_id = users.id AND provider_type = ?
                    )
                    AND (
                        (
                            trim(email) <> ''
                            AND lower(trim(email)) NOT LIKE '%@linuxdo-connect.invalid'
                            AND lower(trim(email)) NOT LIKE '%@oidc-connect.invalid'
                            AND lower(trim(email)) NOT LIKE '%@wechat-connect.invalid'
                            AND lower(trim(email)) NOT LIKE '%@dingtalk-connect.invalid'
                            AND (
                                lower(trim(signup_source)) IN ('', 'email')
                                OR EXISTS (
                                    SELECT 1 FROM auth_identities AS email_identity
                                    WHERE email_identity.user_id = users.id
                                        AND email_identity.provider_type = 'email'
                                        AND json_extract(email_identity.metadata, '$.source') IN (
                                            'auth_service_email_bind',
                                            'auth_service_login_backfill',
                                            'auth_service_dual_write'
                                        )
                                )
                            )
                        )
                        OR EXISTS (
                            SELECT 1 FROM auth_identities AS alternative
                            WHERE alternative.user_id = users.id
                                AND alternative.provider_type IN ('linuxdo', 'oidc', 'wechat', 'dingtalk')
                                AND alternative.provider_type <> ?
                        )
                    )
                RETURNING id
            `, [updatedAt, userId, expectedUpdatedAt, provider, provider]),
            prepareStatement(this.#db, `
                DELETE FROM auth_identities
                WHERE user_id = ?
                    AND provider_type = ?
                    AND EXISTS (
                        SELECT 1 FROM users WHERE id = ? AND updated_at = ?
                    )
            `, [userId, provider, userId, updatedAt]),
            prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ?
                    AND revoked_at IS NULL
                    AND EXISTS (
                        SELECT 1 FROM users WHERE id = ? AND updated_at = ?
                    )
            `, [revokedAt, userId, userId, updatedAt])
        ]);
        results.forEach((result, index) => requireSuccess(result, `D1 identity unbind statement ${index + 1} failed`));
        if (changed(results[0]) !== 1 || changed(results[1]) < 1) {
            throw new IdentityBindingMutationRejectedError();
        }
    }
}

function changed(result: { meta?: { changes?: number }; results?: unknown[] }): number {
    return result.meta?.changes ?? result.results?.length ?? 0;
}
