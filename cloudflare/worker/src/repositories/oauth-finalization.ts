import type { D1Database, D1PreparedStatement } from "../types/d1.ts";
import { prepareStatement, requireSuccess } from "./d1.ts";
import type { FirstBindSubscriptionMutation } from "./identity-bindings.ts";

export interface OAuthIdentityMutation {
    providerType: string;
    providerKey: string;
    providerSubject: string;
    issuer: string | null;
    metadata: Record<string, unknown>;
}

export interface OAuthAdoptionMutation {
    adoptDisplayName: boolean;
    adoptAvatar: boolean;
    displayName: string;
    avatarUrl: string;
}

export interface OAuthFirstBindGrantMutation {
    balance: number;
    concurrency: number;
    subscriptions: readonly FirstBindSubscriptionMutation[];
}

export interface CompleteOAuthBindingMutation {
    pendingSessionId: number;
    browserSessionKey: string;
    finalizationNonce: string;
    userId: number;
    identity: OAuthIdentityMutation;
    adoption: OAuthAdoptionMutation;
    completedAt: string;
    completedAtMs: number;
    recordLogin: boolean;
    firstBindGrant?: OAuthFirstBindGrantMutation;
}

export class OAuthFinalizationRejectedError extends Error {
    constructor(message = "oauth finalization was rejected by a database guard") {
        super(message);
        this.name = "OAuthFinalizationRejectedError";
    }
}

export class D1OAuthFinalizationRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async completeBinding(input: CompleteOAuthBindingMutation): Promise<void> {
        const statements: D1PreparedStatement[] = [];
        const identity = input.identity;
        const adoption = input.adoption;
        const channel = oauthChannel(identity);
        const channelGuardSql = channel === null ? "" : `
                AND NOT EXISTS (
                    SELECT 1
                    FROM auth_identity_channels AS identity_channel
                    JOIN auth_identities AS channel_identity
                        ON channel_identity.id = identity_channel.identity_id
                    WHERE identity_channel.provider_type = ?
                        AND identity_channel.provider_key = ?
                        AND identity_channel.channel = ?
                        AND identity_channel.channel_app_id = ?
                        AND identity_channel.channel_subject = ?
                        AND channel_identity.user_id <> ?
                )`;
        const channelGuardValues = channel === null ? [] : [
            identity.providerType,
            identity.providerKey,
            channel.channel,
            channel.appId,
            channel.subject,
            input.userId
        ];

        statements.push(prepareStatement(this.#db, `
            UPDATE pending_auth_sessions
            SET
                consumed_at = ?,
                updated_at = ?,
                completion_code_hash = '',
                completion_code_expires_at = NULL,
                local_flow_state = json_set(
                    COALESCE(local_flow_state, '{}'),
                    '$.__finalization_nonce',
                    ?
                )
            WHERE id = ?
                AND consumed_at IS NULL
                AND expires_at >= ?
                AND (trim(browser_session_key) = '' OR browser_session_key = ?)
                AND intent IN ('login', 'bind_current_user', 'adopt_existing_user_by_email')
                AND (target_user_id IS NULL OR target_user_id = ?)
                AND EXISTS (
                    SELECT 1 FROM users
                    WHERE id = ? AND deleted_at IS NULL AND status = 'active'
                )
                AND provider_type = ?
                AND provider_key = ?
                AND provider_subject = ?
                AND NOT EXISTS (
                    SELECT 1
                    FROM auth_identities
                    WHERE provider_type = ?
                        AND provider_key = ?
                        AND provider_subject = ?
                        AND user_id <> ?
                )
                ${channelGuardSql}
            RETURNING id
        `, [
            input.completedAt,
            input.completedAt,
            input.finalizationNonce,
            input.pendingSessionId,
            input.completedAt,
            input.browserSessionKey,
            input.userId,
            input.userId,
            identity.providerType,
            identity.providerKey,
            identity.providerSubject,
            identity.providerType,
            identity.providerKey,
            identity.providerSubject,
            input.userId,
            ...channelGuardValues
        ]));

        statements.push(prepareStatement(this.#db, `
            INSERT INTO auth_identities (
                created_at, updated_at, provider_type, provider_key,
                provider_subject, verified_at, issuer, metadata, user_id
            )
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
            WHERE EXISTS (${finalizationGuard()})
            ON CONFLICT(provider_type, provider_key, provider_subject) DO UPDATE SET
                updated_at = excluded.updated_at,
                issuer = excluded.issuer,
                metadata = excluded.metadata
            WHERE auth_identities.user_id = excluded.user_id
        `, [
            input.completedAt,
            input.completedAt,
            identity.providerType,
            identity.providerKey,
            identity.providerSubject,
            input.completedAt,
            identity.issuer,
            JSON.stringify(identity.metadata),
            input.userId,
            input.pendingSessionId,
            input.finalizationNonce
        ]));

        if (channel !== null) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO auth_identity_channels (
                    created_at, updated_at, provider_type, provider_key,
                    channel, channel_app_id, channel_subject, metadata, identity_id
                )
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, id
                FROM auth_identities
                WHERE provider_type = ? AND provider_key = ? AND provider_subject = ?
                    AND user_id = ? AND EXISTS (${finalizationGuard()})
                ON CONFLICT(provider_type, provider_key, channel, channel_app_id, channel_subject)
                DO UPDATE SET
                    updated_at = excluded.updated_at,
                    metadata = excluded.metadata,
                    identity_id = excluded.identity_id
                WHERE auth_identity_channels.identity_id = excluded.identity_id
            `, [
                input.completedAt,
                input.completedAt,
                identity.providerType,
                identity.providerKey,
                channel.channel,
                channel.appId,
                channel.subject,
                JSON.stringify(channel.metadata),
                identity.providerType,
                identity.providerKey,
                identity.providerSubject,
                input.userId,
                input.pendingSessionId,
                input.finalizationNonce
            ]));
        }

        statements.push(prepareStatement(this.#db, `
            UPDATE identity_adoption_decisions
            SET identity_id = NULL, updated_at = ?
            WHERE identity_id = (
                SELECT id FROM auth_identities
                WHERE provider_type = ? AND provider_key = ? AND provider_subject = ?
            )
                AND pending_auth_session_id <> ?
                AND EXISTS (${finalizationGuard()})
        `, [
            input.completedAt,
            identity.providerType,
            identity.providerKey,
            identity.providerSubject,
            input.pendingSessionId,
            input.pendingSessionId,
            input.finalizationNonce
        ]));

        statements.push(prepareStatement(this.#db, `
            INSERT INTO identity_adoption_decisions (
                created_at, updated_at, adopt_display_name, adopt_avatar,
                decided_at, identity_id, pending_auth_session_id
            )
            SELECT
                ?, ?, ?, ?, ?,
                (
                    SELECT id FROM auth_identities
                    WHERE provider_type = ? AND provider_key = ? AND provider_subject = ?
                ),
                ?
            WHERE EXISTS (${finalizationGuard()})
            ON CONFLICT(pending_auth_session_id) DO UPDATE SET
                updated_at = excluded.updated_at,
                adopt_display_name = excluded.adopt_display_name,
                adopt_avatar = excluded.adopt_avatar,
                decided_at = excluded.decided_at,
                identity_id = excluded.identity_id
        `, [
            input.completedAt,
            input.completedAt,
            adoption.adoptDisplayName ? 1 : 0,
            adoption.adoptAvatar ? 1 : 0,
            input.completedAt,
            identity.providerType,
            identity.providerKey,
            identity.providerSubject,
            input.pendingSessionId,
            input.pendingSessionId,
            input.finalizationNonce
        ]));

        statements.push(prepareStatement(this.#db, `
            UPDATE users
            SET
                username = CASE WHEN ? = 1 AND trim(?) <> '' THEN ? ELSE username END,
                last_login_at = CASE WHEN ? = 1 THEN ? ELSE last_login_at END,
                last_active_at = CASE WHEN ? = 1 THEN ? ELSE last_active_at END,
                updated_at = ?
            WHERE id = ? AND EXISTS (${finalizationGuard()})
        `, [
            adoption.adoptDisplayName ? 1 : 0,
            adoption.displayName,
            adoption.displayName,
            input.recordLogin ? 1 : 0,
            input.completedAt,
            input.recordLogin ? 1 : 0,
            input.completedAt,
            input.completedAt,
            input.userId,
            input.pendingSessionId,
            input.finalizationNonce
        ]));

        if (adoption.adoptAvatar && adoption.avatarUrl !== "") {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_avatars (
                    user_id, storage_provider, storage_key, url,
                    content_type, byte_size, sha256, created_at, updated_at
                )
                SELECT ?, 'external', '', ?, '', 0, '', ?, ?
                WHERE EXISTS (${finalizationGuard()})
                ON CONFLICT(user_id) DO UPDATE SET
                    storage_provider = excluded.storage_provider,
                    storage_key = excluded.storage_key,
                    url = excluded.url,
                    content_type = excluded.content_type,
                    byte_size = excluded.byte_size,
                    sha256 = excluded.sha256,
                    updated_at = excluded.updated_at
            `, [
                input.userId,
                adoption.avatarUrl,
                input.completedAt,
                input.completedAt,
                input.pendingSessionId,
                input.finalizationNonce
            ]));
        }

        if (input.firstBindGrant !== undefined) {
            this.#appendFirstBindGrant(statements, input);
        }

        const results = await this.#db.batch(statements);
        results.forEach((result, index) => {
            requireSuccess(result, `D1 oauth finalization statement ${index + 1} failed`);
        });
        const consumedId = (results[0]?.results?.[0] as { id?: number } | undefined)?.id;
        if (consumedId !== input.pendingSessionId) {
            throw new OAuthFinalizationRejectedError();
        }
    }

    #appendFirstBindGrant(
        statements: D1PreparedStatement[],
        input: CompleteOAuthBindingMutation
    ): void {
        const grant = input.firstBindGrant;
        if (grant === undefined) return;
        const provider = input.identity.providerType;
        statements.push(prepareStatement(this.#db, `
            INSERT INTO user_provider_default_grants (
                user_id, provider_type, grant_reason, granted_at, created_at
            )
            SELECT ?, ?, 'first_bind', ?, ?
            WHERE EXISTS (${finalizationGuard()})
            ON CONFLICT(user_id, provider_type, grant_reason) DO NOTHING
        `, [
            input.userId,
            provider,
            input.completedAt,
            input.completedAt,
            input.pendingSessionId,
            input.finalizationNonce
        ]));
        statements.push(prepareStatement(this.#db, `
            UPDATE users
            SET balance = balance + ?, concurrency = concurrency + ?
            WHERE id = ?
                AND EXISTS (${finalizationGuard()})
                AND EXISTS (
                    SELECT 1 FROM user_provider_default_grants
                    WHERE user_id = ? AND provider_type = ?
                        AND grant_reason = 'first_bind' AND granted_at = ?
                )
        `, [
            grant.balance,
            grant.concurrency,
            input.userId,
            input.pendingSessionId,
            input.finalizationNonce,
            input.userId,
            provider,
            input.completedAt
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
                    SELECT id FROM user_subscriptions
                    WHERE user_id = ? AND group_id = ? AND deleted_at IS NULL
                    ORDER BY id LIMIT 1
                )
                    AND EXISTS (${grantGuard()})
                    AND EXISTS (${finalizationGuard()})
            `, [
                input.completedAt,
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
                provider,
                input.completedAt,
                input.pendingSessionId,
                input.finalizationNonce
            ]));
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_subscriptions (
                    created_at, updated_at, deleted_at, starts_at, expires_at,
                    status, assigned_at, notes, group_id, user_id, assigned_by
                )
                SELECT ?, ?, NULL, ?, ?, 'active', ?, ?, ?, ?, NULL
                WHERE EXISTS (${grantGuard()})
                    AND EXISTS (${finalizationGuard()})
                    AND NOT EXISTS (
                        SELECT 1 FROM user_subscriptions
                        WHERE user_id = ? AND group_id = ? AND deleted_at IS NULL
                    )
            `, [
                input.completedAt,
                input.completedAt,
                subscription.startsAt,
                subscription.expiresAt,
                input.completedAt,
                "auto assigned by first bind defaults",
                subscription.groupId,
                input.userId,
                input.userId,
                provider,
                input.completedAt,
                input.pendingSessionId,
                input.finalizationNonce,
                input.userId,
                subscription.groupId
            ]));
        }
    }
}

function oauthChannel(identity: OAuthIdentityMutation): {
    channel: string;
    appId: string;
    subject: string;
    metadata: Record<string, unknown>;
} | null {
    const channel = stringMetadata(identity.metadata.channel);
    const appId = stringMetadata(identity.metadata.channel_app_id);
    const subject = stringMetadata(identity.metadata.channel_subject);
    return channel === "" || appId === "" || subject === "" ? null : {
        channel, appId, subject, metadata: identity.metadata
    };
}

function stringMetadata(value: unknown): string {
    return typeof value === "string" ? value.trim() : "";
}

function finalizationGuard(): string {
    return `
        SELECT 1 FROM pending_auth_sessions
        WHERE id = ?
            AND json_extract(local_flow_state, '$.__finalization_nonce') = ?
    `;
}

function grantGuard(): string {
    return `
        SELECT 1 FROM user_provider_default_grants
        WHERE user_id = ? AND provider_type = ?
            AND grant_reason = 'first_bind' AND granted_at = ?
    `;
}
