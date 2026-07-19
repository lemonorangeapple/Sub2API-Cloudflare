import type { D1Database, D1PreparedStatement, D1Result } from "../types/d1.ts";
import { firstRow, prepareStatement, requireSuccess } from "./d1.ts";
import type { OAuthAdoptionMutation, OAuthIdentityMutation } from "./oauth-finalization.ts";

export interface DefaultSubscriptionMutation {
    groupId: number;
    startsAt: string;
    expiresAt: string;
    notes: string;
}

export interface PlatformQuotaMutation {
    platform: string;
    dailyLimitUsd: number | null;
    weeklyLimitUsd: number | null;
    monthlyLimitUsd: number | null;
}

export interface CreateManagedUserMutation {
    email: string;
    passwordHash: string;
    role: "admin" | "user";
    username: string;
    notes: string;
    balance: number;
    concurrency: number;
    rpmLimit: number;
    status: "active" | "disabled";
    signupSource: string;
    allowedGroups: readonly number[];
    groupRates: ReadonlyMap<number, number>;
    defaultSubscriptions: readonly DefaultSubscriptionMutation[];
    createdAt: string;
    requireEmptyDatabase?: boolean;
    verificationState?: {
        key: string;
        expectedJson: string;
        now: number;
    };
    invitation?: {
        code: string;
        nowIso: string;
    };
    touchLoginAt?: string;
    platformQuotas?: readonly PlatformQuotaMutation[];
    affiliate?: {
        profileCode: string;
        inviterCode?: string;
    };
    promotion?: {
        code: string;
        nowIso: string;
    };
    oauthFinalization?: {
        pendingSessionId: number;
        browserSessionKey: string;
        finalizationNonce: string;
        identity: OAuthIdentityMutation;
        adoption: OAuthAdoptionMutation;
        grantOnSignup: boolean;
    };
}

export interface FullUserUpdateMutation {
    targetUserId: number;
    expectedUpdatedAt: string;
    email: string | null;
    passwordHash: string | null;
    username: string | null;
    notes: string | null;
    role: "admin" | "user" | null;
    balance: number | null;
    concurrency: number | null;
    rpmLimit: number | null;
    status: "active" | "disabled" | null;
    replaceAllowedGroups: boolean;
    allowedGroups: readonly number[];
    groupRates: ReadonlyMap<number, number | null> | null;
    securityChanged: boolean;
    blockDisableAdmin: boolean;
    blockSelfDemotion: boolean;
    requireOtherAdmin: boolean;
    updatedAt: string;
    revokedAt: number;
    concurrencyAdjustment?: {
        code: string;
        delta: number;
        actorAdminId: number;
    };
}

export class UserMutationRejectedError extends Error {
    constructor(message = "user mutation was rejected by a database guard") {
        super(message);
        this.name = "UserMutationRejectedError";
    }
}

export class D1UserManagementRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async createUser(input: CreateManagedUserMutation): Promise<number> {
        const statements: D1PreparedStatement[] = [];
        const verification = input.verificationState ?? null;
        const invitation = input.invitation ?? null;
        const affiliate = input.affiliate ?? null;
        const promotion = input.promotion ?? null;
        const oauth = input.oauthFinalization ?? null;
        const oauthChannelMetadata = oauth === null ? null : oauthChannel(oauth.identity);
        const normalizedEmail = input.email.trim().toLowerCase();
        let oauthConsumeIndex: number | null = null;
        let verificationIndex: number | null = null;
        let invitationIndex: number | null = null;

        if (oauth !== null) {
            const channelGuardSql = oauthChannelMetadata === null ? "" : `
                    AND NOT EXISTS (
                        SELECT 1
                        FROM auth_identity_channels
                        WHERE provider_type = ?
                            AND provider_key = ?
                            AND channel = ?
                            AND channel_app_id = ?
                            AND channel_subject = ?
                    )`;
            const channelGuardValues = oauthChannelMetadata === null ? [] : [
                oauth.identity.providerType,
                oauth.identity.providerKey,
                oauthChannelMetadata.channel,
                oauthChannelMetadata.appId,
                oauthChannelMetadata.subject
            ];
            oauthConsumeIndex = statements.length;
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
                    AND intent = 'login'
                    AND target_user_id IS NULL
                    AND provider_type = ?
                    AND provider_key = ?
                    AND provider_subject = ?
                    AND NOT EXISTS (
                        SELECT 1 FROM users
                        WHERE lower(trim(email)) = ? AND deleted_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM auth_identities
                        WHERE provider_type = ?
                            AND provider_key = ?
                            AND provider_subject = ?
                    )
                    ${channelGuardSql}
                    AND (
                        ? IS NULL
                        OR EXISTS (
                            SELECT 1 FROM runtime_expiring_values
                            WHERE state_key = ?
                                AND value_json = ?
                                AND expires_at > ?
                        )
                    )
                    AND (
                        ? IS NULL
                        OR EXISTS (
                            SELECT 1 FROM redeem_codes
                            WHERE code = ?
                                AND type = 'invitation'
                                AND status = 'unused'
                                AND (expires_at IS NULL OR expires_at > ?)
                        )
                    )
                RETURNING id
            `, [
                input.createdAt,
                input.createdAt,
                oauth.finalizationNonce,
                oauth.pendingSessionId,
                input.createdAt,
                oauth.browserSessionKey,
                oauth.identity.providerType,
                oauth.identity.providerKey,
                oauth.identity.providerSubject,
                normalizedEmail,
                oauth.identity.providerType,
                oauth.identity.providerKey,
                oauth.identity.providerSubject,
                ...channelGuardValues,
                verification?.key ?? null,
                verification?.key ?? null,
                verification?.expectedJson ?? null,
                verification?.now ?? 0,
                invitation?.code ?? null,
                invitation?.code ?? null,
                invitation?.nowIso ?? input.createdAt
            ]));
        }

        const userInsertIndex = statements.length;
        statements.push(prepareStatement(this.#db, `
            INSERT INTO users (
                created_at,
                updated_at,
                deleted_at,
                email,
                password_hash,
                role,
                balance,
                frozen_balance,
                concurrency,
                status,
                username,
                notes,
                signup_source,
                balance_notify_enabled,
                balance_notify_threshold_type,
                balance_notify_extra_emails,
                total_recharged,
                rpm_limit,
                token_version,
                last_login_at,
                last_active_at
            )
            SELECT
                ?, ?, NULL, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 1, 'fixed', '[]', 0, ?, 0, ?, ?
            WHERE (? = 0 OR NOT EXISTS (SELECT 1 FROM users))
                AND (
                    ? IS NULL
                    OR EXISTS (
                        SELECT 1 FROM pending_auth_sessions
                        WHERE id = ?
                            AND json_extract(local_flow_state, '$.__finalization_nonce') = ?
                    )
                )
                AND (
                    ? IS NULL
                    OR EXISTS (
                        SELECT 1
                        FROM runtime_expiring_values
                        WHERE state_key = ?
                            AND value_json = ?
                            AND expires_at > ?
                    )
                )
                AND (
                    ? IS NULL
                    OR EXISTS (
                        SELECT 1
                        FROM redeem_codes
                        WHERE code = ?
                            AND type = 'invitation'
                            AND status = 'unused'
                            AND (expires_at IS NULL OR expires_at > ?)
                    )
                )
            RETURNING id
        `, [
            input.createdAt,
            input.createdAt,
            input.email,
            input.passwordHash,
            input.role,
            input.balance,
            input.concurrency,
            input.status,
            input.username,
            input.notes,
            input.signupSource,
            input.rpmLimit,
            input.touchLoginAt ?? null,
            input.touchLoginAt ?? null,
            input.requireEmptyDatabase === true ? 1 : 0,
            oauth?.finalizationNonce ?? null,
            oauth?.pendingSessionId ?? 0,
            oauth?.finalizationNonce ?? null,
            verification?.key ?? null,
            verification?.key ?? null,
            verification?.expectedJson ?? null,
            verification?.now ?? 0,
            invitation?.code ?? null,
            invitation?.code ?? null,
            invitation?.nowIso ?? input.createdAt
        ]));

        if (verification !== null) {
            verificationIndex = statements.length;
            statements.push(prepareStatement(this.#db, `
                DELETE FROM runtime_expiring_values
                WHERE state_key = ?
                    AND value_json = ?
                    AND expires_at > ?
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE lower(trim(email)) = ?
                            AND created_at = ?
                            AND deleted_at IS NULL
                    )
            `, [
                verification.key,
                verification.expectedJson,
                verification.now,
                normalizedEmail,
                input.createdAt
            ]));
        }

        if (invitation !== null) {
            invitationIndex = statements.length;
            statements.push(prepareStatement(this.#db, `
                UPDATE redeem_codes
                SET
                    status = 'used',
                    used_at = ?,
                    used_by = (
                        SELECT id
                        FROM users
                        WHERE lower(trim(email)) = ?
                            AND created_at = ?
                            AND deleted_at IS NULL
                    )
                WHERE code = ?
                    AND type = 'invitation'
                    AND status = 'unused'
                    AND (expires_at IS NULL OR expires_at > ?)
                    AND EXISTS (
                        SELECT 1
                        FROM users
                        WHERE lower(trim(email)) = ?
                            AND created_at = ?
                            AND deleted_at IS NULL
                    )
            `, [
                input.createdAt,
                normalizedEmail,
                input.createdAt,
                invitation.code,
                invitation.nowIso,
                normalizedEmail,
                input.createdAt
            ]));
        }

        for (const groupId of uniquePositiveIntegers(input.allowedGroups)) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_allowed_groups (created_at, user_id, group_id)
                SELECT ?, id, ?
                FROM users
                WHERE lower(trim(email)) = ?
                    AND created_at = ?
                    AND deleted_at IS NULL
            `, [input.createdAt, groupId, normalizedEmail, input.createdAt]));
        }

        for (const [groupId, rate] of input.groupRates) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_group_rate_multipliers (
                    user_id, group_id, rate_multiplier, created_at, updated_at
                )
                SELECT id, ?, ?, ?, ?
                FROM users
                WHERE lower(trim(email)) = ?
                    AND created_at = ?
                    AND deleted_at IS NULL
            `, [groupId, rate, input.createdAt, input.createdAt, normalizedEmail, input.createdAt]));
        }

        for (const subscription of input.defaultSubscriptions) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_subscriptions (
                    created_at,
                    updated_at,
                    deleted_at,
                    starts_at,
                    expires_at,
                    status,
                    assigned_at,
                    notes,
                    group_id,
                    user_id,
                    assigned_by
                )
                SELECT ?, ?, NULL, ?, ?, 'active', ?, ?, ?, id, NULL
                FROM users
                WHERE lower(trim(email)) = ?
                    AND created_at = ?
                    AND deleted_at IS NULL
            `, [
                input.createdAt,
                input.createdAt,
                subscription.startsAt,
                subscription.expiresAt,
                input.createdAt,
                subscription.notes,
                subscription.groupId,
                normalizedEmail,
                input.createdAt
            ]));
        }

        for (const quota of input.platformQuotas ?? []) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_platform_quotas (
                    created_at,
                    updated_at,
                    deleted_at,
                    platform,
                    daily_limit_usd,
                    weekly_limit_usd,
                    monthly_limit_usd,
                    daily_usage_usd,
                    weekly_usage_usd,
                    monthly_usage_usd,
                    daily_window_start,
                    weekly_window_start,
                    monthly_window_start,
                    user_id
                )
                SELECT ?, ?, NULL, ?, ?, ?, ?, 0, 0, 0, NULL, NULL, NULL, id
                FROM users
                WHERE lower(trim(email)) = ?
                    AND created_at = ?
                    AND deleted_at IS NULL
            `, [
                input.createdAt,
                input.createdAt,
                quota.platform,
                quota.dailyLimitUsd,
                quota.weeklyLimitUsd,
                quota.monthlyLimitUsd,
                normalizedEmail,
                input.createdAt
            ]));
        }

        if (affiliate !== null) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO user_affiliates (
                    user_id,
                    aff_code,
                    inviter_id,
                    aff_count,
                    aff_quota,
                    aff_history_quota,
                    created_at,
                    updated_at,
                    aff_code_custom,
                    aff_frozen_quota
                )
                SELECT
                    created_user.id,
                    ?,
                    (
                        SELECT inviter.user_id
                        FROM user_affiliates AS inviter
                        WHERE upper(inviter.aff_code) = upper(?)
                            AND inviter.user_id <> created_user.id
                        ORDER BY inviter.user_id
                        LIMIT 1
                    ),
                    0,
                    0,
                    0,
                    ?,
                    ?,
                    0,
                    0
                FROM users AS created_user
                WHERE lower(trim(created_user.email)) = ?
                    AND created_user.created_at = ?
                    AND created_user.deleted_at IS NULL
            `, [
                affiliate.profileCode,
                affiliate.inviterCode ?? "",
                input.createdAt,
                input.createdAt,
                normalizedEmail,
                input.createdAt
            ]));
            statements.push(prepareStatement(this.#db, `
                UPDATE user_affiliates
                SET aff_count = aff_count + 1, updated_at = ?
                WHERE user_id = (
                    SELECT inviter_id
                    FROM user_affiliates
                    WHERE user_id = (
                        SELECT id
                        FROM users
                        WHERE lower(trim(email)) = ?
                            AND created_at = ?
                            AND deleted_at IS NULL
                    )
                )
            `, [input.createdAt, normalizedEmail, input.createdAt]));
        }

        if (promotion !== null) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO promo_code_usages (
                    bonus_amount, used_at, promo_code_id, user_id
                )
                SELECT promo.bonus_amount, ?, promo.id, created_user.id
                FROM promo_codes AS promo
                JOIN users AS created_user
                    ON lower(trim(created_user.email)) = ?
                    AND created_user.created_at = ?
                    AND created_user.deleted_at IS NULL
                WHERE lower(promo.code) = lower(?)
                    AND promo.status = 'active'
                    AND (promo.expires_at IS NULL OR promo.expires_at > ?)
                    AND (promo.max_uses = 0 OR promo.used_count < promo.max_uses)
                    AND NOT EXISTS (
                        SELECT 1
                        FROM promo_code_usages AS existing
                        WHERE existing.promo_code_id = promo.id
                            AND existing.user_id = created_user.id
                    )
                ORDER BY promo.id
                LIMIT 1
            `, [
                input.createdAt,
                normalizedEmail,
                input.createdAt,
                promotion.code,
                promotion.nowIso
            ]));
            statements.push(prepareStatement(this.#db, `
                UPDATE users
                SET balance = balance + (
                    SELECT usage.bonus_amount
                    FROM promo_code_usages AS usage
                    JOIN promo_codes AS promo ON promo.id = usage.promo_code_id
                    WHERE usage.user_id = users.id
                        AND usage.used_at = ?
                        AND lower(promo.code) = lower(?)
                    ORDER BY usage.id DESC
                    LIMIT 1
                )
                WHERE lower(trim(email)) = ?
                    AND created_at = ?
                    AND deleted_at IS NULL
                    AND EXISTS (
                        SELECT 1
                        FROM promo_code_usages AS usage
                        JOIN promo_codes AS promo ON promo.id = usage.promo_code_id
                        WHERE usage.user_id = users.id
                            AND usage.used_at = ?
                            AND lower(promo.code) = lower(?)
                    )
            `, [
                input.createdAt,
                promotion.code,
                normalizedEmail,
                input.createdAt,
                input.createdAt,
                promotion.code
            ]));
            statements.push(prepareStatement(this.#db, `
                UPDATE promo_codes
                SET used_count = used_count + 1, updated_at = ?
                WHERE id = (
                    SELECT usage.promo_code_id
                    FROM promo_code_usages AS usage
                    JOIN users AS created_user ON created_user.id = usage.user_id
                    WHERE lower(trim(created_user.email)) = ?
                        AND created_user.created_at = ?
                        AND usage.used_at = ?
                    ORDER BY usage.id DESC
                    LIMIT 1
                )
            `, [input.createdAt, normalizedEmail, input.createdAt, input.createdAt]));
        }

        if (oauth !== null) {
            const identity = oauth.identity;
            const adoption = oauth.adoption;
            statements.push(prepareStatement(this.#db, `
                INSERT INTO auth_identities (
                    created_at, updated_at, provider_type, provider_key,
                    provider_subject, verified_at, issuer, metadata, user_id
                )
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, id
                FROM users
                WHERE lower(trim(email)) = ?
                    AND created_at = ?
                    AND deleted_at IS NULL
                    AND EXISTS (${oauthCreationGuard()})
            `, [
                input.createdAt,
                input.createdAt,
                identity.providerType,
                identity.providerKey,
                identity.providerSubject,
                input.createdAt,
                identity.issuer,
                JSON.stringify(identity.metadata),
                normalizedEmail,
                input.createdAt,
                oauth.pendingSessionId,
                oauth.finalizationNonce
            ]));
            const channel = oauthChannelMetadata;
            if (channel !== null) {
                statements.push(prepareStatement(this.#db, `
                    INSERT INTO auth_identity_channels (
                        created_at, updated_at, provider_type, provider_key,
                        channel, channel_app_id, channel_subject, metadata, identity_id
                    )
                    SELECT ?, ?, ?, ?, ?, ?, ?, ?, identity.id
                    FROM auth_identities AS identity
                    JOIN users AS created_user ON created_user.id = identity.user_id
                    WHERE identity.provider_type = ?
                        AND identity.provider_key = ?
                        AND identity.provider_subject = ?
                        AND lower(trim(created_user.email)) = ?
                        AND created_user.created_at = ?
                        AND EXISTS (${oauthCreationGuard()})
                    ON CONFLICT(provider_type, provider_key, channel, channel_app_id, channel_subject)
                    DO UPDATE SET
                        updated_at = excluded.updated_at,
                        metadata = excluded.metadata,
                        identity_id = excluded.identity_id
                    WHERE auth_identity_channels.identity_id = excluded.identity_id
                `, [
                    input.createdAt,
                    input.createdAt,
                    identity.providerType,
                    identity.providerKey,
                    channel.channel,
                    channel.appId,
                    channel.subject,
                    JSON.stringify(channel.metadata),
                    identity.providerType,
                    identity.providerKey,
                    identity.providerSubject,
                    normalizedEmail,
                    input.createdAt,
                    oauth.pendingSessionId,
                    oauth.finalizationNonce
                ]));
            }
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
                WHERE EXISTS (${oauthCreationGuard()})
                ON CONFLICT(pending_auth_session_id) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    adopt_display_name = excluded.adopt_display_name,
                    adopt_avatar = excluded.adopt_avatar,
                    decided_at = excluded.decided_at,
                    identity_id = excluded.identity_id
            `, [
                input.createdAt,
                input.createdAt,
                adoption.adoptDisplayName ? 1 : 0,
                adoption.adoptAvatar ? 1 : 0,
                input.createdAt,
                identity.providerType,
                identity.providerKey,
                identity.providerSubject,
                oauth.pendingSessionId,
                oauth.pendingSessionId,
                oauth.finalizationNonce
            ]));
            if (adoption.adoptAvatar && adoption.avatarUrl !== "") {
                statements.push(prepareStatement(this.#db, `
                    INSERT INTO user_avatars (
                        user_id, storage_provider, storage_key, url,
                        content_type, byte_size, sha256, created_at, updated_at
                    )
                    SELECT id, 'external', '', ?, '', 0, '', ?, ?
                    FROM users
                    WHERE lower(trim(email)) = ?
                        AND created_at = ?
                        AND deleted_at IS NULL
                        AND EXISTS (${oauthCreationGuard()})
                `, [
                    adoption.avatarUrl,
                    input.createdAt,
                    input.createdAt,
                    normalizedEmail,
                    input.createdAt,
                    oauth.pendingSessionId,
                    oauth.finalizationNonce
                ]));
            }
            if (oauth.grantOnSignup) {
                statements.push(prepareStatement(this.#db, `
                    INSERT INTO user_provider_default_grants (
                        user_id, provider_type, grant_reason, granted_at, created_at
                    )
                    SELECT id, ?, 'signup', ?, ?
                    FROM users
                    WHERE lower(trim(email)) = ?
                        AND created_at = ?
                        AND deleted_at IS NULL
                        AND EXISTS (${oauthCreationGuard()})
                `, [
                    identity.providerType,
                    input.createdAt,
                    input.createdAt,
                    normalizedEmail,
                    input.createdAt,
                    oauth.pendingSessionId,
                    oauth.finalizationNonce
                ]));
            }
        }

        const results = await this.#db.batch(statements);
        requireBatchSuccess(results, "create user");
        if (oauthConsumeIndex !== null) {
            const consumed = results[oauthConsumeIndex]?.results?.[0] as { id?: number } | undefined;
            if (consumed?.id !== oauth?.pendingSessionId) {
                throw new UserMutationRejectedError("oauth account finalization was rejected");
            }
        }
        const inserted = results[userInsertIndex]?.results?.[0] as { id?: number } | undefined;
        const insertedId = inserted?.id;
        if (!Number.isSafeInteger(insertedId) || (insertedId ?? 0) <= 0) {
            throw new UserMutationRejectedError();
        }
        if (verificationIndex !== null && changed(results[verificationIndex]) !== 1) {
            throw new Error("user creation did not consume its verification state");
        }
        if (invitationIndex !== null && changed(results[invitationIndex]) !== 1) {
            throw new Error("user creation did not consume its invitation code");
        }
        return insertedId as number;
    }

    async updateUser(input: FullUserUpdateMutation): Promise<boolean> {
        const statements: D1PreparedStatement[] = [];
        statements.push(prepareStatement(this.#db, `
            UPDATE users
            SET
                email = COALESCE(?, email),
                password_hash = COALESCE(?, password_hash),
                username = COALESCE(?, username),
                notes = COALESCE(?, notes),
                role = COALESCE(?, role),
                balance = COALESCE(?, balance),
                concurrency = COALESCE(?, concurrency),
                rpm_limit = COALESCE(?, rpm_limit),
                status = COALESCE(?, status),
                token_version = token_version + ?,
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
            RETURNING id
        `, [
            input.email,
            input.passwordHash,
            input.username,
            input.notes,
            input.role,
            input.balance,
            input.concurrency,
            input.rpmLimit,
            input.status,
            input.securityChanged ? 1 : 0,
            input.updatedAt,
            input.targetUserId,
            input.expectedUpdatedAt,
            input.blockDisableAdmin ? 1 : 0,
            input.blockSelfDemotion ? 1 : 0,
            input.requireOtherAdmin ? 1 : 0
        ]));

        if (input.replaceAllowedGroups) {
            statements.push(guardedStatement(this.#db, `
                DELETE FROM user_allowed_groups
                WHERE user_id = ?
            `, [input.targetUserId], input.targetUserId, input.updatedAt));
            for (const groupId of uniquePositiveIntegers(input.allowedGroups)) {
                statements.push(prepareStatement(this.#db, `
                    INSERT INTO user_allowed_groups (created_at, user_id, group_id)
                    SELECT ?, ?, ?
                    WHERE EXISTS (
                        SELECT 1 FROM users WHERE id = ? AND updated_at = ? AND deleted_at IS NULL
                    )
                `, [input.updatedAt, input.targetUserId, groupId, input.targetUserId, input.updatedAt]));
            }
        }

        if (input.groupRates !== null) {
            for (const [groupId, rate] of input.groupRates) {
                if (rate === null) {
                    statements.push(guardedStatement(this.#db, `
                        DELETE FROM user_group_rate_multipliers
                        WHERE user_id = ? AND group_id = ?
                    `, [input.targetUserId, groupId], input.targetUserId, input.updatedAt));
                } else {
                    statements.push(prepareStatement(this.#db, `
                        INSERT INTO user_group_rate_multipliers (
                            user_id, group_id, rate_multiplier, created_at, updated_at
                        )
                        SELECT ?, ?, ?, ?, ?
                        WHERE EXISTS (
                            SELECT 1 FROM users WHERE id = ? AND updated_at = ? AND deleted_at IS NULL
                        )
                        ON CONFLICT(user_id, group_id) DO UPDATE SET
                            rate_multiplier = excluded.rate_multiplier,
                            updated_at = excluded.updated_at
                    `, [
                        input.targetUserId,
                        groupId,
                        rate,
                        input.updatedAt,
                        input.updatedAt,
                        input.targetUserId,
                        input.updatedAt
                    ]));
                }
            }
        }

        if (input.securityChanged) {
            statements.push(prepareStatement(this.#db, `
                UPDATE auth_refresh_sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ?
                    AND revoked_at IS NULL
                    AND EXISTS (
                        SELECT 1 FROM users WHERE id = ? AND updated_at = ? AND deleted_at IS NULL
                    )
            `, [input.revokedAt, input.targetUserId, input.targetUserId, input.updatedAt]));
        }

        if (input.concurrencyAdjustment !== undefined && input.concurrencyAdjustment.delta !== 0) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO redeem_codes (
                    code,
                    type,
                    value,
                    status,
                    used_at,
                    notes,
                    created_at,
                    validity_days,
                    used_by
                )
                SELECT ?, 'admin_concurrency', ?, 'used', ?, ?, ?, 0, ?
                WHERE EXISTS (
                    SELECT 1 FROM users WHERE id = ? AND updated_at = ? AND deleted_at IS NULL
                )
            `, [
                input.concurrencyAdjustment.code,
                input.concurrencyAdjustment.delta,
                input.updatedAt,
                `actor_admin_id=${input.concurrencyAdjustment.actorAdminId}`,
                input.updatedAt,
                input.targetUserId,
                input.targetUserId,
                input.updatedAt
            ]));
        }

        const results = await this.#db.batch(statements);
        requireBatchSuccess(results, "update user");
        return (results[0]?.results?.length ?? 0) === 1;
    }

    async findActiveUserIdByNormalizedEmail(email: string): Promise<number | null> {
        const row = await firstRow<{ id: number }>(this.#db, `
            SELECT id
            FROM users
            WHERE lower(trim(email)) = ? AND deleted_at IS NULL
        `, [email.trim().toLowerCase()]);
        return row?.id ?? null;
    }
}

function oauthChannel(identity: {
    metadata: Record<string, unknown>;
}): { channel: string; appId: string; subject: string; metadata: Record<string, unknown> } | null {
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

function guardedStatement(
    db: D1Database,
    mutationSql: string,
    values: readonly (string | number | null)[],
    userId: number,
    updatedAt: string
): D1PreparedStatement {
    const normalized = mutationSql.trim().replace(/;$/u, "");
    const guarded = normalized.replace(/\s*$/u, `
        AND EXISTS (
            SELECT 1 FROM users WHERE id = ? AND updated_at = ? AND deleted_at IS NULL
        )
    `);
    return prepareStatement(db, guarded, [...values, userId, updatedAt]);
}

function uniquePositiveIntegers(values: readonly number[]): number[] {
    return [...new Set(values)].filter((value) => Number.isSafeInteger(value) && value > 0);
}

function changed(result: D1Result | undefined): number {
    return result?.meta?.changes ?? 0;
}

function oauthCreationGuard(): string {
    return `
        SELECT 1 FROM pending_auth_sessions
        WHERE id = ?
            AND json_extract(local_flow_state, '$.__finalization_nonce') = ?
    `;
}

function requireBatchSuccess(results: D1Result[], operation: string): void {
    results.forEach((result, index) => {
        requireSuccess(result, `${operation} statement ${index + 1} failed`);
    });
}
