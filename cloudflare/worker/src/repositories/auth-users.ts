import type { AuthIdentityRecord, AuthUserRecord } from "../types/auth.ts";
import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

interface AuthUserRow {
    id: number;
    email: string;
    passwordHash: string;
    role: string;
    status: string;
    username: string;
    notes: string;
    balance: number;
    frozenBalance: number;
    concurrency: number;
    createdAt: string;
    updatedAt: string;
    deletedAt: string | null;
    lastLoginAt: string | null;
    lastActiveAt: string | null;
    balanceNotifyEnabled: number;
    balanceNotifyThresholdType: string;
    balanceNotifyThreshold: number | null;
    balanceNotifyExtraEmails: string;
    totalRecharged: number;
    rpmLimit: number;
    totpEnabled: number;
    totpEnabledAt: string | null;
    totpSecretEncrypted: string | null;
    tokenVersion: number | string;
    signupSource: string;
    avatarUrl: string;
}

interface AllowedGroupRow {
    groupId: number;
}

interface GroupRateRow {
    groupId: number;
    rateMultiplier: number;
}

interface AuthIdentityRow {
    providerType: string;
    providerKey: string;
    providerSubject: string;
    verifiedAt: string | null;
    issuer: string | null;
    metadata: string;
    createdAt: string;
    updatedAt: string;
}

export class DuplicateNormalizedEmailError extends Error {
    constructor() {
        super("normalized email lookup matched multiple users");
        this.name = "DuplicateNormalizedEmailError";
    }
}

export class D1AuthUserRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async findByEmail(emailValue: string): Promise<AuthUserRecord | null> {
        const email = emailValue.trim().toLowerCase();
        const matches = await this.#queryUsers(
            "lower(trim(u.email)) = ?",
            [email],
            2
        );
        if (matches.length === 0) {
            return null;
        }
        if (matches.length > 1) {
            throw new DuplicateNormalizedEmailError();
        }
        return this.#hydrate(matches[0]);
    }

    async findById(userId: number): Promise<AuthUserRecord | null> {
        if (!Number.isSafeInteger(userId) || userId <= 0) {
            return null;
        }
        const matches = await this.#queryUsers("u.id = ?", [userId], 1);
        return matches.length === 0 ? null : this.#hydrate(matches[0]);
    }

    async findByIdentity(
        providerTypeValue: string,
        providerKeyValue: string,
        providerSubjectValue: string
    ): Promise<AuthUserRecord | null> {
        const providerType = providerTypeValue.trim().toLowerCase();
        const providerKey = providerKeyValue.trim();
        const providerSubject = providerSubjectValue.trim();
        if (providerType === "" || providerKey === "" || providerSubject === "") {
            return null;
        }
        const matches = await this.#queryUsers(`EXISTS (
            SELECT 1
            FROM auth_identities AS identity
            WHERE identity.user_id = u.id
                AND identity.provider_type = ?
                AND identity.provider_key = ?
                AND identity.provider_subject = ?
        )`, [providerType, providerKey, providerSubject], 2);
        if (matches.length === 0) return null;
        if (matches.length > 1) {
            throw new Error("auth identity belongs to multiple users");
        }
        return this.#hydrate(matches[0]);
    }

    async findByWeChatIdentity(
        providerSubjectValue: string,
        channelValue: string,
        channelAppIdValue: string,
        channelSubjectValue: string
    ): Promise<AuthUserRecord | null> {
        const providerSubject = providerSubjectValue.trim();
        const channel = channelValue.trim().toLowerCase();
        const channelAppId = channelAppIdValue.trim();
        const channelSubject = channelSubjectValue.trim();
        if (providerSubject === "" || channel === "" || channelAppId === "" || channelSubject === "") {
            return null;
        }
        const matches = await this.#queryUsers(`(
            EXISTS (
                SELECT 1
                FROM auth_identities AS identity
                WHERE identity.user_id = u.id
                    AND identity.provider_type = 'wechat'
                    AND identity.provider_key IN ('wechat-main', 'wechat')
                    AND identity.provider_subject = ?
            )
            OR EXISTS (
                SELECT 1
                FROM auth_identity_channels AS identity_channel
                JOIN auth_identities AS identity ON identity.id = identity_channel.identity_id
                WHERE identity.user_id = u.id
                    AND identity_channel.provider_type = 'wechat'
                    AND identity_channel.provider_key IN ('wechat-main', 'wechat')
                    AND identity_channel.channel = ?
                    AND identity_channel.channel_app_id = ?
                    AND identity_channel.channel_subject = ?
            )
        )`, [providerSubject, channel, channelAppId, channelSubject], 2);
        if (matches.length === 0) return null;
        if (matches.length > 1) {
            throw new Error("wechat identity belongs to multiple users");
        }
        return this.#hydrate(matches[0]);
    }

    async listIdentities(userId: number): Promise<AuthIdentityRecord[]> {
        const rows = await allRows<AuthIdentityRow>(this.#db, `
            SELECT
                provider_type AS providerType,
                provider_key AS providerKey,
                provider_subject AS providerSubject,
                verified_at AS verifiedAt,
                issuer,
                metadata,
                created_at AS createdAt,
                updated_at AS updatedAt
            FROM auth_identities
            WHERE user_id = ?
            ORDER BY provider_type, created_at, id
        `, [userId]);
        return rows.map((row) => ({
            providerType: row.providerType,
            providerKey: row.providerKey,
            providerSubject: row.providerSubject,
            verifiedAt: row.verifiedAt,
            issuer: row.issuer,
            metadata: parseObject(row.metadata),
            createdAt: row.createdAt,
            updatedAt: row.updatedAt
        }));
    }

    async countActiveAdmins(): Promise<number> {
        const row = await firstRow<{ count: number }>(this.#db, `
            SELECT COUNT(*) AS count
            FROM users
            WHERE deleted_at IS NULL
                AND role = 'admin'
                AND status = 'active'
        `);
        return row?.count ?? 0;
    }

    async recordSuccessfulLogin(userId: number, now: string): Promise<void> {
        await runStatement(this.#db, `
            UPDATE users
            SET last_login_at = ?, last_active_at = ?, updated_at = ?
            WHERE id = ? AND deleted_at IS NULL
        `, [now, now, now, userId]);
    }

    async incrementTokenVersion(userId: number, now: string): Promise<bigint | null> {
        const row = await firstRow<{ tokenVersion: number | string }>(this.#db, `
            UPDATE users
            SET token_version = token_version + 1, updated_at = ?
            WHERE id = ? AND deleted_at IS NULL
            RETURNING token_version AS tokenVersion
        `, [now, userId]);
        return row === null ? null : BigInt(row.tokenVersion);
    }

    async #queryUsers(whereSQL: string, values: readonly D1Value[], limit: number): Promise<AuthUserRow[]> {
        return allRows<AuthUserRow>(this.#db, `
            SELECT
                u.id,
                u.email,
                u.password_hash AS passwordHash,
                u.role,
                u.status,
                u.username,
                u.notes,
                u.balance,
                u.frozen_balance AS frozenBalance,
                u.concurrency,
                u.created_at AS createdAt,
                u.updated_at AS updatedAt,
                u.deleted_at AS deletedAt,
                u.last_login_at AS lastLoginAt,
                u.last_active_at AS lastActiveAt,
                u.balance_notify_enabled AS balanceNotifyEnabled,
                u.balance_notify_threshold_type AS balanceNotifyThresholdType,
                u.balance_notify_threshold AS balanceNotifyThreshold,
                u.balance_notify_extra_emails AS balanceNotifyExtraEmails,
                u.total_recharged AS totalRecharged,
                u.rpm_limit AS rpmLimit,
                u.totp_enabled AS totpEnabled,
                u.totp_enabled_at AS totpEnabledAt,
                u.totp_secret_encrypted AS totpSecretEncrypted,
                u.token_version AS tokenVersion,
                u.signup_source AS signupSource,
                COALESCE((
                    SELECT avatar.url
                    FROM user_avatars AS avatar
                    WHERE avatar.user_id = u.id
                    ORDER BY avatar.id
                    LIMIT 1
                ), '') AS avatarUrl
            FROM users AS u
            WHERE u.deleted_at IS NULL AND ${whereSQL}
            ORDER BY u.id
            LIMIT ${limit}
        `, values);
    }

    async #hydrate(row: AuthUserRow): Promise<AuthUserRecord> {
        const allowedGroupRows = await allRows<AllowedGroupRow>(this.#db, `
            SELECT group_id AS groupId
            FROM user_allowed_groups
            WHERE user_id = ?
            ORDER BY group_id
        `, [row.id]);
        const groupRateRows = await allRows<GroupRateRow>(this.#db, `
            SELECT group_id AS groupId, rate_multiplier AS rateMultiplier
            FROM user_group_rate_multipliers
            WHERE user_id = ? AND rate_multiplier IS NOT NULL
            ORDER BY group_id
        `, [row.id]);
        return {
            id: row.id,
            email: row.email,
            passwordHash: row.passwordHash,
            role: row.role,
            status: row.status,
            username: row.username,
            notes: row.notes,
            balance: row.balance,
            frozenBalance: row.frozenBalance,
            concurrency: row.concurrency,
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
            deletedAt: row.deletedAt,
            lastLoginAt: row.lastLoginAt,
            lastActiveAt: row.lastActiveAt,
            balanceNotifyEnabled: row.balanceNotifyEnabled !== 0,
            balanceNotifyThresholdType: row.balanceNotifyThresholdType,
            balanceNotifyThreshold: row.balanceNotifyThreshold,
            balanceNotifyExtraEmails: parseArray(row.balanceNotifyExtraEmails),
            totalRecharged: row.totalRecharged,
            rpmLimit: row.rpmLimit,
            totpEnabled: row.totpEnabled !== 0,
            totpEnabledAt: row.totpEnabledAt,
            totpSecretEncrypted: row.totpSecretEncrypted,
            tokenVersion: BigInt(row.tokenVersion),
            signupSource: row.signupSource,
            allowedGroups: allowedGroupRows.length === 0
                ? null
                : allowedGroupRows.map((item) => item.groupId),
            groupRates: Object.fromEntries(
                groupRateRows.map((item) => [String(item.groupId), item.rateMultiplier])
            ),
            avatarUrl: row.avatarUrl
        };
    }
}

function parseArray(raw: string): unknown[] {
    try {
        const parsed: unknown = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function parseObject(raw: string): Record<string, unknown> {
    try {
        const parsed: unknown = JSON.parse(raw);
        return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
            ? parsed as Record<string, unknown>
            : {};
    } catch {
        return {};
    }
}
