import type { D1Database, D1PreparedStatement } from "../types/d1.ts";
import { allRows, firstRow, prepareStatement, requireSuccess } from "./d1.ts";

export interface AdminAuthIdentityCandidate {
    id: number;
    userId: number;
    providerKey: string;
    issuer: string | null;
    metadata: string;
}

export interface AdminAuthIdentityChannelCandidate {
    id: number;
    userId: number;
    metadata: string;
}

export interface AdminAuthIdentityMutation {
    userId: number;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    issuer: string | null;
    metadata: Record<string, unknown>;
    now: string;
    existingIdentityId: number | null;
    channel: {
        channel: string;
        appId: string;
        subject: string;
        metadata: Record<string, unknown>;
        existingId: number | null;
    } | null;
}

export interface AdminBoundAuthIdentityRecord {
    id: number;
    userId: number;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    verifiedAt: string | null;
    issuer: string | null;
    metadata: string;
    createdAt: string;
    updatedAt: string;
}

export class D1AdminAuthIdentityRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async identityCandidates(
        providerType: string,
        providerKeys: readonly string[],
        subject: string
    ): Promise<AdminAuthIdentityCandidate[]> {
        const placeholders = providerKeys.map(() => "?").join(", ");
        return allRows(this.#db, `
            SELECT id, user_id AS userId, provider_key AS providerKey, issuer, metadata
            FROM auth_identities
            WHERE provider_type = ? AND provider_key IN (${placeholders}) AND provider_subject = ?
            ORDER BY CASE provider_key WHEN 'wechat-main' THEN 0 WHEN 'wechat' THEN 2 ELSE 1 END, id
        `, [providerType, ...providerKeys, subject]);
    }

    async channelCandidates(
        providerType: string,
        providerKeys: readonly string[],
        channel: string,
        appId: string,
        subject: string
    ): Promise<AdminAuthIdentityChannelCandidate[]> {
        const placeholders = providerKeys.map(() => "?").join(", ");
        return allRows(this.#db, `
            SELECT identity_channel.id, identity.user_id AS userId, identity_channel.metadata
            FROM auth_identity_channels AS identity_channel
            JOIN auth_identities AS identity ON identity.id = identity_channel.identity_id
            WHERE identity_channel.provider_type = ?
                AND identity_channel.provider_key IN (${placeholders})
                AND identity_channel.channel = ?
                AND identity_channel.channel_app_id = ?
                AND identity_channel.channel_subject = ?
            ORDER BY identity_channel.id
        `, [providerType, ...providerKeys, channel, appId, subject]);
    }

    async bind(input: AdminAuthIdentityMutation): Promise<void> {
        const statements: D1PreparedStatement[] = [];
        if (input.existingIdentityId === null) {
            statements.push(prepareStatement(this.#db, `
                INSERT INTO auth_identities (
                    created_at, updated_at, provider_type, provider_key,
                    provider_subject, verified_at, issuer, metadata, user_id
                )
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
                WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL)
            `, [
                input.now, input.now, input.providerType, input.providerKey,
                input.providerSubject, input.now, input.issuer, JSON.stringify(input.metadata), input.userId,
                input.userId
            ]));
        } else {
            statements.push(prepareStatement(this.#db, `
                UPDATE auth_identities
                SET provider_key = ?, verified_at = ?, issuer = ?, metadata = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
            `, [
                input.providerKey, input.now, input.issuer, JSON.stringify(input.metadata), input.now,
                input.existingIdentityId, input.userId
            ]));
        }
        if (input.channel !== null) {
            if (input.channel.existingId === null) {
                statements.push(prepareStatement(this.#db, `
                    INSERT INTO auth_identity_channels (
                        created_at, updated_at, provider_type, provider_key,
                        channel, channel_app_id, channel_subject, metadata, identity_id
                    )
                    SELECT ?, ?, ?, ?, ?, ?, ?, ?, identity.id
                    FROM auth_identities AS identity
                    WHERE identity.provider_type = ? AND identity.provider_key = ?
                        AND identity.provider_subject = ? AND identity.user_id = ?
                `, [
                    input.now, input.now, input.providerType, input.providerKey,
                    input.channel.channel, input.channel.appId, input.channel.subject,
                    JSON.stringify(input.channel.metadata),
                    input.providerType, input.providerKey, input.providerSubject, input.userId
                ]));
            } else {
                statements.push(prepareStatement(this.#db, `
                    UPDATE auth_identity_channels
                    SET provider_key = ?, metadata = ?, updated_at = ?,
                        identity_id = (
                            SELECT id FROM auth_identities
                            WHERE provider_type = ? AND provider_key = ?
                                AND provider_subject = ? AND user_id = ?
                        )
                    WHERE id = ? AND EXISTS (
                        SELECT 1 FROM auth_identities
                        WHERE id = auth_identity_channels.identity_id AND user_id = ?
                    )
                `, [
                    input.providerKey, JSON.stringify(input.channel.metadata), input.now,
                    input.providerType, input.providerKey, input.providerSubject, input.userId,
                    input.channel.existingId, input.userId
                ]));
            }
        }
        const results = await this.#db.batch(statements);
        results.forEach((result, index) => requireSuccess(result, `D1 admin identity bind statement ${index + 1} failed`));
        if (results.some((result) => (result.meta?.changes ?? 0) !== 1)) {
            throw new Error("admin identity bind target changed");
        }
    }

    async boundIdentity(
        userId: number,
        providerType: string,
        providerKey: string,
        subject: string
    ): Promise<AdminBoundAuthIdentityRecord | null> {
        return firstRow(this.#db, `
            SELECT id, user_id AS userId, provider_type AS providerType,
                provider_key AS providerKey, provider_subject AS providerSubject,
                verified_at AS verifiedAt, issuer, metadata,
                created_at AS createdAt, updated_at AS updatedAt
            FROM auth_identities
            WHERE user_id = ? AND provider_type = ? AND provider_key = ? AND provider_subject = ?
        `, [userId, providerType, providerKey, subject]);
    }

    async boundChannel(identityId: number, channel: string, appId: string, subject: string) {
        return firstRow<{
            channel: string;
            appId: string;
            subject: string;
            metadata: string;
            createdAt: string;
            updatedAt: string;
        }>(this.#db, `
            SELECT channel, channel_app_id AS appId, channel_subject AS subject,
                metadata, created_at AS createdAt, updated_at AS updatedAt
            FROM auth_identity_channels
            WHERE identity_id = ? AND channel = ? AND channel_app_id = ? AND channel_subject = ?
        `, [identityId, channel, appId, subject]);
    }
}
