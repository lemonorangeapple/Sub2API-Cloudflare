import type { D1Database } from "../types/d1.ts";
import { firstRow, prepareStatement, requireSuccess } from "./d1.ts";

interface PendingAuthRow {
    id: number;
    createdAt: string;
    updatedAt: string;
    sessionToken: string;
    intent: string;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    targetUserId: number | null;
    redirectTo: string;
    resolvedEmail: string;
    registrationPasswordHash: string;
    upstreamIdentityClaims: string;
    localFlowState: string;
    browserSessionKey: string;
    completionCodeHash: string;
    completionCodeExpiresAt: string | null;
    emailVerifiedAt: string | null;
    passwordVerifiedAt: string | null;
    totpVerifiedAt: string | null;
    expiresAt: string;
    consumedAt: string | null;
}

export interface PendingAuthSessionRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    sessionTokenHash: string;
    intent: string;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    targetUserId: number | null;
    redirectTo: string;
    resolvedEmail: string;
    registrationPasswordHash: string;
    upstreamIdentityClaims: Record<string, unknown>;
    localFlowState: Record<string, unknown>;
    browserSessionKey: string;
    completionCodeHash: string;
    completionCodeExpiresAt: string | null;
    emailVerifiedAt: string | null;
    passwordVerifiedAt: string | null;
    totpVerifiedAt: string | null;
    expiresAt: string;
    consumedAt: string | null;
}

export interface CreatePendingAuthMutation {
    sessionTokenHash: string;
    intent: string;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    targetUserId: number | null;
    redirectTo: string;
    resolvedEmail: string;
    registrationPasswordHash: string;
    upstreamIdentityClaims: Record<string, unknown>;
    localFlowState: Record<string, unknown>;
    browserSessionKey: string;
    expiresAt: string;
    createdAt: string;
}

export interface IdentityAdoptionDecisionRecord {
    id: number;
    pendingAuthSessionId: number;
    identityId: number | null;
    adoptDisplayName: boolean;
    adoptAvatar: boolean;
    decidedAt: string;
}

interface AdoptionRow {
    id: number;
    pendingAuthSessionId: number;
    identityId: number | null;
    adoptDisplayName: number;
    adoptAvatar: number;
    decidedAt: string;
}

const PENDING_SELECT = `
    SELECT
        id,
        created_at AS createdAt,
        updated_at AS updatedAt,
        session_token AS sessionToken,
        intent,
        provider_type AS providerType,
        provider_key AS providerKey,
        provider_subject AS providerSubject,
        target_user_id AS targetUserId,
        redirect_to AS redirectTo,
        resolved_email AS resolvedEmail,
        registration_password_hash AS registrationPasswordHash,
        upstream_identity_claims AS upstreamIdentityClaims,
        local_flow_state AS localFlowState,
        browser_session_key AS browserSessionKey,
        completion_code_hash AS completionCodeHash,
        completion_code_expires_at AS completionCodeExpiresAt,
        email_verified_at AS emailVerifiedAt,
        password_verified_at AS passwordVerifiedAt,
        totp_verified_at AS totpVerifiedAt,
        expires_at AS expiresAt,
        consumed_at AS consumedAt
    FROM pending_auth_sessions
`;

export class D1PendingAuthRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async create(input: CreatePendingAuthMutation): Promise<PendingAuthSessionRecord> {
        const row = await firstRow<{ id: number }>(this.#db, `
            INSERT INTO pending_auth_sessions (
                created_at, updated_at, session_token, intent,
                provider_type, provider_key, provider_subject, target_user_id,
                redirect_to, resolved_email, registration_password_hash,
                upstream_identity_claims, local_flow_state, browser_session_key,
                completion_code_hash, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?)
            RETURNING id
        `, [
            input.createdAt,
            input.createdAt,
            input.sessionTokenHash,
            input.intent,
            input.providerType,
            input.providerKey,
            input.providerSubject,
            input.targetUserId,
            input.redirectTo,
            input.resolvedEmail,
            input.registrationPasswordHash,
            JSON.stringify(input.upstreamIdentityClaims),
            JSON.stringify(input.localFlowState),
            input.browserSessionKey,
            input.expiresAt
        ]);
        if (row === null) throw new Error("pending auth session was not created");
        const created = await this.findById(row.id);
        if (created === null) throw new Error("pending auth session disappeared after creation");
        return created;
    }

    async findById(id: number): Promise<PendingAuthSessionRecord | null> {
        return this.#find("id = ?", id);
    }

    async findBySessionTokenHash(tokenHash: string): Promise<PendingAuthSessionRecord | null> {
        return this.#find("session_token = ?", tokenHash);
    }

    async findByCompletionCodeHash(codeHash: string): Promise<PendingAuthSessionRecord | null> {
        return this.#find("completion_code_hash = ?", codeHash);
    }

    async issueCompletionCode(
        id: number,
        codeHash: string,
        browserSessionKey: string,
        expiresAt: string,
        updatedAt: string
    ): Promise<boolean> {
        const row = await firstRow<{ id: number }>(this.#db, `
            UPDATE pending_auth_sessions
            SET
                completion_code_hash = ?,
                completion_code_expires_at = ?,
                browser_session_key = CASE WHEN trim(?) = '' THEN browser_session_key ELSE ? END,
                updated_at = ?
            WHERE id = ?
            RETURNING id
        `, [codeHash, expiresAt, browserSessionKey, browserSessionKey, updatedAt, id]);
        return row !== null;
    }

    async consume(
        id: number,
        browserSessionKey: string,
        localFlowState: Record<string, unknown>,
        nowIso: string
    ): Promise<PendingAuthSessionRecord | null> {
        const row = await firstRow<PendingAuthRow>(this.#db, `
            UPDATE pending_auth_sessions
            SET
                consumed_at = ?,
                updated_at = ?,
                local_flow_state = ?,
                completion_code_hash = '',
                completion_code_expires_at = NULL
            WHERE id = ?
                AND consumed_at IS NULL
                AND expires_at >= ?
                AND (completion_code_expires_at IS NULL OR completion_code_expires_at >= ?)
                AND (trim(browser_session_key) = '' OR browser_session_key = ?)
            RETURNING
                id,
                created_at AS createdAt,
                updated_at AS updatedAt,
                session_token AS sessionToken,
                intent,
                provider_type AS providerType,
                provider_key AS providerKey,
                provider_subject AS providerSubject,
                target_user_id AS targetUserId,
                redirect_to AS redirectTo,
                resolved_email AS resolvedEmail,
                registration_password_hash AS registrationPasswordHash,
                upstream_identity_claims AS upstreamIdentityClaims,
                local_flow_state AS localFlowState,
                browser_session_key AS browserSessionKey,
                completion_code_hash AS completionCodeHash,
                completion_code_expires_at AS completionCodeExpiresAt,
                email_verified_at AS emailVerifiedAt,
                password_verified_at AS passwordVerifiedAt,
                totp_verified_at AS totpVerifiedAt,
                expires_at AS expiresAt,
                consumed_at AS consumedAt
        `, [
            nowIso,
            nowIso,
            JSON.stringify(localFlowState),
            id,
            nowIso,
            nowIso,
            browserSessionKey
        ]);
        return row === null ? null : mapPending(row);
    }

    async transitionAccountChoice(input: {
        id: number;
        browserSessionKey: string;
        email: string;
        targetUserId: number;
        localFlowState: Record<string, unknown>;
        updatedAt: string;
    }): Promise<PendingAuthSessionRecord | null> {
        const row = await firstRow<PendingAuthRow>(this.#db, `
            UPDATE pending_auth_sessions
            SET
                resolved_email = ?,
                target_user_id = ?,
                local_flow_state = ?,
                updated_at = ?
            WHERE id = ?
                AND intent = 'login'
                AND consumed_at IS NULL
                AND expires_at >= ?
                AND (trim(browser_session_key) = '' OR browser_session_key = ?)
            RETURNING
                id,
                created_at AS createdAt,
                updated_at AS updatedAt,
                session_token AS sessionToken,
                intent,
                provider_type AS providerType,
                provider_key AS providerKey,
                provider_subject AS providerSubject,
                target_user_id AS targetUserId,
                redirect_to AS redirectTo,
                resolved_email AS resolvedEmail,
                registration_password_hash AS registrationPasswordHash,
                upstream_identity_claims AS upstreamIdentityClaims,
                local_flow_state AS localFlowState,
                browser_session_key AS browserSessionKey,
                completion_code_hash AS completionCodeHash,
                completion_code_expires_at AS completionCodeExpiresAt,
                email_verified_at AS emailVerifiedAt,
                password_verified_at AS passwordVerifiedAt,
                totp_verified_at AS totpVerifiedAt,
                expires_at AS expiresAt,
                consumed_at AS consumedAt
        `, [
            input.email,
            input.targetUserId,
            JSON.stringify(input.localFlowState),
            input.updatedAt,
            input.id,
            input.updatedAt,
            input.browserSessionKey
        ]);
        return row === null ? null : mapPending(row);
    }

    async upsertAdoptionDecision(input: {
        pendingAuthSessionId: number;
        identityId: number | null;
        adoptDisplayName: boolean;
        adoptAvatar: boolean;
        decidedAt: string;
    }): Promise<IdentityAdoptionDecisionRecord> {
        const results = await this.#db.batch([
            prepareStatement(this.#db, `
                UPDATE identity_adoption_decisions
                SET identity_id = NULL, updated_at = ?
                WHERE identity_id = ? AND pending_auth_session_id <> ?
            `, [input.decidedAt, input.identityId, input.pendingAuthSessionId]),
            prepareStatement(this.#db, `
                INSERT INTO identity_adoption_decisions (
                    created_at, updated_at, adopt_display_name, adopt_avatar,
                    decided_at, identity_id, pending_auth_session_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(pending_auth_session_id) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    adopt_display_name = excluded.adopt_display_name,
                    adopt_avatar = excluded.adopt_avatar,
                    decided_at = excluded.decided_at,
                    identity_id = excluded.identity_id
            `, [
                input.decidedAt,
                input.decidedAt,
                input.adoptDisplayName ? 1 : 0,
                input.adoptAvatar ? 1 : 0,
                input.decidedAt,
                input.identityId,
                input.pendingAuthSessionId
            ])
        ]);
        results.forEach((result, index) => requireSuccess(result, `D1 adoption decision statement ${index + 1} failed`));
        const row = await firstRow<AdoptionRow>(this.#db, `
            SELECT
                id,
                pending_auth_session_id AS pendingAuthSessionId,
                identity_id AS identityId,
                adopt_display_name AS adoptDisplayName,
                adopt_avatar AS adoptAvatar,
                decided_at AS decidedAt
            FROM identity_adoption_decisions
            WHERE pending_auth_session_id = ?
        `, [input.pendingAuthSessionId]);
        if (row === null) throw new Error("identity adoption decision was not persisted");
        return {
            id: row.id,
            pendingAuthSessionId: row.pendingAuthSessionId,
            identityId: row.identityId,
            adoptDisplayName: row.adoptDisplayName !== 0,
            adoptAvatar: row.adoptAvatar !== 0,
            decidedAt: row.decidedAt
        };
    }

    async #find(whereSql: string, value: string | number): Promise<PendingAuthSessionRecord | null> {
        const row = await firstRow<PendingAuthRow>(this.#db, `${PENDING_SELECT} WHERE ${whereSql}`, [value]);
        return row === null ? null : mapPending(row);
    }
}

function mapPending(row: PendingAuthRow): PendingAuthSessionRecord {
    return {
        id: row.id,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
        sessionTokenHash: row.sessionToken,
        intent: row.intent,
        providerType: row.providerType,
        providerKey: row.providerKey,
        providerSubject: row.providerSubject,
        targetUserId: row.targetUserId,
        redirectTo: row.redirectTo,
        resolvedEmail: row.resolvedEmail,
        registrationPasswordHash: row.registrationPasswordHash,
        upstreamIdentityClaims: parseObject(row.upstreamIdentityClaims),
        localFlowState: parseObject(row.localFlowState),
        browserSessionKey: row.browserSessionKey,
        completionCodeHash: row.completionCodeHash,
        completionCodeExpiresAt: row.completionCodeExpiresAt,
        emailVerifiedAt: row.emailVerifiedAt,
        passwordVerifiedAt: row.passwordVerifiedAt,
        totpVerifiedAt: row.totpVerifiedAt,
        expiresAt: row.expiresAt,
        consumedAt: row.consumedAt
    };
}

function parseObject(value: string): Record<string, unknown> {
    try {
        const parsed: unknown = JSON.parse(value);
        return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
            ? parsed as Record<string, unknown>
            : {};
    } catch {
        return {};
    }
}
