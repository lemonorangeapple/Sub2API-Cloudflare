import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1PendingAuthRepository } from "../src/repositories/pending-auth.ts";
import { D1UserManagementRepository } from "../src/repositories/user-management.ts";
import { D1PendingAuthService, PendingAuthError } from "../src/services/pending-auth.ts";
import { sha256Hex } from "../src/utils/crypto.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql",
    "0006_user_email_integrity.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

const FIXED_NOW = Date.parse("2026-07-16T08:00:00.000Z");

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

test("pending OAuth sessions hash opaque tokens and atomically sanitize one-time completion", async () => {
    const db = createDatabase();
    let now = FIXED_NOW;
    const repository = new D1PendingAuthRepository(db);
    const tokens = ["completion-token", "race-token"];
    const service = new D1PendingAuthService(repository, {
        clock: () => now,
        opaqueTokenFactory: () => tokens.shift() ?? "fallback-token"
    });
    const created = await service.create({
        sessionToken: "browser-session-token",
        intent: "login",
        providerType: "linuxdo",
        providerKey: "linuxdo",
        providerSubject: "subject-1",
        browserSessionKey: "browser-1",
        upstreamIdentityClaims: { id: 1, username: "upstream" },
        localFlowState: {
            completion_response: {
                access_token: "must-disappear",
                refresh_token: "must-disappear",
                expires_in: 3600,
                token_type: "Bearer",
                next: "/dashboard"
            }
        }
    });
    assert.equal(created.sessionToken, "browser-session-token");
    assert.equal(created.session.sessionTokenHash, await sha256Hex("browser-session-token"));
    assert.notEqual(created.session.sessionTokenHash, "browser-session-token");
    await assert.rejects(
        service.getBrowserSession(created.sessionToken, "wrong-browser"),
        (error) => error instanceof PendingAuthError && error.code === "pending_auth_browser_mismatch"
    );

    const completion = await service.issueCompletionCode(created.session.id, "browser-1");
    assert.equal(completion.code, "completion-token");
    const storedBefore = await db.prepare(`
        SELECT session_token, completion_code_hash FROM pending_auth_sessions WHERE id = ?
    `).bind(created.session.id).first();
    assert.equal(storedBefore.session_token, await sha256Hex("browser-session-token"));
    assert.equal(storedBefore.completion_code_hash, await sha256Hex("completion-token"));
    assert.doesNotMatch(JSON.stringify(storedBefore), /browser-session-token|completion-token/u);

    const consumed = await service.consumeCompletionCode(completion.code, "browser-1");
    assert.notEqual(consumed.consumedAt, null);
    assert.deepEqual(consumed.localFlowState.completion_response, { next: "/dashboard" });
    assert.equal(consumed.completionCodeHash, "");
    await assert.rejects(
        service.consumeBrowserSession(created.sessionToken, "browser-1"),
        (error) => error instanceof PendingAuthError && error.code === "pending_auth_session_consumed"
    );

    const race = await service.create({
        sessionToken: "race-session",
        intent: "bind_current_user",
        providerType: "oidc",
        providerKey: "issuer-client",
        providerSubject: "subject-2"
    });
    const results = await Promise.allSettled([
        service.consumeBrowserSession(race.sessionToken),
        service.consumeBrowserSession(race.sessionToken)
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(results.filter((result) => result.status === "rejected").length, 1);

    const expiring = await service.create({
        sessionToken: "expiring-session",
        intent: "login",
        providerType: "wechat",
        providerKey: "wechat-open",
        providerSubject: "subject-3",
        expiresAt: now + 100
    });
    now += 101;
    await assert.rejects(
        service.consumeBrowserSession(expiring.sessionToken),
        (error) => error instanceof PendingAuthError && error.code === "pending_auth_session_expired"
    );
    db.close();
});

test("identity adoption upsert is unique per pending session and reassigns an identity atomically", async () => {
    const db = createDatabase();
    let sequence = 0;
    const repository = new D1PendingAuthRepository(db);
    const service = new D1PendingAuthService(repository, {
        clock: () => FIXED_NOW + sequence++,
        opaqueTokenFactory: () => `token-${sequence}`
    });
    const users = new D1UserManagementRepository(db);
    const userId = await users.createUser({
        email: "adoption@example.com",
        passwordHash: "hash:password",
        role: "user",
        username: "",
        notes: "",
        balance: 0,
        concurrency: 1,
        rpmLimit: 0,
        status: "active",
        signupSource: "email",
        allowedGroups: [],
        groupRates: new Map(),
        defaultSubscriptions: [],
        createdAt: new Date(FIXED_NOW).toISOString()
    });
    const identity = await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key,
            provider_subject, verified_at, issuer, metadata, user_id
        ) VALUES (?, ?, 'linuxdo', 'linuxdo', 'subject-adoption', ?, NULL, '{}', ?)
        RETURNING id
    `).bind(
        new Date(FIXED_NOW).toISOString(),
        new Date(FIXED_NOW).toISOString(),
        new Date(FIXED_NOW).toISOString(),
        userId
    ).first();
    const first = await service.create({
        intent: "adopt_existing_user_by_email",
        providerType: "linuxdo",
        providerKey: "linuxdo",
        providerSubject: "subject-adoption"
    });
    const second = await service.create({
        intent: "adopt_existing_user_by_email",
        providerType: "linuxdo",
        providerKey: "linuxdo",
        providerSubject: "subject-adoption"
    });

    const initial = await service.upsertAdoptionDecision({
        pendingAuthSessionId: first.session.id,
        identityId: identity.id,
        adoptDisplayName: true,
        adoptAvatar: false
    });
    assert.equal(initial.identityId, identity.id);
    const replacement = await service.upsertAdoptionDecision({
        pendingAuthSessionId: second.session.id,
        identityId: identity.id,
        adoptDisplayName: false,
        adoptAvatar: true
    });
    assert.equal(replacement.identityId, identity.id);
    assert.equal((await db.prepare(`
        SELECT identity_id FROM identity_adoption_decisions WHERE pending_auth_session_id = ?
    `).bind(first.session.id).first()).identity_id, null);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM identity_adoption_decisions
        WHERE pending_auth_session_id = ?
    `).bind(second.session.id).first()).count, 1);
    db.close();
});
