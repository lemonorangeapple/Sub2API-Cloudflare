import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1OAuthFinalizationRepository, OAuthFinalizationRejectedError } from "../src/repositories/oauth-finalization.ts";
import { D1PendingAuthRepository } from "../src/repositories/pending-auth.ts";
import { D1PendingAuthService } from "../src/services/pending-auth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const NOW = Date.parse("2026-07-16T04:00:00.000Z");
const NOW_ISO = new Date(NOW).toISOString();

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertUser(db, email) {
    const result = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, signup_source, balance, concurrency
        ) VALUES (?, ?, ?, 'unused', 'user', 'active', '', 'email', 0, 5)
    `).bind(NOW_ISO, NOW_ISO, email).run();
    return result.meta.last_row_id;
}

async function createPending(db, userId, browser, token) {
    return new D1PendingAuthService(new D1PendingAuthRepository(db), {
        clock: () => NOW,
        opaqueTokenFactory: () => token
    }).create({
        intent: "bind_current_user",
        providerType: "linuxdo",
        providerKey: "linuxdo",
        providerSubject: "member_42",
        targetUserId: userId,
        resolvedEmail: "linuxdo-member_42@linuxdo-connect.invalid",
        browserSessionKey: browser,
        upstreamIdentityClaims: {
            suggested_display_name: "Member Name",
            suggested_avatar_url: "https://cdn.example/member.png"
        },
        localFlowState: { completion_response: { redirect: "/profile" } }
    });
}

function mutation(pendingSessionId, userId, browser, nonce) {
    return {
        pendingSessionId,
        browserSessionKey: browser,
        finalizationNonce: nonce,
        userId,
        identity: {
            providerType: "linuxdo",
            providerKey: "linuxdo",
            providerSubject: "member_42",
            issuer: null,
            metadata: { suggested_display_name: "Member Name" }
        },
        adoption: {
            adoptDisplayName: true,
            adoptAvatar: true,
            displayName: "Member Name",
            avatarUrl: "https://cdn.example/member.png"
        },
        completedAt: NOW_ISO,
        completedAtMs: NOW,
        recordLogin: true,
        firstBindGrant: {
            balance: 3.5,
            concurrency: 2,
            subscriptions: []
        }
    };
}

test("OAuth binding atomically consumes pending state, binds identity, adopts profile, and grants once", async () => {
    const db = createDatabase();
    const userId = await insertUser(db, "member@example.com");
    const pending = await createPending(db, userId, "browser-a", "session-token-a");
    const repository = new D1OAuthFinalizationRepository(db);

    await repository.completeBinding(mutation(pending.session.id, userId, "browser-a", "nonce-a"));

    const session = await db.prepare(`
        SELECT consumed_at AS consumedAt,
            json_extract(local_flow_state, '$.__finalization_nonce') AS nonce
        FROM pending_auth_sessions WHERE id = ?
    `).bind(pending.session.id).first();
    assert.equal(session.consumedAt, NOW_ISO);
    assert.equal(session.nonce, "nonce-a");
    const user = await db.prepare(`
        SELECT username, balance, concurrency, last_login_at AS lastLoginAt
        FROM users WHERE id = ?
    `).bind(userId).first();
    assert.deepEqual({ ...user }, {
        username: "Member Name",
        balance: 3.5,
        concurrency: 7,
        lastLoginAt: NOW_ISO
    });
    const identity = await db.prepare(`
        SELECT id, user_id AS userId, metadata FROM auth_identities
    `).first();
    assert.equal(identity.userId, userId);
    assert.equal(JSON.parse(identity.metadata).suggested_display_name, "Member Name");
    const decision = await db.prepare(`
        SELECT identity_id AS identityId, adopt_display_name AS display, adopt_avatar AS avatar
        FROM identity_adoption_decisions
    `).first();
    assert.deepEqual({ ...decision }, { identityId: identity.id, display: 1, avatar: 1 });
    assert.equal((await db.prepare(`SELECT url FROM user_avatars WHERE user_id = ?`).bind(userId).first()).url,
        "https://cdn.example/member.png");
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM user_provider_default_grants`).first()).count, 1);

    await assert.rejects(
        () => repository.completeBinding(mutation(pending.session.id, userId, "browser-a", "nonce-replay")),
        OAuthFinalizationRejectedError
    );
    const afterReplay = await db.prepare(`SELECT balance, concurrency FROM users WHERE id = ?`).bind(userId).first();
    assert.deepEqual({ ...afterReplay }, { balance: 3.5, concurrency: 7 });
});

test("wrong browser and competing identity owner cannot consume or partially mutate pending state", async () => {
    const db = createDatabase();
    const firstUserId = await insertUser(db, "first@example.com");
    const secondUserId = await insertUser(db, "second@example.com");
    const firstPending = await createPending(db, firstUserId, "browser-first", "session-first");
    const secondPending = await createPending(db, secondUserId, "browser-second", "session-second");
    const repository = new D1OAuthFinalizationRepository(db);

    await assert.rejects(
        () => repository.completeBinding(mutation(firstPending.session.id, firstUserId, "wrong-browser", "wrong")),
        OAuthFinalizationRejectedError
    );
    assert.equal((await db.prepare(`
        SELECT consumed_at AS consumedAt FROM pending_auth_sessions WHERE id = ?
    `).bind(firstPending.session.id).first()).consumedAt, null);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_identities`).first()).count, 0);

    await repository.completeBinding(mutation(firstPending.session.id, firstUserId, "browser-first", "winner"));
    await assert.rejects(
        () => repository.completeBinding(mutation(secondPending.session.id, secondUserId, "browser-second", "loser")),
        OAuthFinalizationRejectedError
    );
    assert.equal((await db.prepare(`
        SELECT consumed_at AS consumedAt FROM pending_auth_sessions WHERE id = ?
    `).bind(secondPending.session.id).first()).consumedAt, null);
    assert.equal((await db.prepare(`SELECT user_id AS userId FROM auth_identities`).first()).userId, firstUserId);
    assert.equal((await db.prepare(`SELECT username FROM users WHERE id = ?`).bind(secondUserId).first()).username, "");
});

test("a competing WeChat channel owner rejects the whole finalization batch", async () => {
    const db = createDatabase();
    const ownerId = await insertUser(db, "wechat-owner@example.com");
    const targetId = await insertUser(db, "wechat-target@example.com");
    const identity = await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key, provider_subject,
            verified_at, issuer, metadata, user_id
        ) VALUES (?, ?, 'wechat', 'wechat-main', 'owner-unionid', ?, NULL, '{}', ?)
    `).bind(NOW_ISO, NOW_ISO, NOW_ISO, ownerId).run();
    await db.prepare(`
        INSERT INTO auth_identity_channels (
            created_at, updated_at, provider_type, provider_key, channel,
            channel_app_id, channel_subject, metadata, identity_id
        ) VALUES (?, ?, 'wechat', 'wechat-main', 'open', 'open-app', 'shared-openid', '{}', ?)
    `).bind(NOW_ISO, NOW_ISO, identity.meta.last_row_id).run();
    const pending = await new D1PendingAuthService(new D1PendingAuthRepository(db), {
        clock: () => NOW,
        opaqueTokenFactory: () => "wechat-channel-conflict-token"
    }).create({
        intent: "bind_current_user",
        providerType: "wechat",
        providerKey: "wechat-main",
        providerSubject: "different-unionid",
        targetUserId: targetId,
        resolvedEmail: "wechat-different-unionid@wechat-connect.invalid",
        browserSessionKey: "wechat-channel-conflict-browser",
        upstreamIdentityClaims: {},
        localFlowState: { completion_response: { redirect: "/profile" } }
    });
    const repository = new D1OAuthFinalizationRepository(db);
    await assert.rejects(() => repository.completeBinding({
        pendingSessionId: pending.session.id,
        browserSessionKey: "wechat-channel-conflict-browser",
        finalizationNonce: "wechat-channel-conflict",
        userId: targetId,
        identity: {
            providerType: "wechat",
            providerKey: "wechat-main",
            providerSubject: "different-unionid",
            issuer: null,
            metadata: {
                channel: "open",
                channel_app_id: "open-app",
                channel_subject: "shared-openid"
            }
        },
        adoption: {
            adoptDisplayName: false,
            adoptAvatar: false,
            displayName: "",
            avatarUrl: ""
        },
        completedAt: NOW_ISO,
        completedAtMs: NOW,
        recordLogin: true
    }), OAuthFinalizationRejectedError);
    assert.equal((await db.prepare(`
        SELECT consumed_at AS consumedAt FROM pending_auth_sessions WHERE id = ?
    `).bind(pending.session.id).first()).consumedAt, null);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_identities WHERE provider_subject = 'different-unionid'
    `).first()).count, 0);
    assert.equal((await db.prepare(`SELECT last_login_at AS lastLoginAt FROM users WHERE id = ?`)
        .bind(targetId).first()).lastLoginAt, null);
});
