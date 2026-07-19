import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1PendingAuthRepository } from "../src/repositories/pending-auth.ts";
import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import {
    routeStagedPendingOAuth,
    STAGED_PENDING_OAUTH_PATHS
} from "../src/router/staged-pending-oauth.ts";
import { routeStagedAuth, STAGED_AUTH_PATHS } from "../src/router/staged-auth.ts";
import { D1PendingAuthService } from "../src/services/pending-auth.ts";
import { verificationStateKey } from "../src/services/email-task-producer.ts";
import { AesGcmTotpSecretDecryptor } from "../src/services/totp.ts";
import { sha256Hex } from "../src/utils/crypto.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql",
    "0006_user_email_integrity.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const NOW = Date.parse("2026-07-16T06:00:00.000Z");
const NOW_ISO = new Date(NOW).toISOString();
const JWT_SECRET = "pending-oauth-route-secret-that-is-at-least-32-bytes";
const TOTP_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertUser(db, email, username = "") {
    const result = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, signup_source, token_version
        ) VALUES (?, ?, ?, 'test-password-hash', 'user', 'active', ?, 'email', 0)
    `).bind(NOW_ISO, NOW_ISO, email, username).run();
    return result.meta.last_row_id;
}

async function insertIdentity(db, userId, subject) {
    await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key,
            provider_subject, metadata, user_id
        ) VALUES (?, ?, 'linuxdo', 'linuxdo', ?, '{}', ?)
    `).bind(NOW_ISO, NOW_ISO, subject, userId).run();
}

async function createPending(db, overrides = {}) {
    const token = overrides.token ?? "pending-session-token";
    const browser = overrides.browser ?? "pending-browser-key";
    const providerType = overrides.providerType ?? "linuxdo";
    const providerKey = overrides.providerKey ?? providerType;
    const subject = overrides.subject ?? "member_42";
    const created = await new D1PendingAuthService(new D1PendingAuthRepository(db), {
        clock: () => NOW,
        opaqueTokenFactory: () => token
    }).create({
        intent: overrides.intent ?? "login",
        providerType,
        providerKey,
        providerSubject: subject,
        ...(overrides.targetUserId ? { targetUserId: overrides.targetUserId } : {}),
        redirectTo: "/dashboard",
        resolvedEmail: overrides.email ?? `${providerType}-${subject}@${providerType}-connect.invalid`,
        browserSessionKey: browser,
        upstreamIdentityClaims: {
            username: "Provider Initial Name",
            suggested_display_name: "Provider Name",
            suggested_avatar_url: "https://cdn.example/avatar.png"
        },
        localFlowState: {
            completion_response: overrides.completion ?? { redirect: "/dashboard" },
            ...(overrides.localFlowState ?? {})
        }
    });
    return { ...created, token, browser };
}

async function configureRegistration(db, overrides = {}) {
    const values = {
        registration_enabled: "true",
        backend_mode_enabled: "false",
        invitation_code_enabled: "false",
        promo_code_enabled: "true",
        default_balance: "1",
        default_concurrency: "5",
        default_user_rpm_limit: "9",
        default_subscriptions: "[]",
        default_platform_quotas: "{}",
        auth_source_default_linuxdo_grant_on_signup: "true",
        auth_source_default_linuxdo_balance: "7.5",
        auth_source_default_linuxdo_concurrency: "3",
        auth_source_default_linuxdo_subscriptions: "[]",
        auth_source_default_linuxdo_platform_quotas: "{}",
        ...overrides
    };
    for (const [key, value] of Object.entries(values)) {
        await db.prepare(`
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        `).bind(key, value, NOW_ISO).run();
    }
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET,
        JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600",
        JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30",
        TOTP_ENCRYPTION_KEY: TOTP_KEY
    };
}

function request(path, pending, body = {}) {
    return new Request(`https://api.example${path}`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            cookie: `oauth_pending_session=${encodeURIComponent(pending.token)}; oauth_pending_browser_session=${encodeURIComponent(pending.browser)}`
        },
        body: JSON.stringify(body)
    });
}

async function data(response) {
    const body = await response.json();
    assert.equal(body.code, 0, JSON.stringify(body));
    return body.data;
}

const acceptingPassword = {
    async verify(password, hash) {
        return password === "correct-password" && hash === "test-password-hash";
    }
};

test("pending exchange finalizes an existing identity login and clears browser state", async () => {
    const db = createDatabase();
    const userId = await insertUser(db, "member@example.com", "Local Name");
    await insertIdentity(db, userId, "member_42");
    const pending = await createPending(db, { targetUserId: userId });

    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.exchange, pending),
        env(db),
        { clock: () => NOW, nonceFactory: () => "exchange-nonce", passwordVerifier: acceptingPassword }
    );
    assert.equal(response.status, 200);
    const payload = await data(response);
    assert.match(payload.access_token, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u);
    assert.match(payload.refresh_token, /^rt_[a-f0-9]{64}$/u);
    assert.equal(payload.redirect, "/dashboard");
    assert.ok(response.headers.getSetCookie().some((value) => value.startsWith("oauth_pending_session=;")));
    assert.notEqual((await db.prepare(`
        SELECT consumed_at AS consumedAt FROM pending_auth_sessions WHERE id = ?
    `).bind(pending.session.id).first()).consumedAt, null);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_refresh_sessions`).first()).count, 1);
    assert.equal((await db.prepare(`SELECT username FROM users WHERE id = ?`).bind(userId).first()).username, "Local Name");
});

test("choice exchange keeps pending cookies and does not consume until the user decides", async () => {
    const db = createDatabase();
    const pending = await createPending(db, {
        targetUserId: undefined,
        completion: {
            step: "choose_account_action_required",
            adoption_required: true,
            existing_account_bindable: false
        }
    });
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.exchange, pending),
        env(db),
        { clock: () => NOW, nonceFactory: () => "choice-nonce", passwordVerifier: acceptingPassword }
    );
    const payload = await data(response);
    assert.equal(payload.step, "choose_account_action_required");
    assert.equal(response.headers.getSetCookie().length, 0);
    assert.equal((await db.prepare(`
        SELECT consumed_at AS consumedAt FROM pending_auth_sessions WHERE id = ?
    `).bind(pending.session.id).first()).consumedAt, null);
});

test("generic and provider aliases validate password, ownership, and provider", async () => {
    for (const [path, providerType] of [
        [STAGED_PENDING_OAUTH_PATHS.bindLogin, "linuxdo"],
        [STAGED_PENDING_OAUTH_PATHS.linuxdoBindLogin, "linuxdo"],
        [STAGED_PENDING_OAUTH_PATHS.oidcBindLogin, "oidc"],
        [STAGED_PENDING_OAUTH_PATHS.wechatBindLogin, "wechat"],
        [STAGED_PENDING_OAUTH_PATHS.dingtalkBindLogin, "dingtalk"]
    ]) {
        const db = createDatabase();
        const userId = await insertUser(db, "member@example.com", "Local Name");
        const pending = await createPending(db, {
            token: `token-${path}`,
            browser: `browser-${path}`,
            targetUserId: userId,
            intent: "login",
            providerType,
            providerKey: providerType === "oidc" ? "https://issuer.example" : providerType
        });
        const response = await routeStagedPendingOAuth(
            request(path, pending, {
                email: "member@example.com",
                password: "correct-password",
                adopt_display_name: false,
                adopt_avatar: true
            }),
            env(db),
            { clock: () => NOW, nonceFactory: () => `nonce-${path}`, passwordVerifier: acceptingPassword }
        );
        const payload = await data(response);
        assert.match(payload.access_token, /^[A-Za-z0-9_-]+\./u);
        assert.equal((await db.prepare(`SELECT user_id AS userId FROM auth_identities`).first()).userId, userId);
        assert.equal((await db.prepare(`SELECT username FROM users WHERE id = ?`).bind(userId).first()).username, "Local Name");
        assert.equal((await db.prepare(`SELECT url FROM user_avatars WHERE user_id = ?`).bind(userId).first()).url,
            "https://cdn.example/avatar.png");
    }
});

test("OIDC complete-registration atomically creates a synthetic identity account", async () => {
    const db = createDatabase();
    await configureRegistration(db, {
        auth_source_default_oidc_grant_on_signup: "true",
        auth_source_default_oidc_balance: "4.25",
        auth_source_default_oidc_concurrency: "2",
        auth_source_default_oidc_subscriptions: "[]",
        auth_source_default_oidc_platform_quotas: "{}"
    });
    const pending = await createPending(db, {
        token: "oidc-complete-token",
        browser: "oidc-complete-browser",
        providerType: "oidc",
        providerKey: "https://issuer.example",
        subject: "oidc-subject",
        completion: { error: "invitation_required" }
    });
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.oidcCompleteRegistration, pending, {
            adopt_display_name: true,
            adopt_avatar: false
        }),
        env(db),
        { clock: () => NOW, nonceFactory: () => "oidc-complete-nonce" }
    );
    const payload = await data(response);
    assert.match(payload.access_token, /^[A-Za-z0-9_-]+\./u);
    const user = await db.prepare(`
        SELECT email, username, balance, concurrency, signup_source AS signupSource FROM users
    `).first();
    assert.deepEqual({ ...user }, {
        email: "oidc-oidc-subject@oidc-connect.invalid",
        username: "Provider Name",
        balance: 4.25,
        concurrency: 2,
        signupSource: "oidc"
    });
    const identity = await db.prepare(`
        SELECT provider_type AS providerType, provider_key AS providerKey FROM auth_identities
    `).first();
    assert.deepEqual({ ...identity }, { providerType: "oidc", providerKey: "https://issuer.example" });
});

test("DingTalk complete-registration atomically creates its provider identity account", async () => {
    const db = createDatabase();
    await configureRegistration(db, {
        auth_source_default_dingtalk_grant_on_signup: "true",
        auth_source_default_dingtalk_balance: "2.75",
        auth_source_default_dingtalk_concurrency: "2",
        auth_source_default_dingtalk_subscriptions: "[]",
        auth_source_default_dingtalk_platform_quotas: "{}"
    });
    const pending = await createPending(db, {
        token: "dingtalk-complete-token",
        browser: "dingtalk-complete-browser",
        providerType: "dingtalk",
        providerKey: "dingtalk",
        subject: "ding-subject"
    });
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.dingtalkCompleteRegistration, pending, {
            adopt_display_name: true,
            adopt_avatar: false
        }),
        env(db),
        { clock: () => NOW, nonceFactory: () => "dingtalk-complete-nonce" }
    );
    const payload = await data(response);
    assert.ok(payload.access_token);
    const user = await db.prepare(`
        SELECT email, signup_source AS signupSource, balance, concurrency FROM users
    `).first();
    assert.deepEqual({ ...user }, {
        email: "dingtalk-ding-subject@dingtalk-connect.invalid",
        signupSource: "dingtalk",
        balance: 2.75,
        concurrency: 2
    });
    assert.equal((await db.prepare(`SELECT provider_type AS providerType FROM auth_identities`).first())
        .providerType, "dingtalk");
});

test("GitHub and Google complete-registration trust provider email but require a local password", async () => {
    for (const [providerType, path] of [
        ["github", STAGED_PENDING_OAUTH_PATHS.githubCompleteRegistration],
        ["google", STAGED_PENDING_OAUTH_PATHS.googleCompleteRegistration]
    ]) {
        const db = createDatabase();
        await configureRegistration(db, {
            [`auth_source_default_${providerType}_grant_on_signup`]: "true",
            [`auth_source_default_${providerType}_balance`]: "3.5",
            [`auth_source_default_${providerType}_concurrency`]: "2",
            [`auth_source_default_${providerType}_subscriptions`]: "[]",
            [`auth_source_default_${providerType}_platform_quotas`]: "{}"
        });
        const pending = await createPending(db, {
            token: `${providerType}-complete-token`,
            browser: `${providerType}-complete-browser`,
            providerType,
            providerKey: providerType,
            subject: `${providerType}-subject`,
            email: `${providerType}-verified@example.com`,
            completion: { error: "registration_completion_required" }
        });
        const response = await routeStagedPendingOAuth(
            request(path, pending, { password: "provider-password" }),
            env(db),
            { clock: () => NOW, nonceFactory: () => `${providerType}-complete-nonce` }
        );
        const payload = await data(response);
        assert.match(payload.access_token, /^[A-Za-z0-9_-]+\./u);
        const user = await db.prepare(`
            SELECT email, signup_source AS signupSource, balance, concurrency FROM users
        `).first();
        assert.deepEqual({ ...user }, {
            email: `${providerType}-verified@example.com`,
            signupSource: providerType,
            balance: 3.5,
            concurrency: 2
        });
        assert.equal((await db.prepare(`SELECT provider_type AS providerType FROM auth_identities`).first())
            .providerType, providerType);
    }
});

test("LinuxDo completion atomically creates one account, binds identity, and applies signup grants", async () => {
    const db = createDatabase();
    await configureRegistration(db);
    const pending = await createPending(db, {
        token: "linuxdo-create-token",
        browser: "linuxdo-create-browser",
        completion: { error: "invitation_required" }
    });
    const dependencies = {
        clock: () => NOW,
        nonceFactory: () => "linuxdo-create-nonce",
        passwordVerifier: acceptingPassword
    };
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.linuxdoCompleteRegistration, pending, {
            adopt_display_name: false,
            adopt_avatar: true
        }),
        env(db),
        dependencies
    );
    assert.equal(response.status, 200);
    const payload = await data(response);
    assert.match(payload.access_token, /^[A-Za-z0-9_-]+\./u);
    const user = await db.prepare(`
        SELECT email, username, balance, concurrency, rpm_limit AS rpmLimit, signup_source AS signupSource
        FROM users
    `).first();
    assert.deepEqual({ ...user }, {
        email: "linuxdo-member_42@linuxdo-connect.invalid",
        username: "Provider Initial Name",
        balance: 7.5,
        concurrency: 3,
        rpmLimit: 9,
        signupSource: "linuxdo"
    });
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_identities`).first()).count, 1);
    assert.equal((await db.prepare(`SELECT grant_reason AS reason FROM user_provider_default_grants`).first()).reason,
        "signup");
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_refresh_sessions`).first()).count, 1);

    const replay = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.linuxdoCompleteRegistration, pending),
        env(db),
        dependencies
    );
    assert.equal(replay.status, 401);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM users`).first()).count, 1);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM user_provider_default_grants`).first()).count, 1);
});

test("generic and OIDC create-account consume verification state in the guarded batch", async () => {
    for (const [path, providerType] of [
        [STAGED_PENDING_OAUTH_PATHS.createAccount, "linuxdo"],
        [STAGED_PENDING_OAUTH_PATHS.oidcCreateAccount, "oidc"]
    ]) {
        const db = createDatabase();
        await configureRegistration(db, { auth_source_default_linuxdo_grant_on_signup: "false" });
        const email = `new-${providerType}@example.com`;
        const verifyCode = "123456";
        const key = await verificationStateKey(email);
        await new D1ExpiringStateRepository(db, { clock: () => NOW }).put(key, {
            codeHash: await sha256Hex(verifyCode),
            secretEnvelope: "sealed",
            attempts: 0,
            createdAt: NOW
        }, 15 * 60 * 1000);
        const pending = await createPending(db, {
            token: `${providerType}-create-token`,
            browser: `${providerType}-create-browser`,
            providerType,
            providerKey: providerType === "oidc" ? "https://issuer.example" : providerType,
            completion: { step: "create_account_required" }
        });
        const response = await routeStagedPendingOAuth(
            request(path, pending, {
                email,
                password: "new-password",
                verify_code: verifyCode,
                adopt_display_name: true
            }),
            env(db),
            { clock: () => NOW, nonceFactory: () => `${providerType}-create-nonce` }
        );
        assert.equal(response.status, 200);
        await data(response);
        assert.equal((await db.prepare(`SELECT username FROM users`).first()).username, "Provider Name");
        assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM runtime_expiring_values WHERE state_key = ?`)
            .bind(key).first()).count, 0);
        assert.notEqual((await db.prepare(`
            SELECT consumed_at AS consumedAt FROM pending_auth_sessions
        `).first()).consumedAt, null);
    }
});

test("only a trusted DingTalk pending session can bypass disabled registration", async () => {
    const db = createDatabase();
    await configureRegistration(db, {
        registration_enabled: "false",
        auth_source_default_dingtalk_grant_on_signup: "false"
    });
    const rejected = await createPending(db, {
        token: "dingtalk-no-bypass-token",
        browser: "dingtalk-no-bypass-browser",
        providerType: "dingtalk",
        email: "dingtalk-no_bypass@dingtalk-connect.invalid"
    });
    const rejectedResponse = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.dingtalkCompleteRegistration, rejected),
        env(db),
        { clock: () => NOW, nonceFactory: () => "dingtalk-no-bypass-nonce" }
    );
    assert.equal(rejectedResponse.status, 403);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM users`).first()).count, 0);

    const allowed = await createPending(db, {
        token: "dingtalk-bypass-token",
        browser: "dingtalk-bypass-browser",
        providerType: "dingtalk",
        subject: "internal_member",
        email: "dingtalk-internal_member@dingtalk-connect.invalid",
        localFlowState: { registration_bypass_allowed: true }
    });
    const allowedResponse = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.dingtalkCompleteRegistration, allowed),
        env(db),
        { clock: () => NOW, nonceFactory: () => "dingtalk-bypass-nonce" }
    );
    assert.equal(allowedResponse.status, 200);
    await data(allowedResponse);
    assert.equal((await db.prepare(`SELECT signup_source AS source FROM users`).first()).source, "dingtalk");
});

test("wrong pending browser cannot create a user or consume verification state", async () => {
    const db = createDatabase();
    await configureRegistration(db);
    const pending = await createPending(db, {
        token: "wrong-browser-create-token",
        browser: "right-browser"
    });
    const wrong = { ...pending, browser: "wrong-browser" };
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.linuxdoCompleteRegistration, wrong),
        env(db),
        { clock: () => NOW, nonceFactory: () => "wrong-browser-nonce" }
    );
    assert.equal(response.status, 401);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM users`).first()).count, 0);
    assert.equal((await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first()).consumedAt,
        null);
});

test("competing OAuth identity owner rejects new account without consuming pending state", async () => {
    const db = createDatabase();
    await configureRegistration(db);
    const ownerId = await insertUser(db, "identity-owner@example.com");
    await insertIdentity(db, ownerId, "member_42");
    const pending = await createPending(db, {
        token: "identity-conflict-token",
        browser: "identity-conflict-browser"
    });
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.linuxdoCompleteRegistration, pending),
        env(db),
        { clock: () => NOW, nonceFactory: () => "identity-conflict-nonce" }
    );
    assert.equal(response.status, 409);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM users`).first()).count, 1);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_identities`).first()).count, 1);
    assert.equal((await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first()).consumedAt,
        null);
});

test("pending verification queues a Worker email task without storing the plaintext code", async () => {
    const db = createDatabase();
    await configureRegistration(db, { site_name: "Pending OAuth Test" });
    const pending = await createPending(db, {
        token: "pending-email-token",
        browser: "pending-email-browser"
    });
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.sendVerifyCode, pending, {
            email: "pending-new@example.com"
        }),
        env(db),
        {
            clock: () => NOW,
            verificationCodeFactory: () => "654321",
            emailCipher: {
                async seal() { return "sealed-code"; },
                async open() { return "654321"; }
            }
        }
    );
    assert.equal(response.status, 200);
    assert.equal((await data(response)).countdown, 60);
    const task = await db.prepare(`SELECT payload_json AS payload FROM runtime_tasks WHERE queue_name = 'email'`).first();
    assert.doesNotMatch(task.payload, /654321/u);
    const state = await db.prepare(`SELECT value_json AS value FROM runtime_expiring_values`).first();
    assert.equal(JSON.parse(state.value).secretEnvelope, "sealed-code");
});

test("pending verification transitions an existing email to account choice without sending mail", async () => {
    const db = createDatabase();
    await configureRegistration(db);
    const userId = await insertUser(db, "existing-choice@example.com");
    const pending = await createPending(db, {
        token: "existing-choice-token",
        browser: "existing-choice-browser"
    });
    const response = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.sendVerifyCode, pending, {
            email: "existing-choice@example.com"
        }),
        env(db),
        { clock: () => NOW }
    );
    assert.equal(response.status, 200);
    const payload = await data(response);
    assert.equal(payload.step, "choose_account_action_required");
    assert.equal(payload.existing_account_bindable, true);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM runtime_tasks`).first()).count, 0);
    const updated = await db.prepare(`
        SELECT target_user_id AS targetUserId, resolved_email AS email, consumed_at AS consumedAt
        FROM pending_auth_sessions WHERE id = ?
    `).bind(pending.session.id).first();
    assert.deepEqual({ ...updated }, { targetUserId: userId, email: "existing-choice@example.com", consumedAt: null });
});

test("pending bind-login completes identity binding only after one-time TOTP verification", async () => {
    const db = createDatabase();
    await configureRegistration(db, {
        totp_enabled: "true",
        auth_source_default_linuxdo_grant_on_first_bind: "true"
    });
    const userId = await insertUser(db, "totp-bind@example.com", "Local TOTP Name");
    const encryptedSecret = await new AesGcmTotpSecretDecryptor(TOTP_KEY).encrypt(TOTP_SECRET);
    await db.prepare(`
        UPDATE users SET totp_enabled = 1, totp_secret_encrypted = ? WHERE id = ?
    `).bind(encryptedSecret, userId).run();
    const pending = await createPending(db, {
        token: "totp-pending-token",
        browser: "totp-pending-browser",
        targetUserId: userId
    });
    const bind = await routeStagedPendingOAuth(
        request(STAGED_PENDING_OAUTH_PATHS.bindLogin, pending, {
            email: "totp-bind@example.com",
            password: "correct-password",
            adopt_display_name: false,
            adopt_avatar: true
        }),
        env(db),
        { clock: () => NOW, passwordVerifier: acceptingPassword, nonceFactory: () => "totp-bind-nonce" }
    );
    const challenge = await data(bind);
    assert.equal(challenge.requires_2fa, true);
    assert.match(challenge.temp_token, /^[a-f0-9]{64}$/u);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_identities`).first()).count, 0);
    assert.equal((await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first()).consumedAt,
        null);

    const correctCode = await totpCode(TOTP_SECRET, NOW);
    const wrongCode = `${correctCode[0] === "0" ? "1" : "0"}${correctCode.slice(1)}`;
    const rejected = await routeStagedAuth(new Request(`https://api.example${STAGED_AUTH_PATHS.login2fa}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ temp_token: challenge.temp_token, totp_code: wrongCode })
    }), env(db), { clock: () => NOW });
    assert.equal(rejected.status, 400);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_identities`).first()).count, 0);
    assert.equal((await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first()).consumedAt,
        null);

    const complete = await routeStagedAuth(new Request(`https://api.example${STAGED_AUTH_PATHS.login2fa}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            temp_token: challenge.temp_token,
            totp_code: correctCode
        })
    }), env(db), { clock: () => NOW });
    assert.equal(complete.status, 200);
    const payload = await data(complete);
    assert.match(payload.access_token, /^[A-Za-z0-9_-]+\./u);
    assert.equal((await db.prepare(`SELECT user_id AS userId FROM auth_identities`).first()).userId, userId);
    assert.notEqual((await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first()).consumedAt,
        null);
    assert.equal((await db.prepare(`SELECT url FROM user_avatars WHERE user_id = ?`).bind(userId).first()).url,
        "https://cdn.example/avatar.png");
    assert.ok(complete.headers.getSetCookie().some((value) => value.startsWith("oauth_pending_session=;")));

    const replay = await routeStagedAuth(new Request(`https://api.example${STAGED_AUTH_PATHS.login2fa}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            temp_token: challenge.temp_token,
            totp_code: correctCode
        })
    }), env(db), { clock: () => NOW });
    assert.equal(replay.status, 400);
});

async function totpCode(secret, nowMs) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const character of secret.replace(/=+$/u, "")) {
        bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
    }
    const bytes = Uint8Array.from(bits.match(/.{8}/gu)?.map((value) => Number.parseInt(value, 2)) ?? []);
    const counter = Math.floor(nowMs / 30_000);
    const message = new Uint8Array(8);
    new DataView(message.buffer).setBigUint64(0, BigInt(counter));
    const key = await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
    const offset = digest[digest.length - 1] & 15;
    const value = ((digest[offset] & 127) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3];
    return String(value % 1_000_000).padStart(6, "0");
}
