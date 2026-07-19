import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1AuthSessionRepository } from "../src/repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../src/repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import { D1UserManagementRepository } from "../src/repositories/user-management.ts";
import { routeRequest } from "../src/index.ts";
import { routeStagedSecurity } from "../src/router/staged-security.ts";
import { routeStagedUserDomain } from "../src/router/staged-user-domain.ts";
import { AuthTokenService } from "../src/services/auth-tokens.ts";
import { AesGcmEmailSecretCipher, verificationStateKey } from "../src/services/email-task-producer.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { D1UserManagementService } from "../src/services/user-management.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql",
    "0006_user_email_integrity.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const indexSource = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");

const FIXED_NOW = Date.parse("2026-07-15T12:00:00.000Z");
const JWT_SECRET = "user-domain-test-jwt-secret-that-is-at-least-32-bytes";
const EMAIL_KEY = "11".repeat(32);
const RESET_TOKEN = "ab".repeat(32);

const passwordHasher = {
    async hash(password) { return `hash:${password}`; },
    async verify(password, hash) { return hash === `hash:${password}`; }
};

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertGroup(db, id, name = `group-${id}`) {
    await db.prepare(`
        INSERT INTO groups (
            id, created_at, updated_at, name, description, platform, rate_multiplier,
            status, is_exclusive, sort_order, supported_model_scopes,
            messages_dispatch_model_config, models_list_config
        ) VALUES (?, ?, ?, ?, '', 'openai', 1, 'active', 0, 0, '[]', '{}', '{}')
    `).bind(id, new Date(FIXED_NOW).toISOString(), new Date(FIXED_NOW).toISOString(), name).run();
}

async function upsertSetting(db, key, value) {
    await db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).bind(key, value, new Date(FIXED_NOW).toISOString()).run();
}

async function createService(db, now = FIXED_NOW) {
    const users = new D1AuthUserRepository(db);
    const sessions = new D1AuthSessionRepository(db);
    const tokens = new AuthTokenService(
        sessions,
        new Hs256JwtSigner(JWT_SECRET, 3600, () => now),
        30,
        () => now
    );
    return {
        users,
        sessions,
        tokens,
        service: new D1UserManagementService(
            users,
            new D1UserManagementRepository(db),
            passwordHasher,
            new D1ExpiringStateRepository(db, { clock: () => now }),
            tokens,
            () => now
        )
    };
}

async function createAdmin(db, email = "admin@example.com") {
    const { service, users, tokens } = await createService(db);
    const admin = await service.createInitialAdmin(email, "admin-password");
    const user = await users.findById(admin.id);
    const pair = await tokens.issue(user);
    return { user, accessToken: pair.accessToken };
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET,
        JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600",
        JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30",
        EMAIL_TASK_ENCRYPTION_KEY: EMAIL_KEY
    };
}

function dependencies(overrides = {}) {
    return {
        clock: () => FIXED_NOW,
        passwordHasher,
        verificationCodeFactory: () => "123456",
        resetTokenFactory: () => RESET_TOKEN,
        ...overrides
    };
}

test("normalized active email index blocks concurrent-equivalent identities but permits soft-deleted reuse", async () => {
    const db = createDatabase();
    const repository = new D1UserManagementRepository(db);
    const base = {
        passwordHash: "hash:password",
        role: "user",
        username: "",
        notes: "",
        balance: 0,
        concurrency: 1,
        rpmLimit: 0,
        status: "active",
        signupSource: "admin",
        allowedGroups: [],
        groupRates: new Map(),
        defaultSubscriptions: [],
        createdAt: new Date(FIXED_NOW).toISOString()
    };
    const firstId = await repository.createUser({ ...base, email: "User@Example.com" });
    await assert.rejects(
        repository.createUser({
            ...base,
            email: " user@example.COM ",
            createdAt: new Date(FIXED_NOW + 1).toISOString()
        }),
        /unique|email/i
    );
    await db.prepare("UPDATE users SET deleted_at = ?, updated_at = ? WHERE id = ?")
        .bind(new Date(FIXED_NOW + 2).toISOString(), new Date(FIXED_NOW + 2).toISOString(), firstId)
        .run();
    const reused = await repository.createUser({
        ...base,
        email: "user@example.com",
        createdAt: new Date(FIXED_NOW + 3).toISOString()
    });
    assert.notEqual(reused, firstId);
    db.close();
});

test("admin create and full update persist relations, defaults, adjustment audit, and session revocation", async () => {
    const db = createDatabase();
    await insertGroup(db, 1);
    await insertGroup(db, 2);
    await upsertSetting(db, "default_balance", "12.5");
    await upsertSetting(db, "default_subscriptions", '[{"group_id":1,"validity_days":30}]');
    const { user: actor, accessToken } = await createAdmin(db);

    const createdResponse = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/admin/users",
        {
            method: "POST",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({
                email: "managed@example.com",
                password: "managed-password",
                username: "managed",
                concurrency: 2,
                rpm_limit: 9,
                allowed_groups: [1]
            })
        }
    ), env(db), dependencies());
    assert.equal(createdResponse.status, 200);
    const created = (await createdResponse.json()).data;
    assert.equal(created.balance, 12.5);
    assert.deepEqual(created.allowed_groups, [1]);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM user_subscriptions WHERE user_id = ?")
        .bind(created.id).first()).count, 1);

    const managed = await new D1AuthUserRepository(db).findById(created.id);
    const tokenService = (await createService(db)).tokens;
    await tokenService.issue(managed);

    const updatedResponse = await routeStagedUserDomain(new Request(
        `https://example.test/api/v1/admin/users/${created.id}`,
        {
            method: "PUT",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({
                email: "managed-new@example.com",
                username: "renamed",
                notes: "updated",
                balance: 20,
                concurrency: 4,
                rpm_limit: 12,
                allowed_groups: [2],
                group_rates: { "2": 1.5 }
            })
        }
    ), env(db), dependencies());
    assert.equal(updatedResponse.status, 200);
    const updated = (await updatedResponse.json()).data;
    assert.equal(updated.email, "managed-new@example.com");
    assert.equal(updated.username, "renamed");
    assert.equal(updated.notes, "updated");
    assert.deepEqual(updated.allowed_groups, [2]);
    assert.deepEqual(updated.group_rates, { "2": 1.5 });
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_refresh_sessions
        WHERE user_id = ? AND revoked_at IS NOT NULL
    `).bind(created.id).first()).count, 1);
    const audit = await db.prepare(`
        SELECT type, value, used_by FROM redeem_codes
        WHERE type = 'admin_concurrency' AND used_by = ?
    `).bind(created.id).first();
    assert.equal(audit.value, 2);
    assert.equal(audit.used_by, created.id);
    assert.equal(actor.role, "admin");
    db.close();
});

test("verification email task and registration atomically consume encrypted state and invitation", async () => {
    const db = createDatabase();
    await insertGroup(db, 1);
    for (const [key, value] of Object.entries({
        registration_enabled: "true",
        email_verify_enabled: "true",
        invitation_code_enabled: "true",
        registration_email_suffix_whitelist: '["example.com"]',
        default_balance: "3",
        default_concurrency: "7",
        default_user_rpm_limit: "11",
        default_subscriptions: '[{"group_id":1,"validity_days":10}]',
        site_name: "Example",
        turnstile_enabled: "false",
        backend_mode_enabled: "false"
    })) await upsertSetting(db, key, value);
    await db.prepare(`
        INSERT INTO redeem_codes (
            code, type, value, status, created_at, validity_days
        ) VALUES ('invite-1', 'invitation', 0, 'unused', ?, 30)
    `).bind(new Date(FIXED_NOW).toISOString()).run();

    const send = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/auth/send-verify-code",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email: "new@example.com" })
        }
    ), env(db), dependencies());
    assert.equal(send.status, 200);
    const key = await verificationStateKey("new@example.com");
    const state = JSON.parse((await db.prepare(`
        SELECT value_json FROM runtime_expiring_values WHERE state_key = ?
    `).bind(key).first()).value_json);
    assert.notEqual(state.secretEnvelope, "123456");
    assert.equal(await new AesGcmEmailSecretCipher(EMAIL_KEY).open(state.secretEnvelope), "123456");
    const taskPayload = (await db.prepare(`
        SELECT payload_json FROM runtime_tasks WHERE queue_name = 'email'
    `).first()).payload_json;
    assert.doesNotMatch(taskPayload, /123456/u);

    const register = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/auth/register",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                email: "new@example.com",
                password: "new-password",
                verify_code: "123456",
                invitation_code: "invite-1"
            })
        }
    ), env(db), dependencies());
    assert.equal(register.status, 200);
    const data = (await register.json()).data;
    assert.match(data.access_token, /^ey/u);
    assert.equal(data.user.balance, 3);
    assert.equal(data.user.concurrency, 7);
    assert.equal(data.user.rpm_limit, 11);
    assert.equal(await db.prepare("SELECT COUNT(*) AS count FROM runtime_expiring_values WHERE state_key = ?")
        .bind(key).first().then((row) => row.count), 0);
    const invitation = await db.prepare("SELECT status, used_by FROM redeem_codes WHERE code = 'invite-1'").first();
    assert.equal(invitation.status, "used");
    assert.equal(invitation.used_by, data.user.id);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM user_subscriptions WHERE user_id = ?")
        .bind(data.user.id).first()).count, 1);
    db.close();
});

test("registration applies source defaults, platform quotas, promo bonus, and affiliate binding atomically", async () => {
    const db = createDatabase();
    await insertGroup(db, 1);
    const repository = new D1UserManagementRepository(db);
    const inviterId = await repository.createUser({
        email: "inviter@example.com",
        passwordHash: "hash:inviter-password",
        role: "user",
        username: "inviter",
        notes: "",
        balance: 0,
        concurrency: 1,
        rpmLimit: 0,
        status: "active",
        signupSource: "admin",
        allowedGroups: [],
        groupRates: new Map(),
        defaultSubscriptions: [],
        createdAt: new Date(FIXED_NOW - 1000).toISOString()
    });
    await db.prepare(`
        INSERT INTO user_affiliates (user_id, aff_code, created_at, updated_at)
        VALUES (?, 'INVITER2026', ?, ?)
    `).bind(
        inviterId,
        new Date(FIXED_NOW - 1000).toISOString(),
        new Date(FIXED_NOW - 1000).toISOString()
    ).run();
    await db.prepare(`
        INSERT INTO promo_codes (
            code, bonus_amount, max_uses, used_count, status, expires_at, notes, created_at, updated_at
        ) VALUES ('WELCOME', 9, 1, 0, 'active', ?, '', ?, ?)
    `).bind(
        new Date(FIXED_NOW + 86_400_000).toISOString(),
        new Date(FIXED_NOW).toISOString(),
        new Date(FIXED_NOW).toISOString()
    ).run();
    for (const [key, value] of Object.entries({
        registration_enabled: "true",
        email_verify_enabled: "false",
        invitation_code_enabled: "false",
        promo_code_enabled: "true",
        affiliate_enabled: "true",
        turnstile_enabled: "false",
        backend_mode_enabled: "false",
        default_balance: "1",
        default_concurrency: "2",
        default_user_rpm_limit: "6",
        default_subscriptions: "[]",
        default_platform_quotas: JSON.stringify({
            anthropic: { daily: 5, weekly: 10 },
            openai: { monthly: 20 }
        }),
        auth_source_default_email_grant_on_signup: "true",
        auth_source_default_email_balance: "4",
        auth_source_default_email_concurrency: "8",
        auth_source_default_email_subscriptions: '[{"group_id":1,"validity_days":5}]',
        auth_source_default_email_platform_quotas: JSON.stringify({
            anthropic: { weekly: 15 },
            grok: { daily: 0 }
        })
    })) await upsertSetting(db, key, value);

    const register = (email, promoCode, affiliateCode) => routeStagedUserDomain(new Request(
        "https://example.test/api/v1/auth/register",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                email,
                password: "new-password",
                promo_code: promoCode,
                aff_code: affiliateCode
            })
        }
    ), env(db), dependencies());

    const applied = await register("beneficiary@example.com", "welcome", "inviter2026");
    assert.equal(applied.status, 200);
    const appliedUser = (await applied.json()).data.user;
    assert.equal(appliedUser.balance, 13);
    assert.equal(appliedUser.concurrency, 8);
    assert.equal(appliedUser.rpm_limit, 6);
    const affiliate = await db.prepare(`
        SELECT aff_code, inviter_id FROM user_affiliates WHERE user_id = ?
    `).bind(appliedUser.id).first();
    assert.match(affiliate.aff_code, /^[A-HJ-NP-Z2-9]{12}$/u);
    assert.equal(affiliate.inviter_id, inviterId);
    assert.equal((await db.prepare("SELECT aff_count FROM user_affiliates WHERE user_id = ?")
        .bind(inviterId).first()).aff_count, 1);
    assert.equal((await db.prepare("SELECT used_count FROM promo_codes WHERE code = 'WELCOME'").first()).used_count, 1);
    assert.equal((await db.prepare("SELECT bonus_amount FROM promo_code_usages WHERE user_id = ?")
        .bind(appliedUser.id).first()).bonus_amount, 9);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM user_subscriptions WHERE user_id = ?")
        .bind(appliedUser.id).first()).count, 1);
    const quotas = await db.prepare(`
        SELECT platform, daily_limit_usd, weekly_limit_usd, monthly_limit_usd
        FROM user_platform_quotas
        WHERE user_id = ?
        ORDER BY platform
    `).bind(appliedUser.id).all();
    assert.equal(quotas.results.length, 5);
    const anthropic = quotas.results.find((quota) => quota.platform === "anthropic");
    assert.deepEqual({ ...anthropic }, {
        platform: "anthropic",
        daily_limit_usd: 5,
        weekly_limit_usd: 15,
        monthly_limit_usd: null
    });
    const grok = quotas.results.find((quota) => quota.platform === "grok");
    assert.equal(grok.daily_limit_usd, 0);

    const ignored = await register("ignored@example.com", "missing", "missing-affiliate");
    assert.equal(ignored.status, 200);
    const ignoredUser = (await ignored.json()).data.user;
    assert.equal(ignoredUser.balance, 4);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM promo_code_usages WHERE user_id = ?")
        .bind(ignoredUser.id).first()).count, 0);
    assert.equal((await db.prepare("SELECT inviter_id FROM user_affiliates WHERE user_id = ?")
        .bind(ignoredUser.id).first()).inviter_id, null);

    await db.prepare(`
        INSERT INTO promo_codes (
            code, bonus_amount, max_uses, used_count, status, expires_at, notes, created_at, updated_at
        ) VALUES ('RACE', 9, 1, 0, 'active', ?, '', ?, ?)
    `).bind(
        new Date(FIXED_NOW + 86_400_000).toISOString(),
        new Date(FIXED_NOW).toISOString(),
        new Date(FIXED_NOW).toISOString()
    ).run();
    const raced = await Promise.all([
        register("race-a@example.com", "RACE", ""),
        register("race-b@example.com", "RACE", "")
    ]);
    assert.deepEqual(raced.map((response) => response.status), [200, 200]);
    const racedBalances = await Promise.all(raced.map(async (response) => (await response.json()).data.user.balance));
    assert.deepEqual(racedBalances.sort((left, right) => left - right), [4, 13]);
    assert.equal((await db.prepare("SELECT used_count FROM promo_codes WHERE code = 'RACE'").first()).used_count, 1);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count
        FROM promo_code_usages AS usage
        JOIN promo_codes AS promo ON promo.id = usage.promo_code_id
        WHERE promo.code = 'RACE'
    `).first()).count, 1);
    db.close();
});

test("forgot-password task keeps raw token encrypted and staged reset consumes the object state", async () => {
    const db = createDatabase();
    await upsertSetting(db, "password_reset_enabled", "true");
    await upsertSetting(db, "frontend_url", "https://app.example.test");
    await upsertSetting(db, "site_name", "Example");
    await upsertSetting(db, "turnstile_enabled", "false");
    const repository = new D1UserManagementRepository(db);
    const userId = await repository.createUser({
        email: "reset@example.com",
        passwordHash: "hash:old-password",
        role: "user",
        username: "",
        notes: "",
        balance: 0,
        concurrency: 1,
        rpmLimit: 0,
        status: "active",
        signupSource: "admin",
        allowedGroups: [],
        groupRates: new Map(),
        defaultSubscriptions: [],
        createdAt: new Date(FIXED_NOW).toISOString()
    });

    const forgot = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/auth/forgot-password",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email: "reset@example.com" })
        }
    ), env(db), dependencies());
    assert.equal(forgot.status, 200);
    const task = await db.prepare(`
        SELECT payload_json FROM runtime_tasks WHERE queue_name = 'email'
    `).first();
    assert.doesNotMatch(task.payload_json, new RegExp(RESET_TOKEN, "u"));

    const reset = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/auth/reset-password",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                email: "reset@example.com",
                token: RESET_TOKEN,
                new_password: "new-password"
            })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher });
    assert.equal(reset.status, 200);
    assert.equal((await db.prepare("SELECT password_hash FROM users WHERE id = ?").bind(userId).first()).password_hash, "hash:new-password");
    db.close();
});

test("email identity replacement consumes verification state and revokes every D1 session", async () => {
    const db = createDatabase();
    await upsertSetting(db, "site_name", "Example");
    const { user, accessToken } = await createAdmin(db, "current@example.com");
    const requestAt = FIXED_NOW + 1_000;
    const requestDependencies = dependencies({ clock: () => requestAt });

    const start = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/auth-identities/bind/start",
        {
            method: "POST",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({ provider: "linuxdo", redirect_to: "/settings/profile" })
        }
    ), env(db), requestDependencies);
    assert.equal(start.status, 200);
    assert.deepEqual((await start.json()).data, {
        provider: "linuxdo",
        authorize_url: "/api/v1/auth/oauth/linuxdo/bind/start?redirect=%2Fsettings%2Fprofile&intent=bind_current_user",
        method: "GET",
        use_browser_redirect: true
    });

    const send = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/account-bindings/email/send-code",
        {
            method: "POST",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({ email: "replacement@example.com" })
        }
    ), env(db), requestDependencies);
    assert.equal(send.status, 200);

    const bind = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/account-bindings/email",
        {
            method: "POST",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({
                email: "replacement@example.com",
                verify_code: "123456",
                password: "admin-password"
            })
        }
    ), env(db), requestDependencies);
    assert.equal(bind.status, 200, await bind.clone().text());
    const profile = (await bind.json()).data;
    assert.equal(profile.email, "replacement@example.com");
    assert.equal(profile.email_bound, true);
    assert.equal(profile.identities.email.display_name, "replacement@example.com");

    const changedUser = await db.prepare(`
        SELECT email, password_hash, token_version FROM users WHERE id = ?
    `).bind(user.id).first();
    assert.equal(changedUser.email, "replacement@example.com");
    assert.equal(changedUser.password_hash, "hash:admin-password");
    assert.equal(changedUser.token_version, 1);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM runtime_expiring_values
        WHERE state_key LIKE 'auth:verify-code:%'
    `).first()).count, 0);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_refresh_sessions
        WHERE user_id = ? AND revoked_at IS NOT NULL
    `).bind(user.id).first()).count, 1);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_identities
        WHERE user_id = ? AND provider_type = 'email' AND provider_subject = ?
    `).bind(user.id, "replacement@example.com").first()).count, 1);
    db.close();
});

test("first email bind grants defaults once and provider unbind preserves a remaining login method", async () => {
    const db = createDatabase();
    await insertGroup(db, 3);
    await db.prepare("UPDATE groups SET subscription_type = 'subscription' WHERE id = 3").run();
    for (const [key, value] of Object.entries({
        site_name: "Example",
        auth_source_default_email_grant_on_first_bind: "true",
        auth_source_default_email_balance: "4",
        auth_source_default_email_concurrency: "2",
        auth_source_default_email_subscriptions: '[{"group_id":3,"validity_days":30}]'
    })) await upsertSetting(db, key, value);
    const repository = new D1UserManagementRepository(db);
    const createdAt = new Date(FIXED_NOW).toISOString();
    const userId = await repository.createUser({
        email: "subject@linuxdo-connect.invalid",
        passwordHash: "hash:unusable-password",
        role: "user",
        username: "oauth-user",
        notes: "",
        balance: 1,
        concurrency: 1,
        rpmLimit: 0,
        status: "active",
        signupSource: "linuxdo",
        allowedGroups: [],
        groupRates: new Map(),
        defaultSubscriptions: [],
        createdAt
    });
    const originalSubscriptionExpiry = new Date(FIXED_NOW + 10 * 86_400_000).toISOString();
    await db.prepare(`
        INSERT INTO user_subscriptions (
            created_at, updated_at, deleted_at, starts_at, expires_at,
            status, assigned_at, notes, group_id, user_id, assigned_by
        ) VALUES (?, ?, NULL, ?, ?, 'active', ?, 'existing', 3, ?, NULL)
    `).bind(createdAt, createdAt, createdAt, originalSubscriptionExpiry, createdAt, userId).run();
    await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key,
            provider_subject, verified_at, issuer, metadata, user_id
        ) VALUES (?, ?, 'linuxdo', 'linuxdo', 'linuxdo-subject', ?, NULL, '{}', ?)
    `).bind(createdAt, createdAt, createdAt, userId).run();
    const { users, tokens } = await createService(db);
    const oauthUser = await users.findById(userId);
    const accessToken = (await tokens.issue(oauthUser)).accessToken;
    const bindAt = FIXED_NOW + 1_000;
    const bindDependencies = dependencies({ clock: () => bindAt });

    const send = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/account-bindings/email/send-code",
        {
            method: "POST",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({ email: "bound@example.com" })
        }
    ), env(db), bindDependencies);
    assert.equal(send.status, 200);
    const bind = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/account-bindings/email",
        {
            method: "POST",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({
                email: "bound@example.com",
                verify_code: "123456",
                password: "new-password"
            })
        }
    ), env(db), bindDependencies);
    assert.equal(bind.status, 200, await bind.clone().text());
    const afterBind = await db.prepare(`
        SELECT email, balance, concurrency, token_version FROM users WHERE id = ?
    `).bind(userId).first();
    assert.deepEqual({ ...afterBind }, {
        email: "bound@example.com",
        balance: 5,
        concurrency: 3,
        token_version: 1
    });
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM user_provider_default_grants
        WHERE user_id = ? AND provider_type = 'email' AND grant_reason = 'first_bind'
    `).bind(userId).first()).count, 1);
    const subscription = await db.prepare(`
        SELECT COUNT(*) AS count, expires_at, notes
        FROM user_subscriptions WHERE user_id = ? AND group_id = 3
    `).bind(userId).first();
    assert.equal(subscription.count, 1);
    assert.equal(
        Date.parse(subscription.expires_at),
        Date.parse(originalSubscriptionExpiry) + 30 * 86_400_000
    );
    assert.match(subscription.notes, /existing\nauto assigned by first bind defaults/u);

    const reboundUser = await users.findById(userId);
    const unbindToken = (await (await createService(db, bindAt)).tokens.issue(reboundUser)).accessToken;
    const unbindAt = FIXED_NOW + 2_000;
    const unbind = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/account-bindings/linuxdo",
        {
            method: "DELETE",
            headers: { authorization: `Bearer ${unbindToken}` }
        }
    ), env(db), dependencies({ clock: () => unbindAt }));
    assert.equal(unbind.status, 200, await unbind.clone().text());
    const unboundProfile = (await unbind.json()).data;
    assert.equal(unboundProfile.linuxdo_bound, false);
    assert.equal(unboundProfile.email_bound, true);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_identities
        WHERE user_id = ? AND provider_type = 'linuxdo'
    `).bind(userId).first()).count, 0);
    assert.equal((await db.prepare("SELECT token_version FROM users WHERE id = ?").bind(userId).first()).token_version, 2);

    const lastOnlyId = await repository.createUser({
        email: "subject@oidc-connect.invalid",
        passwordHash: "hash:unusable-password",
        role: "user",
        username: "last-only",
        notes: "",
        balance: 0,
        concurrency: 1,
        rpmLimit: 0,
        status: "active",
        signupSource: "oidc",
        allowedGroups: [],
        groupRates: new Map(),
        defaultSubscriptions: [],
        createdAt: new Date(FIXED_NOW + 3_000).toISOString()
    });
    await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key,
            provider_subject, verified_at, issuer, metadata, user_id
        ) VALUES (?, ?, 'oidc', 'oidc', 'oidc-subject', ?, NULL, '{}', ?)
    `).bind(createdAt, createdAt, createdAt, lastOnlyId).run();
    const lastOnly = await users.findById(lastOnlyId);
    const lastOnlyToken = (await (await createService(db, FIXED_NOW + 3_000)).tokens.issue(lastOnly)).accessToken;
    const blocked = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/account-bindings/oidc",
        {
            method: "DELETE",
            headers: { authorization: `Bearer ${lastOnlyToken}` }
        }
    ), env(db), dependencies({ clock: () => FIXED_NOW + 4_000 }));
    assert.equal(blocked.status, 409);
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_identities
        WHERE user_id = ? AND provider_type = 'oidc'
    `).bind(lastOnlyId).first()).count, 1);
    db.close();
});

test("current-user profile read and update use D1 including avatar metadata and notification fields", async () => {
    const db = createDatabase();
    await upsertSetting(db, "linuxdo_connect_enabled", "true");
    const { user, accessToken } = await createAdmin(db, "profile@example.com");
    const avatar = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
    const updatedResponse = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user",
        {
            method: "PUT",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({
                username: "Profile Name",
                avatar_url: avatar,
                balance_notify_enabled: true,
                balance_notify_threshold: 12.5,
                balance_notify_extra_emails: []
            })
        }
    ), env(db), dependencies());
    assert.equal(updatedResponse.status, 200, await updatedResponse.clone().text());
    const updated = (await updatedResponse.json()).data;
    assert.equal(updated.id, user.id);
    assert.equal(updated.username, "Profile Name");
    assert.equal(updated.avatar_url, avatar);
    assert.equal(updated.balance_notify_enabled, true);
    assert.equal(updated.balance_notify_threshold, 12.5);
    assert.equal(updated.email_bound, true);

    const storedAvatar = await db.prepare(`
        SELECT storage_provider AS provider, content_type AS contentType,
            byte_size AS byteSize, sha256 FROM user_avatars WHERE user_id = ?
    `).bind(user.id).first();
    assert.equal(storedAvatar.provider, "inline");
    assert.equal(storedAvatar.contentType, "image/png");
    assert.ok(storedAvatar.byteSize > 0);
    assert.match(storedAvatar.sha256, /^[a-f0-9]{64}$/u);

    const profileResponse = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user/profile",
        { headers: { authorization: `Bearer ${accessToken}` } }
    ), env(db), dependencies());
    assert.equal(profileResponse.status, 200);
    const profile = (await profileResponse.json()).data;
    assert.equal(profile.username, "Profile Name");
    assert.equal(profile.avatar_url, avatar);
    assert.equal(profile.run_mode, "standard");

    const clearedResponse = await routeStagedUserDomain(new Request(
        "https://example.test/api/v1/user",
        {
            method: "PUT",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify({ avatar_url: "", balance_notify_threshold: 0 })
        }
    ), env(db), dependencies());
    assert.equal(clearedResponse.status, 200);
    const cleared = (await clearedResponse.json()).data;
    assert.equal(cleared.avatar_url, undefined);
    assert.equal(cleared.balance_notify_threshold, null);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM user_avatars`).first()).count, 0);
    db.close();
});

test("notification email verification, toggle, and removal use encrypted one-time D1 state", async () => {
    const db = createDatabase();
    await upsertSetting(db, "site_name", "Profile Test");
    const { user, accessToken } = await createAdmin(db, "notify-owner@example.com");
    const route = (path, method, body) => routeStagedUserDomain(new Request(
        `https://example.test${path}`,
        {
            method,
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify(body)
        }
    ), env(db), dependencies());

    const send = await route("/api/v1/user/notify-email/send-code", "POST", {
        email: "Extra@Example.com"
    });
    assert.equal(send.status, 200);
    const task = await db.prepare(`SELECT payload_json AS payload FROM runtime_tasks`).first();
    assert.doesNotMatch(task.payload, /123456/u);

    const wrong = await route("/api/v1/user/notify-email/verify", "POST", {
        email: "extra@example.com",
        code: "000000"
    });
    assert.equal(wrong.status, 400);
    const verify = await route("/api/v1/user/notify-email/verify", "POST", {
        email: "extra@example.com",
        code: "123456"
    });
    assert.equal(verify.status, 200, await verify.clone().text());
    assert.deepEqual((await verify.json()).data.balance_notify_extra_emails, [
        { email: "extra@example.com", disabled: false, verified: true }
    ]);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM runtime_expiring_values`).first()).count, 0);

    const toggle = await route("/api/v1/user/notify-email/toggle", "PUT", {
        email: "extra@example.com",
        disabled: true
    });
    assert.equal(toggle.status, 200);
    assert.equal((await toggle.json()).data.balance_notify_extra_emails[0].disabled, true);

    const remove = await route("/api/v1/user/notify-email", "DELETE", {
        email: "extra@example.com"
    });
    assert.equal(remove.status, 200);
    assert.deepEqual((await remove.json()).data.balance_notify_extra_emails, []);
    assert.equal((await db.prepare(`
        SELECT balance_notify_extra_emails AS emails FROM users WHERE id = ?
    `).bind(user.id).first()).emails, "[]");
    db.close();
});

test("administrator identity binding is idempotent and rejects identity or channel ownership conflicts", async () => {
    const db = createDatabase();
    const { user: admin, accessToken } = await createAdmin(db, "identity-admin@example.com");
    const { service } = await createService(db);
    const first = await service.createByAdmin(admin, {
        email: "identity-one@example.com",
        password: "identity-password"
    }, {});
    const second = await service.createByAdmin(admin, {
        email: "identity-two@example.com",
        password: "identity-password"
    }, {});
    const bind = (userId, body) => routeStagedUserDomain(new Request(
        `https://example.test/api/v1/admin/users/${userId}/auth-identities`,
        {
            method: "POST",
            headers: {
                authorization: `Bearer ${accessToken}`,
                "content-type": "application/json"
            },
            body: JSON.stringify(body)
        }
    ), env(db), dependencies());

    const oidcInput = {
        provider_type: "oidc",
        provider_key: "https://issuer.example",
        provider_subject: "subject-123",
        issuer: "https://issuer.example",
        metadata: { report_id: 12 }
    };
    const firstBind = await bind(first.id, oidcInput);
    assert.equal(firstBind.status, 200, await firstBind.clone().text());
    const firstPayload = (await firstBind.json()).data;
    assert.equal(firstPayload.user_id, first.id);
    assert.equal(firstPayload.provider_type, "oidc");
    assert.deepEqual(firstPayload.metadata, { report_id: 12 });
    const replay = await bind(first.id, oidcInput);
    assert.equal(replay.status, 200);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_identities`).first()).count, 1);
    const conflict = await bind(second.id, oidcInput);
    assert.equal(conflict.status, 409);

    const wechatInput = {
        provider_type: "wechat",
        provider_key: "wechat",
        provider_subject: "union-1",
        metadata: { nickname: "Member" },
        channel: {
            channel: "open",
            channel_app_id: "wx-app",
            channel_subject: "openid-1",
            metadata: { source: "migration" }
        }
    };
    const wechat = await bind(first.id, wechatInput);
    assert.equal(wechat.status, 200, await wechat.clone().text());
    const wechatPayload = (await wechat.json()).data;
    assert.equal(wechatPayload.provider_key, "wechat");
    assert.equal(wechatPayload.channel.channel_subject, "openid-1");
    const channelConflict = await bind(second.id, {
        ...wechatInput,
        provider_subject: "union-2"
    });
    assert.equal(channelConflict.status, 409);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM auth_identity_channels`).first()).count, 1);
    db.close();
});

test("setup creates exactly one initial administrator", async () => {
    const db = createDatabase();
    const request = () => new Request("https://example.test/setup/install", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            admin: { email: "owner@example.com", password: "owner-password" }
        })
    });
    const first = await routeStagedUserDomain(request(), env(db), dependencies());
    assert.equal(first.status, 200);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first()).count, 1);
    const second = await routeStagedUserDomain(request(), env(db), dependencies());
    assert.equal(second.status, 403);
    assert.match(indexSource, /routeStagedUserDomain/u);
    db.close();
});

test("Worker activates all staged user-domain routes as D1-native", async () => {
    const db = createDatabase();
    let forwarded = 0;
    const workerEnv = {
        ...env(db),
        BACKEND: {
            async fetch() {
                forwarded += 1;
                return new Response("forwarded", { status: 202 });
            }
        }
    };
    const installed = await routeRequest(new Request("https://example.test/setup/install", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            admin: { email: "edge-owner@example.com", password: "owner-password" }
        })
    }), workerEnv);
    assert.equal(installed.status, 200, await installed.clone().text());
    assert.equal(forwarded, 0);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first()).count, 1);

    const stagedAuth = await routeRequest(new Request("https://example.test/api/v1/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "user@example.com", password: "password" })
    }), workerEnv);
    assert.notEqual(stagedAuth.status, 202);
    assert.equal(forwarded, 0);
    db.close();
});
