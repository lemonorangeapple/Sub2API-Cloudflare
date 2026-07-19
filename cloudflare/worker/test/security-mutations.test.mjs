import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1AuthSessionRepository } from "../src/repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../src/repositories/auth-users.ts";
import { D1CoordinationRepository } from "../src/repositories/runtime-coordination.ts";
import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import { D1SecurityMutationRepository } from "../src/repositories/security-mutations.ts";
import { routeStagedAuth } from "../src/router/staged-auth.ts";
import { routeStagedSecurity } from "../src/router/staged-security.ts";
import { AuthTokenService } from "../src/services/auth-tokens.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { AesGcmTotpSecretDecryptor } from "../src/services/totp.ts";
import { TotpManagementService } from "../src/services/totp-management.ts";
import { UserSecurityService } from "../src/services/user-security.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const indexSource = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");

const FIXED_NOW = Date.parse("2026-07-15T12:00:00.000Z");
const JWT_SECRET = "security-mutation-test-secret-at-least-32-bytes";
const TOTP_KEY = "11".repeat(32);
const fakePasswords = {
    async verify(password, hash) {
        return hash === `hash:${password}`;
    },
    async hash(password) {
        return `hash:${password}`;
    }
};

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) {
        db.exec(migration);
    }
    return db;
}

async function insertSetting(db, key, value) {
    await db.prepare("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)")
        .bind(key, value, new Date(FIXED_NOW).toISOString())
        .run();
}

async function insertUser(db, overrides = {}) {
    const input = {
        email: "user@example.com",
        password: "old-password",
        role: "user",
        status: "active",
        username: "user",
        notes: "",
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status, username, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        input.email,
        `hash:${input.password}`,
        input.role,
        input.status,
        input.username,
        input.notes
    ).run();
    return Number(result.meta.last_row_id);
}

async function issueTokens(db, userId, now = FIXED_NOW) {
    const users = new D1AuthUserRepository(db);
    const user = await users.findById(userId);
    assert.ok(user);
    const sessions = new D1AuthSessionRepository(db);
    const signer = new Hs256JwtSigner(JWT_SECRET, 3600, () => now);
    const service = new AuthTokenService(sessions, signer, 30, () => now);
    return service.issue(user);
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

function bearer(token) {
    return { authorization: `Bearer ${token}` };
}

async function body(response) {
    return response.json();
}

async function count(db, sql, ...values) {
    return Number((await db.prepare(sql).bind(...values).first()).count);
}

test("password change and password reset atomically revoke D1 sessions", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    await insertSetting(db, "password_reset_enabled", "true");
    const firstPair = await issueTokens(db, userId);

    const changed = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/user/password",
        {
            method: "PUT",
            headers: { ...bearer(firstPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({ old_password: "old-password", new_password: "new-password" })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(changed.status, 200);
    assert.equal((await body(changed)).data.message, "Password changed successfully");
    const afterChange = await db.prepare(
        "SELECT password_hash, token_version FROM users WHERE id = ?"
    ).bind(userId).first();
    assert.equal(afterChange.password_hash, "hash:new-password");
    assert.equal(afterChange.token_version, 1);
    assert.equal(await count(
        db,
        "SELECT COUNT(*) AS count FROM auth_refresh_sessions WHERE user_id = ? AND revoked_at IS NOT NULL",
        userId
    ), 1);

    const oldAccess = await routeStagedAuth(new Request(
        "https://example.test/api/v1/auth/me",
        { headers: bearer(firstPair.accessToken) }
    ), env(db), { clock: () => FIXED_NOW });
    assert.equal(oldAccess.status, 401);
    assert.equal((await body(oldAccess)).code, "TOKEN_REVOKED");

    const users = new D1AuthUserRepository(db);
    const state = new D1ExpiringStateRepository(db, { clock: () => FIXED_NOW });
    const mutations = new D1SecurityMutationRepository(db);
    const security = new UserSecurityService(users, mutations, fakePasswords, state, () => FIXED_NOW);
    const resetToken = await security.createPasswordResetToken("USER@example.com");
    await issueTokens(db, userId);

    const reset = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/auth/reset-password",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                email: "user@example.com",
                token: resetToken,
                new_password: "reset-password"
            })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(reset.status, 200);
    assert.equal((await body(reset)).data.message.includes("reset successfully"), true);
    assert.equal((await db.prepare("SELECT password_hash FROM users WHERE id = ?").bind(userId).first()).password_hash, "hash:reset-password");

    const replay = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/auth/reset-password",
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                email: "user@example.com",
                token: resetToken,
                new_password: "another-password"
            })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(replay.status, 400);
    assert.equal((await body(replay)).reason, "INVALID_RESET_TOKEN");
    db.close();
});

test("admin security updates and deletion enforce guards and clean authentication state", async () => {
    const db = createDatabase();
    const actorId = await insertUser(db, {
        email: "admin@example.com",
        role: "admin",
        username: "admin"
    });
    await insertUser(db, {
        email: "second-admin@example.com",
        role: "admin",
        username: "second-admin"
    });
    const targetId = await insertUser(db, {
        email: "target@example.com",
        username: "target"
    });
    const actorPair = await issueTokens(db, actorId);
    await issueTokens(db, targetId);

    const updated = await routeStagedSecurity(new Request(
        `https://example.test/api/v1/admin/users/${targetId}`,
        {
            method: "PUT",
            headers: { ...bearer(actorPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({ status: "disabled", role: "user" })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(updated.status, 200);
    assert.equal((await body(updated)).data.status, "disabled");
    const target = await db.prepare(
        "SELECT status, token_version FROM users WHERE id = ?"
    ).bind(targetId).first();
    assert.equal(target.status, "disabled");
    assert.equal(target.token_version, 1);
    assert.equal(await count(
        db,
        "SELECT COUNT(*) AS count FROM auth_refresh_sessions WHERE user_id = ? AND revoked_at IS NOT NULL",
        targetId
    ), 1);

    const unsupported = await routeStagedSecurity(new Request(
        `https://example.test/api/v1/admin/users/${targetId}`,
        {
            method: "PUT",
            headers: { ...bearer(actorPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({ concurrency: 99 })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(unsupported.status, 409);
    assert.equal((await body(unsupported)).reason, "UNSUPPORTED_UPDATE_FIELDS");

    const selfDemotion = await routeStagedSecurity(new Request(
        `https://example.test/api/v1/admin/users/${actorId}`,
        {
            method: "PUT",
            headers: { ...bearer(actorPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({ role: "user" })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(selfDemotion.status, 400);
    assert.equal((await body(selfDemotion)).reason, "CANNOT_DEMOTE_SELF");

    const apiKey = await db.prepare(`
        INSERT INTO api_keys (created_at, updated_at, key, name, status, user_id)
        VALUES (?, ?, ?, ?, 'active', ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        "sk-target",
        "target key",
        targetId
    ).run();
    assert.ok(apiKey.meta.last_row_id);
    const identity = await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key,
            provider_subject, metadata, user_id
        ) VALUES (?, ?, 'linuxdo', 'linuxdo', 'subject-1', '{}', ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        targetId
    ).run();
    await db.prepare(`
        INSERT INTO auth_identity_channels (
            created_at, updated_at, provider_type, provider_key,
            channel, channel_app_id, channel_subject, metadata, identity_id
        ) VALUES (?, ?, 'linuxdo', 'linuxdo', 'web', 'app', 'channel-subject', '{}', ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        Number(identity.meta.last_row_id)
    ).run();

    const deleted = await routeStagedSecurity(new Request(
        `https://example.test/api/v1/admin/users/${targetId}`,
        { method: "DELETE", headers: bearer(actorPair.accessToken) }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(deleted.status, 200);
    assert.equal((await body(deleted)).data.message, "User deleted successfully");
    assert.ok((await db.prepare("SELECT deleted_at FROM users WHERE id = ?").bind(targetId).first()).deleted_at);
    assert.ok((await db.prepare("SELECT deleted_at FROM api_keys WHERE user_id = ?").bind(targetId).first()).deleted_at);
    assert.equal(await count(db, "SELECT COUNT(*) AS count FROM auth_identities WHERE user_id = ?", targetId), 0);
    assert.equal(await count(db, "SELECT COUNT(*) AS count FROM auth_identity_channels"), 0);

    const mutations = new D1SecurityMutationRepository(db);
    assert.equal(await mutations.restoreUser(targetId, new Date(FIXED_NOW + 1000).toISOString()), true);
    assert.ok(await new D1AuthUserRepository(db).findById(targetId));
    assert.ok((await db.prepare("SELECT deleted_at FROM api_keys WHERE user_id = ?").bind(targetId).first()).deleted_at);
    db.close();
});

test("TOTP setup, enable, and disable use one-time D1 state and revoke sessions", async () => {
    const db = createDatabase();
    const userId = await insertUser(db, { email: "totp@example.com" });
    await insertSetting(db, "totp_enabled", "true");
    await insertSetting(db, "email_verify_enabled", "false");
    const firstPair = await issueTokens(db, userId);

    const setup = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/user/totp/setup",
        {
            method: "POST",
            headers: { ...bearer(firstPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({ password: "old-password" })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(setup.status, 200);
    const setupData = (await body(setup)).data;
    assert.match(setupData.secret, /^[A-Z2-7]+$/u);
    assert.match(setupData.setup_token, /^[a-f0-9]{64}$/u);
    assert.match(setupData.qr_code_url, /^otpauth:\/\/totp\//u);

    const code = totpCode(setupData.secret, FIXED_NOW);
    const enabled = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/user/totp/enable",
        {
            method: "POST",
            headers: { ...bearer(firstPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({
                totp_code: code,
                setup_token: setupData.setup_token
            })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(enabled.status, 200);
    assert.deepEqual((await body(enabled)).data, { success: true });
    const enabledUser = await db.prepare(`
        SELECT totp_enabled, totp_secret_encrypted, token_version
        FROM users WHERE id = ?
    `).bind(userId).first();
    assert.equal(enabledUser.totp_enabled, 1);
    assert.equal(enabledUser.token_version, 1);
    assert.equal(
        await new AesGcmTotpSecretDecryptor(TOTP_KEY).decrypt(enabledUser.totp_secret_encrypted),
        setupData.secret
    );
    assert.equal(await count(
        db,
        "SELECT COUNT(*) AS count FROM runtime_expiring_values WHERE state_key = ?",
        `auth:totp-setup:${userId}`
    ), 0);

    const replay = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/user/totp/enable",
        {
            method: "POST",
            headers: { ...bearer(firstPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({
                totp_code: code,
                setup_token: setupData.setup_token
            })
        }
    ), env(db), { clock: () => FIXED_NOW, passwordHasher: fakePasswords });
    assert.equal(replay.status, 401);
    assert.equal((await body(replay)).code, "TOKEN_REVOKED");

    const secondPair = await issueTokens(db, userId, FIXED_NOW + 1000);
    const disabled = await routeStagedSecurity(new Request(
        "https://example.test/api/v1/user/totp/disable",
        {
            method: "POST",
            headers: { ...bearer(secondPair.accessToken), "content-type": "application/json" },
            body: JSON.stringify({ password: "old-password" })
        }
    ), env(db), { clock: () => FIXED_NOW + 1000, passwordHasher: fakePasswords });
    assert.equal(disabled.status, 200);
    const disabledUser = await db.prepare(`
        SELECT totp_enabled, totp_secret_encrypted, totp_enabled_at, token_version
        FROM users WHERE id = ?
    `).bind(userId).first();
    assert.equal(disabledUser.totp_enabled, 0);
    assert.equal(disabledUser.totp_secret_encrypted, null);
    assert.equal(disabledUser.totp_enabled_at, null);
    assert.equal(disabledUser.token_version, 2);
    db.close();
});

test("email verification code state is one-time and security routes are D1-native", async () => {
    const db = createDatabase();
    const userId = await insertUser(db, { email: "email-code@example.com" });
    const users = new D1AuthUserRepository(db);
    const user = await users.findById(userId);
    const state = new D1ExpiringStateRepository(db, { clock: () => FIXED_NOW });
    const coordination = new D1CoordinationRepository(db, { clock: () => FIXED_NOW });
    const service = new TotpManagementService(
        users,
        state,
        coordination,
        new D1SecurityMutationRepository(db),
        fakePasswords,
        new AesGcmTotpSecretDecryptor(TOTP_KEY),
        () => FIXED_NOW
    );
    await service.storeEmailVerificationCode(user.email, "123456");
    const setup = await service.initiateSetup(
        user,
        { emailCode: "123456" },
        true,
        true
    );
    assert.match(setup.setup_token, /^[a-f0-9]{64}$/u);
    await assert.rejects(
        service.initiateSetup(user, { emailCode: "123456" }, true, true),
        /invalid or expired verification code/u
    );
    assert.match(indexSource, /staged-security/u);
    assert.match(indexSource, /routeStagedSecurity/u);
    db.close();
});

function totpCode(secret, nowMs) {
    const key = decodeBase32(secret);
    const counter = Math.floor(nowMs / 30_000);
    const counterBytes = Buffer.alloc(8);
    counterBytes.writeBigUInt64BE(BigInt(counter));
    const digest = createHmac("sha1", key).update(counterBytes).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary = (
        ((digest[offset] & 0x7f) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    ) >>> 0;
    return String(binary % 1_000_000).padStart(6, "0");
}

function decodeBase32(value) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const output = [];
    let buffer = 0;
    let bits = 0;
    for (const character of value) {
        buffer = (buffer << 5) | alphabet.indexOf(character);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            output.push((buffer >>> bits) & 0xff);
            buffer &= (1 << bits) - 1;
        }
    }
    return Buffer.from(output);
}
