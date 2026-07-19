import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { routeStagedAuth, STAGED_AUTH_PATHS } from "../src/router/staged-auth.ts";
import { Hs256JwtSigner, Hs256JwtVerifier, JwtValidationError } from "../src/services/jwt.ts";
import { AesGcmTotpSecretDecryptor, verifyTotpCode } from "../src/services/totp.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

const JWT_SECRET = "phase-2e-jwt-secret-that-is-at-least-32-bytes";
const TOTP_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const FIXED_NOW = Date.parse("2026-07-15T12:00:00.000Z");
const TOTP_NOW = 59_000;
const TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertSetting(db, key, value) {
    await db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).bind(key, value, "2026-07-15T00:00:00.000Z").run();
}

async function insertUser(db, overrides = {}) {
    const values = {
        email: "admin@example.com",
        passwordHash: PASSWORD_HASH,
        role: "admin",
        status: "active",
        username: "administrator",
        totpEnabled: 0,
        totpSecretEncrypted: null,
        signupSource: "email",
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, totp_enabled, totp_secret_encrypted, signup_source, token_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        values.email,
        values.passwordHash,
        values.role,
        values.status,
        values.username,
        values.totpEnabled,
        values.totpSecretEncrypted,
        values.signupSource
    ).run();
    return result.meta.last_row_id;
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET,
        JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600",
        JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30",
        TOTP_ENCRYPTION_KEY: TOTP_KEY_HEX,
        RUN_MODE: "standard"
    };
}

const acceptingPassword = {
    async verify(password, hash) {
        return password === "correct-password" && hash === PASSWORD_HASH;
    }
};

async function staged(db, path, options = {}) {
    const request = new Request(`https://edge.example${path}`, {
        method: options.method ?? "POST",
        headers: {
            "content-type": "application/json",
            "cf-connecting-ip": options.ip ?? "203.0.113.9",
            ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
            ...(options.headers ?? {})
        },
        ...(options.method === "GET" ? {} : { body: JSON.stringify(options.body ?? {}) })
    });
    return routeStagedAuth(request, env(db), {
        clock: options.clock ?? (() => FIXED_NOW),
        passwordVerifier: options.passwordVerifier ?? acceptingPassword,
        fetchImplementation: options.fetchImplementation
    });
}

async function responseData(response) {
    const body = await response.json();
    assert.equal(body.code, 0, JSON.stringify(body));
    return body.data;
}

async function login(db, overrides = {}) {
    const response = await staged(db, STAGED_AUTH_PATHS.login, {
        body: {
            email: overrides.email ?? "admin@example.com",
            password: "correct-password",
            ...(overrides.turnstileToken ? { turnstile_token: overrides.turnstileToken } : {})
        },
        ...overrides
    });
    assert.equal(response.status, 200);
    return responseData(response);
}

function encryptGoCompatibleTotpSecret(secret) {
    const key = Buffer.from(TOTP_KEY_HEX, "hex");
    const nonce = Buffer.from("00112233445566778899aabb", "hex");
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const encrypted = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
    return Buffer.concat([nonce, encrypted, cipher.getAuthTag()]).toString("base64");
}

function generateTotpCode(secret, nowMs) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const normalized = secret.replaceAll(/[-\s=]/gu, "").toUpperCase();
    const decoded = [];
    let buffer = 0;
    let bits = 0;
    for (const character of normalized) {
        buffer = (buffer << 5) | alphabet.indexOf(character);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            decoded.push((buffer >>> bits) & 0xff);
            buffer &= (1 << bits) - 1;
        }
    }
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(nowMs / 30_000)));
    const digest = createHmac("sha1", Buffer.from(decoded)).update(counter).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary = digest.readUInt32BE(offset) & 0x7fffffff;
    return String(binary % 1_000_000).padStart(6, "0");
}

test("HS256 verifier preserves bigint claims and rejects tampering and expiry", async () => {
    const signer = new Hs256JwtSigner(JWT_SECRET, 60, () => FIXED_NOW);
    const signed = await signer.sign({
        id: 42,
        email: "admin@example.com",
        role: "admin",
        tokenVersion: 0x7fffffffffffffffn
    });
    const verifier = new Hs256JwtVerifier(JWT_SECRET, () => FIXED_NOW);
    const claims = await verifier.verify(signed.token);
    assert.equal(claims.userId, 42);
    assert.equal(claims.tokenVersion, 0x7fffffffffffffffn);
    const [header, payload, signature] = signed.token.split(".");
    await assert.rejects(
        verifier.verify(`${header}.${payload.slice(0, -1)}A.${signature}`),
        JwtValidationError
    );
    await assert.rejects(
        new Hs256JwtVerifier(JWT_SECRET, () => FIXED_NOW + 60_000).verify(signed.token),
        (error) => error instanceof JwtValidationError && error.code === "token_expired"
    );
});

test("Go-compatible AES-GCM TOTP secret and RFC vector verify in Worker crypto", async () => {
    const encrypted = encryptGoCompatibleTotpSecret(TOTP_SECRET);
    const decrypted = await new AesGcmTotpSecretDecryptor(TOTP_KEY_HEX).decrypt(encrypted);
    assert.equal(decrypted, TOTP_SECRET);
    assert.equal(await verifyTotpCode(TOTP_SECRET, "287082", TOTP_NOW, 0), true);
    assert.equal(await verifyTotpCode(TOTP_SECRET, "287083", TOTP_NOW, 0), false);
});

test("staged password login, current user profile, and refresh rotation are D1-native", async () => {
    const db = createDatabase();
    const userId = await insertUser(db, { username: "linuxdo-handle" });
    await insertSetting(db, "totp_enabled", "false");
    await insertSetting(db, "linuxdo_connect_enabled", "true");
    await db.prepare(`
        INSERT INTO user_avatars (user_id, url, created_at, updated_at)
        VALUES (?, ?, ?, ?)
    `).bind(
        userId,
        "https://cdn.example.com/linuxdo.png",
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z"
    ).run();
    await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key,
            provider_subject, verified_at, metadata, user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        "linuxdo",
        "linuxdo",
        "linuxdo-subject-31",
        "2026-07-01T00:00:00.000Z",
        JSON.stringify({
            username: "linuxdo-handle",
            avatar_url: "https://cdn.example.com/linuxdo.png"
        }),
        userId
    ).run();

    const first = await login(db);
    assert.match(first.access_token, /^[^.]+\.[^.]+\.[^.]+$/u);
    assert.match(first.refresh_token, /^rt_[a-f0-9]{64}$/u);

    const meResponse = await staged(db, STAGED_AUTH_PATHS.me, {
        method: "GET",
        token: first.access_token
    });
    assert.equal(meResponse.status, 200);
    const profile = await responseData(meResponse);
    assert.equal(profile.id, userId);
    assert.equal(profile.email_bound, true);
    assert.equal(profile.linuxdo_bound, true);
    assert.equal(profile.auth_bindings.linuxdo.bound, true);
    assert.equal(profile.avatar_source.provider, "linuxdo");
    assert.equal(profile.profile_sources.username.provider, "linuxdo");
    assert.equal(profile.run_mode, "standard");

    const refreshResponse = await staged(db, STAGED_AUTH_PATHS.refresh, {
        body: { refresh_token: first.refresh_token }
    });
    assert.equal(refreshResponse.status, 200);
    const rotated = await responseData(refreshResponse);
    assert.notEqual(rotated.refresh_token, first.refresh_token);

    const oldHash = createHash("sha256").update(first.refresh_token).digest("hex");
    const oldRow = await db.prepare(`
        SELECT rotated_at, replaced_by_hash FROM auth_refresh_sessions WHERE token_hash = ?
    `).bind(oldHash).first();
    assert.equal(oldRow.rotated_at, FIXED_NOW);
    assert.equal(
        oldRow.replaced_by_hash,
        createHash("sha256").update(rotated.refresh_token).digest("hex")
    );

    const replay = await staged(db, STAGED_AUTH_PATHS.refresh, {
        body: { refresh_token: first.refresh_token }
    });
    assert.equal(replay.status, 401);
    const replayBody = await replay.json();
    assert.equal(replayBody.reason, "REFRESH_TOKEN_REUSED");
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_refresh_sessions
        WHERE family_id = (SELECT family_id FROM auth_refresh_sessions WHERE token_hash = ?)
          AND revoked_at IS NULL
    `).bind(oldHash).first()).count, 0);
    db.close();
});

test("TOTP login is one-time, rate limited, and issues tokens only after valid code", async () => {
    const db = createDatabase();
    await insertSetting(db, "totp_enabled", "true");
    await insertUser(db, {
        totpEnabled: 1,
        totpSecretEncrypted: encryptGoCompatibleTotpSecret(TOTP_SECRET)
    });

    const initial = await login(db, { clock: () => TOTP_NOW });
    assert.equal(initial.requires_2fa, true);
    assert.match(initial.temp_token, /^[a-f0-9]{64}$/u);
    assert.equal(initial.user_email_masked, "a***n@example.com");
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM auth_refresh_sessions").first()).count, 0);

    for (let attempt = 0; attempt < 5; attempt += 1) {
        const invalid = await staged(db, STAGED_AUTH_PATHS.login2fa, {
            clock: () => TOTP_NOW,
            body: { temp_token: initial.temp_token, totp_code: "000000" }
        });
        assert.equal(invalid.status, 400);
    }
    const limited = await staged(db, STAGED_AUTH_PATHS.login2fa, {
        clock: () => TOTP_NOW,
        body: { temp_token: initial.temp_token, totp_code: "000000" }
    });
    assert.equal(limited.status, 429);

    const correctButLimited = await staged(db, STAGED_AUTH_PATHS.login2fa, {
        clock: () => TOTP_NOW,
        body: { temp_token: initial.temp_token, totp_code: "287082" }
    });
    assert.equal(correctButLimited.status, 429);

    const later = TOTP_NOW + 15 * 60 * 1000;
    const expired = await staged(db, STAGED_AUTH_PATHS.login2fa, {
        clock: () => later,
        body: { temp_token: initial.temp_token, totp_code: generateTotpCode(TOTP_SECRET, later) }
    });
    assert.equal(expired.status, 400);

    const fresh = await login(db, { clock: () => later, ip: "203.0.113.10" });
    const completed = await staged(db, STAGED_AUTH_PATHS.login2fa, {
        clock: () => later,
        ip: "203.0.113.10",
        body: { temp_token: fresh.temp_token, totp_code: generateTotpCode(TOTP_SECRET, later) }
    });
    assert.equal(completed.status, 200);
    const tokens = await responseData(completed);
    assert.match(tokens.refresh_token, /^rt_[a-f0-9]{64}$/u);

    const replay = await staged(db, STAGED_AUTH_PATHS.login2fa, {
        clock: () => later,
        ip: "203.0.113.10",
        body: { temp_token: fresh.temp_token, totp_code: generateTotpCode(TOTP_SECRET, later) }
    });
    assert.equal(replay.status, 400);
    db.close();
});

test("revoke-all invalidates access JWTs and every D1 refresh session", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const first = await login(db);
    const second = await login(db, { ip: "203.0.113.10" });

    const revoke = await staged(db, STAGED_AUTH_PATHS.revokeAll, {
        token: first.access_token,
        body: {}
    });
    assert.equal(revoke.status, 200);
    assert.equal(
        (await responseData(revoke)).message,
        "All sessions have been revoked. Please log in again."
    );
    assert.equal(
        (await db.prepare("SELECT token_version FROM users WHERE id = ?").bind(userId).first()).token_version,
        1
    );
    assert.equal((await db.prepare(`
        SELECT COUNT(*) AS count FROM auth_refresh_sessions
        WHERE user_id = ? AND revoked_at IS NULL
    `).bind(userId).first()).count, 0);

    const me = await staged(db, STAGED_AUTH_PATHS.me, {
        method: "GET",
        token: first.access_token
    });
    assert.equal(me.status, 401);
    assert.equal((await me.json()).code, "TOKEN_REVOKED");

    const refresh = await staged(db, STAGED_AUTH_PATHS.refresh, {
        body: { refresh_token: second.refresh_token }
    });
    assert.equal(refresh.status, 401);
    db.close();
});

test("logout revokes one refresh token and clears legacy OAuth cookies", async () => {
    const db = createDatabase();
    await insertUser(db);
    const authenticated = await login(db);
    const logout = await staged(db, STAGED_AUTH_PATHS.logout, {
        body: { refresh_token: authenticated.refresh_token }
    });
    assert.equal(logout.status, 200);
    assert.equal((await responseData(logout)).message, "Logged out successfully");
    const tokenHash = createHash("sha256").update(authenticated.refresh_token).digest("hex");
    assert.notEqual((await db.prepare(`
        SELECT revoked_at FROM auth_refresh_sessions WHERE token_hash = ?
    `).bind(tokenHash).first()).revoked_at, null);
    const cookies = typeof logout.headers.getSetCookie === "function"
        ? logout.headers.getSetCookie()
        : [logout.headers.get("set-cookie") ?? ""];
    assert.ok(cookies.some((cookie) => cookie.includes("oauth_pending_session=")));
    assert.ok(cookies.some((cookie) => cookie.includes("oauth_bind_access_token=")));
    db.close();
});

test("authenticated bind-token preparation stores the access token in an HttpOnly short-lived cookie", async () => {
    const db = createDatabase();
    await insertSetting(db, "backend_mode_enabled", "false");
    await insertSetting(db, "totp_enabled", "false");
    await insertUser(db, { role: "user", email: "bind@example.com" });
    const signedIn = await login(db, { email: "bind@example.com" });

    const response = await staged(db, STAGED_AUTH_PATHS.bindToken, {
        token: signedIn.access_token
    });
    assert.equal(response.status, 204);
    const cookie = response.headers.get("set-cookie");
    assert.match(cookie, /^oauth_bind_access_token=/u);
    assert.match(cookie, /Path=\/api\/v1\/auth\/oauth/u);
    assert.match(cookie, /Max-Age=600/u);
    assert.match(cookie, /HttpOnly/u);
    assert.match(cookie, /Secure/u);
});

test("staged auth routes are D1-native and do not fall back to BACKEND", async () => {
    const db = createDatabase();
    let backendCalled = false;
    const response = await routeRequest(
        new Request("https://edge.example/api/v1/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: "admin@example.com", password: "secret" })
        }),
        {
            DB: db,
            BACKEND: {
                async fetch() {
                    backendCalled = true;
                    return new Response("legacy", { status: 200 });
                }
            }
        }
    );
    assert.equal(response.status, 503);
    assert.equal(backendCalled, false);
    db.close();
});
