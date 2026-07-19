import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1AuthSessionRepository } from "../src/repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../src/repositories/auth-users.ts";
import { AuthTokenService } from "../src/services/auth-tokens.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { PasswordAuthError, PasswordAuthService } from "../src/services/password-auth.ts";
import { TurnstileVerificationError, TurnstileVerifier } from "../src/services/turnstile.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const coreMigration = await readFile(
    new URL("../../d1/migrations/0001_ent_core.sql", import.meta.url),
    "utf8"
);
const supplementalMigration = await readFile(
    new URL("../../d1/migrations/0002_business_supplemental.sql", import.meta.url),
    "utf8"
);
const authMigration = await readFile(
    new URL("../../d1/migrations/0005_auth_sessions.sql", import.meta.url),
    "utf8"
);
const workerPackage = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const workerLock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));

const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const JWT_SECRET = "test-jwt-secret-that-is-at-least-32-bytes-long";
const FIXED_NOW = Date.parse("2026-07-15T12:00:00.000Z");

function createDatabase() {
    const db = new SQLiteD1Database();
    db.exec(coreMigration);
    db.exec(supplementalMigration);
    db.exec(authMigration);
    return db;
}

async function insertUser(db, overrides = {}) {
    const values = {
        email: "admin@example.com",
        passwordHash: PASSWORD_HASH,
        role: "admin",
        status: "active",
        username: "administrator",
        totpEnabled: 0,
        tokenVersion: 0,
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO users (
            created_at,
            updated_at,
            email,
            password_hash,
            role,
            status,
            username,
            totp_enabled,
            token_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        values.email,
        values.passwordHash,
        values.role,
        values.status,
        values.username,
        values.totpEnabled,
        values.tokenVersion
    ).run();
    return result.meta.last_row_id;
}

function createAuthService(db, verifier) {
    const users = new D1AuthUserRepository(db);
    const sessions = new D1AuthSessionRepository(db);
    const jwt = new Hs256JwtSigner(JWT_SECRET, 3600, () => FIXED_NOW);
    const tokens = new AuthTokenService(sessions, jwt, 30, () => FIXED_NOW);
    return new PasswordAuthService(users, verifier, tokens, () => FIXED_NOW);
}

function decodeBase64Url(value) {
    return Buffer.from(value, "base64url").toString("utf8");
}

function expectedLegacyTokenVersion(email, passwordHash, stored = 0n) {
    const digest = createHash("sha256")
        .update(`${email.trim().toLowerCase()}\n${passwordHash}`)
        .digest();
    let fingerprint = 0n;
    for (let index = 0; index < 8; index += 1) {
        fingerprint = (fingerprint << 8n) | BigInt(digest[index]);
    }
    return stored ^ (fingerprint & 0x7fffffffffffffffn);
}

async function expectAuthError(promise, code, status) {
    await assert.rejects(promise, (error) => {
        assert.ok(error instanceof PasswordAuthError);
        assert.equal(error.code, code);
        assert.equal(error.status, status);
        return true;
    });
}

test("bcryptjs production dependency is pinned with integrity metadata", () => {
    assert.equal(workerPackage.dependencies.bcryptjs, "3.0.3");
    const locked = workerLock.packages["node_modules/bcryptjs"];
    assert.equal(locked.version, "3.0.3");
    assert.match(locked.integrity, /^sha512-/u);
});

test("administrator password authentication issues a legacy-compatible JWT and hashed D1 refresh session", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const calls = [];
    const verifier = {
        async verify(password, hash) {
            calls.push({ password, hash });
            return password === "correct-password" && hash === PASSWORD_HASH;
        }
    };
    const service = createAuthService(db, verifier);

    const response = await service.loginAdministrator(" ADMIN@example.com ", "correct-password");
    assert.equal(response.token_type, "Bearer");
    assert.equal(response.expires_in, 3600);
    assert.equal(response.user.id, userId);
    assert.equal(response.user.role, "admin");
    assert.equal(response.user.allowed_groups, null);
    assert.equal(response.user.last_active_at, "2026-07-15T12:00:00.000Z");
    assert.match(response.refresh_token, /^rt_[a-f0-9]{64}$/u);
    assert.deepEqual(calls, [{ password: "correct-password", hash: PASSWORD_HASH }]);

    const [headerSegment, payloadSegment, signatureSegment] = response.access_token.split(".");
    assert.deepEqual(JSON.parse(decodeBase64Url(headerSegment)), { alg: "HS256", typ: "JWT" });
    const payloadText = decodeBase64Url(payloadSegment);
    const payload = JSON.parse(payloadText);
    assert.equal(payload.user_id, userId);
    assert.equal(payload.email, "admin@example.com");
    assert.equal(payload.role, "admin");
    assert.equal(payload.exp - payload.iat, 3600);
    assert.equal(payload.nbf, payload.iat);

    const rawTokenVersion = payloadText.match(/"token_version":(\d+)/u)?.[1];
    assert.equal(rawTokenVersion, expectedLegacyTokenVersion("admin@example.com", PASSWORD_HASH).toString());
    const expectedSignature = createHmac("sha256", JWT_SECRET)
        .update(`${headerSegment}.${payloadSegment}`)
        .digest("base64url");
    assert.equal(signatureSegment, expectedSignature);

    const stored = await db.prepare(`
        SELECT token_hash, token_version, family_id, expires_at
        FROM auth_refresh_sessions
        WHERE user_id = ?
    `).bind(userId).first();
    assert.notEqual(stored.token_hash, response.refresh_token);
    assert.equal(
        stored.token_hash,
        createHash("sha256").update(response.refresh_token).digest("hex")
    );
    assert.equal(stored.token_version, rawTokenVersion);
    assert.match(stored.family_id, /^[a-f0-9]{32}$/u);
    assert.equal(stored.expires_at, FIXED_NOW + 30 * 24 * 60 * 60 * 1000);

    const updated = await db.prepare("SELECT last_login_at, last_active_at FROM users WHERE id = ?")
        .bind(userId)
        .first();
    assert.equal(updated.last_login_at, "2026-07-15T12:00:00.000Z");
    assert.equal(updated.last_active_at, "2026-07-15T12:00:00.000Z");
    db.close();
});

test("unknown users and wrong passwords share the invalid-credentials response", async () => {
    const db = createDatabase();
    await insertUser(db);
    const seenHashes = [];
    const verifier = {
        async verify(_password, hash) {
            seenHashes.push(hash);
            return false;
        }
    };
    const service = createAuthService(db, verifier);

    await expectAuthError(
        service.loginAdministrator("missing@example.com", "wrong-password"),
        "invalid_credentials",
        401
    );
    await expectAuthError(
        service.loginAdministrator("admin@example.com", "wrong-password"),
        "invalid_credentials",
        401
    );
    assert.equal(seenHashes.length, 2);
    assert.equal(seenHashes[1], PASSWORD_HASH);
    assert.match(seenHashes[0], /^\$2b\$10\$/u);
    assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM auth_refresh_sessions").first()).count, 0);
    db.close();
});

test("inactive, non-admin, and TOTP administrators fail closed before token issuance", async () => {
    for (const scenario of [
        { overrides: { status: "disabled" }, code: "user_not_active", status: 401 },
        { overrides: { role: "user" }, code: "admin_required", status: 403 },
        { overrides: { totpEnabled: 1 }, code: "totp_required", status: 409 }
    ]) {
        const db = createDatabase();
        await insertUser(db, scenario.overrides);
        const service = createAuthService(db, { async verify() { return true; } });
        await expectAuthError(
            service.loginAdministrator("admin@example.com", "correct-password"),
            scenario.code,
            scenario.status
        );
        assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM auth_refresh_sessions").first()).count, 0);
        db.close();
    }
});

test("Turnstile verifier sends server-side validation and fails closed", async () => {
    let captured;
    const verifier = new TurnstileVerifier("turnstile-secret", async (url, init) => {
        captured = { url, init };
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { "content-type": "application/json" }
        });
    });
    await verifier.verify("client-token", "203.0.113.10");
    assert.equal(captured.url, "https://challenges.cloudflare.com/turnstile/v0/siteverify");
    assert.equal(captured.init.method, "POST");
    assert.deepEqual(JSON.parse(captured.init.body), {
        secret: "turnstile-secret",
        response: "client-token",
        remoteip: "203.0.113.10"
    });

    const rejecting = new TurnstileVerifier("turnstile-secret", async () => new Response(
        JSON.stringify({ success: false, "error-codes": ["timeout-or-duplicate"] }),
        { status: 200 }
    ));
    await assert.rejects(rejecting.verify("client-token"), (error) => {
        assert.ok(error instanceof TurnstileVerificationError);
        assert.deepEqual(error.codes, ["timeout-or-duplicate"]);
        return true;
    });
});
