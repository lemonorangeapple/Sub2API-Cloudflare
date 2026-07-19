import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

const JWT_SECRET = "admin-oauth-test-secret-key-32-bytes-long!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertAdmin(db) {
    await db.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email"
    ).run();
}

async function insertUser(db) {
    await db.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "user@x.com", PASSWORD_HASH, "user", "active", "testuser", 0, null, "email"
    ).run();
}

function env(db) {
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30", TOTP_ENCRYPTION_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" };
}

async function createToken(db, userId = 1, email = "admin@x.com", passwordHash = PASSWORD_HASH, role = "admin") {
    const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, passwordHash, 0n);
    const signed = await signer.sign({ id: userId, email, role, tokenVersion });
    return signed.token;
}

const BASE = "https://edge.example/api/v1/admin";

test("admin OAuth routes", async (t) => {
    // === Auth & Authorization ===
    await t.test("returns 401 without auth", async () => {
        const d = createDatabase();
        for (const path of [
            `${BASE}/openai/generate-auth-url`,
            `${BASE}/gemini/oauth/auth-url`,
            `${BASE}/antigravity/oauth/auth-url`,
            `${BASE}/grok/oauth/auth-url`,
        ]) {
            const r = await routeRequest(new Request(path, { method: "POST" }), env(d));
            assert.equal(r.status, 401, `Expected 401 for ${path} got ${r.status}`);
        }
    });

    await t.test("returns 403 for non-admin user", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d, 1, "user@x.com", PASSWORD_HASH, "user");
        const r = await routeRequest(new Request(`${BASE}/openai/generate-auth-url`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 403);
    });

    // === Grok ===
    await t.test("POST grok/oauth/auth-url returns auth_url, session_id, state", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/oauth/auth-url`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.ok(j.data.auth_url.startsWith("https://auth.x.ai/oauth2/authorize?"));
        assert.ok(j.data.auth_url.includes("response_type=code"));
        assert.ok(j.data.auth_url.includes("client_id=b1a00492"));
        assert.ok(typeof j.data.session_id === "string" && j.data.session_id.length > 0);
        assert.ok(typeof j.data.state === "string" && j.data.state.length > 0);
    });

    await t.test("POST grok/oauth/exchange-code returns 400 for expired session", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/oauth/exchange-code`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: "nonexistent", code: "c", state: "s" })
        }), env(d));
        assert.equal(r.status, 400);
        const j = await r.json();
        assert.ok(j.message.includes("expired or not found"));
    });

    await t.test("POST grok/oauth/create-from-oauth returns 400 for expired session", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/oauth/create-from-oauth`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: "nosession", code: "c", state: "s" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST grok/sso-to-oauth creates accounts from SSO tokens", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/sso-to-oauth`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ sso_tokens: ["sso-token-1", "sso-token-2"], name: "SSO Import" })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.created.length, 2);
        assert.equal(j.data.created[0].platform, "grok");
        assert.equal(j.data.created[0].type, "oauth");
    });

    await t.test("POST grok/accounts/999/refresh returns 404 for missing account", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/accounts/999/refresh`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET grok/accounts/1/quota returns 404 for missing account", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/accounts/1/quota`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("POST grok/accounts/1/reset-quota returns not-available", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/accounts/1/reset-quota`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.success, false);
    });

    await t.test("GET grok/runtime-sanity returns ok", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/grok/runtime-sanity`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.status, "ok");
    });

    // === OpenAI ===
    await t.test("POST openai/generate-auth-url returns auth_url and session_id", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/openai/generate-auth-url`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.ok(j.data.auth_url.startsWith("https://auth.openai.com/oauth/authorize?"));
        assert.ok(j.data.auth_url.includes("client_id=app_EMoamEEZ73f0CkXaXp7hrann"));
        assert.ok(typeof j.data.session_id === "string");
    });

    await t.test("POST openai/exchange-code returns 400 for expired session", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/openai/exchange-code`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: "invalid", code: "c", state: "s" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST openai/create-from-codex-pat creates account from PAT", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/openai/create-from-codex-pat`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ access_token: "at-test-token", name: "My PAT", concurrency: 5, priority: 30 })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.platform, "openai");
        assert.equal(j.data.type, "oauth");
        assert.equal(j.data.name, "My PAT");
        assert.equal(j.data.concurrency, 5);
        assert.equal(j.data.priority, 30);
        assert.equal(j.data.credentials.access_token, "at-test-token");
        assert.equal(j.data.extra.import_source, "codex_personal_access_token");
    });

    await t.test("POST openai/create-from-oauth returns 400 for expired session", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/openai/create-from-oauth`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: "x", code: "c", state: "s" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST openai/accounts/999/refresh returns 404 for missing account", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/openai/accounts/999/refresh`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    // === Gemini ===
    await t.test("GET gemini/oauth/capabilities returns capabilities", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/gemini/oauth/capabilities`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.ai_studio_oauth_enabled, false);
        assert.ok(Array.isArray(j.data.required_redirect_uris));
    });

    await t.test("POST gemini/oauth/auth-url returns auth_url", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/gemini/oauth/auth-url`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ oauth_type: "code_assist" })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.ok(j.data.auth_url.startsWith("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert.ok(j.data.auth_url.includes("client_id=681255809395"));
        assert.ok(typeof j.data.session_id === "string");
    });

    await t.test("POST gemini/oauth/exchange-code returns 400 for expired session", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/gemini/oauth/exchange-code`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: "x", code: "c", state: "s" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    // === Antigravity ===
    await t.test("POST antigravity/oauth/auth-url returns auth_url", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/antigravity/oauth/auth-url`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.ok(j.data.auth_url.startsWith("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert.ok(j.data.auth_url.includes("client_id=1071006060591"));
    });

    await t.test("POST antigravity/oauth/exchange-code returns 400 for expired session", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/antigravity/oauth/exchange-code`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: "x", code: "c", state: "s" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    // === Method validation ===
    await t.test("GET actions reject POST and vice versa", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r1 = await routeRequest(new Request(`${BASE}/grok/runtime-sanity`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r1.status, 405);
        const r2 = await routeRequest(new Request(`${BASE}/grok/oauth/auth-url`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r2.status, 405);
    });
});
