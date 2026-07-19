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

const JWT_SECRET = "admin-settings-test-jwt-secret-that-is-at-least-32-bytes-long";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const FIXED_NOW = Date.parse("2099-07-15T12:00:00.000Z");

function createDatabase(settings = {}) {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertUser(db, overrides = {}) {
    const values = {
        email: "admin@example.com",
        passwordHash: PASSWORD_HASH,
        role: "admin",
        status: "active",
        username: "administrator",
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
        0,
        null,
        "email"
    ).run();
    return Number(result.meta.last_row_id);
}

async function insertSetting(db, key, value) {
    await db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).bind(key, value, "2026-07-15T00:00:00.000Z").run();
}

async function getSetting(db, key) {
    const result = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
    return result?.value ?? null;
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET,
        JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600",
        JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30",
        TOTP_ENCRYPTION_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    };
}

async function createToken(db, role = "admin", userId = 1, email = "admin@example.com", passwordHash = PASSWORD_HASH) {
    const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, passwordHash, 0n);
    const signed = await signer.sign({
        id: userId,
        email,
        role,
        tokenVersion
    });
    return signed.token;
}

test("PUT /api/v1/admin/settings returns 401 without authorization header", async () => {
    const db = createDatabase();
    await insertUser(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ site_name: "Test" })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 401);
});

test("PUT /api/v1/admin/settings returns 403 for non-admin user", async () => {
    const db = createDatabase();
    const userId = await insertUser(db, { role: "user" });
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ site_name: "Test" })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 403);
});

test("GET /api/v1/admin/settings returns 200 with settings data", async () => {
    const db = createDatabase();
    await insertUser(db);
    await insertSetting(db, "site_name", "Test Site");
    await insertSetting(db, "registration_enabled", "true");
    await insertSetting(db, "default_balance", "100");
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.code, 0);
    assert.equal(body.data.site_name, "Test Site");
    assert.equal(body.data.registration_enabled, true);
    assert.equal(body.data.default_balance, 100);
});

test("GET /api/v1/admin/settings returns 401 without authorization", async () => {
    const db = createDatabase();
    await insertUser(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "GET"
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 401);
});

test("PUT /api/v1/admin/settings returns 400 for invalid JSON", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: "not valid json"
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("PUT /api/v1/admin/settings updates boolean settings", async () => {
    const db = createDatabase();
    await insertUser(db);
    await insertSetting(db, "registration_enabled", "false");
    await insertSetting(db, "totp_enabled", "false");
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            registration_enabled: true,
            totp_enabled: false
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.code, 0);
    assert.equal(body.data.updated_count, 2);

    assert.equal(await getSetting(db, "registration_enabled"), "true");
    assert.equal(await getSetting(db, "totp_enabled"), "false");
});

test("PUT /api/v1/admin/settings updates string settings", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            site_name: "My Site",
            site_subtitle: "A subtitle"
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    assert.equal(await getSetting(db, "site_name"), "My Site");
    assert.equal(await getSetting(db, "site_subtitle"), "A subtitle");
});

test("PUT /api/v1/admin/settings updates numeric settings", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            smtp_port: 587,
            default_concurrency: 10
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    assert.equal(await getSetting(db, "smtp_port"), "587");
    assert.equal(await getSetting(db, "default_concurrency"), "10");
});

test("PUT /api/v1/admin/settings validates TOTP requires encryption key", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            totp_enabled: true
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.reason, "totp_key_required");
});

test("PUT /api/v1/admin/settings validates Turnstile requires site key", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            turnstile_enabled: true,
            turnstile_site_key: ""
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.reason, "turnstile_site_key_required");
});

test("PUT /api/v1/admin/settings validates LinuxDo requires client ID and redirect URL", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            linuxdo_connect_enabled: true,
            linuxdo_connect_client_id: "",
            linuxdo_connect_redirect_url: "https://example.com/callback"
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.reason, "linuxdo_client_id_required");
});

test("PUT /api/v1/admin/settings validates DingTalk requires client ID and redirect URL", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            dingtalk_connect_enabled: true,
            dingtalk_connect_client_id: "test",
            dingtalk_connect_redirect_url: ""
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.reason, "dingtalk_redirect_url_required");
});

test("PUT /api/v1/admin/settings validates login agreement requires documents", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            login_agreement_enabled: true,
            login_agreement_documents: []
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.reason, "login_agreement_documents_required");
});

test("PUT /api/v1/admin/settings normalizes DingTalk corp policy", async () => {
    const db = createDatabase();
    await insertUser(db);
    await insertSetting(db, "dingtalk_connect_corp_restriction_policy", "whitelist");
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            dingtalk_connect_corp_restriction_policy: "whitelist"
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    assert.equal(await getSetting(db, "dingtalk_connect_corp_restriction_policy"), "none");
});

test("PUT /api/v1/admin/settings normalizes login agreement mode", async () => {
    const db = createDatabase();
    await insertUser(db);
    const token = await createToken(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            login_agreement_mode: "invalid"
        })
    });

    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    assert.equal(await getSetting(db, "login_agreement_mode"), "modal");
});

test("PUT /api/v1/admin/settings returns 503 without DB binding", async () => {
    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ site_name: "Test" })
    });

    const response = await routeRequest(request, { JWT_SECRET });
    assert.equal(response.status, 503);
});

test("PUT /api/v1/admin/settings returns 503 without JWT secret", async () => {
    const db = createDatabase();
    await insertUser(db);

    const request = new Request("https://edge.example/api/v1/admin/settings", {
        method: "PUT",
        headers: {
            authorization: "Bearer dummy-token",
            "content-type": "application/json"
        },
        body: JSON.stringify({ site_name: "Test" })
    });

    const response = await routeRequest(request, { DB: db });
    assert.equal(response.status, 503);
});
