import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

const JWT_SECRET = "api-keys-test-jwt-secret-that-is-at-least-32-bytes-long";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertUser(db, overrides = {}) {
    const values = {
        email: "user@example.com",
        passwordHash: PASSWORD_HASH,
        role: "user",
        status: "active",
        username: "testuser",
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
    return Number(result.meta?.last_row_id ?? 0);
}

async function insertApiKey(db, overrides = {}) {
    const values = {
        key: "sk-test1234567890abcdef",
        name: "Test Key",
        userId: 1,
        status: "active",
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO api_keys (
            created_at, updated_at, key, name, status, user_id, group_id,
            ip_whitelist, ip_blacklist, quota, quota_used, expires_at,
            rate_limit_5h, rate_limit_1d, rate_limit_7d,
            usage_5h, usage_1d, usage_7d
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 0, 0, 0)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        values.key,
        values.name,
        values.status,
        values.userId,
        null,
        "[]",
        "[]",
        0,
        null,
        0,
        0,
        0
    ).run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function createToken(db, role = "user", userId = 1, email = "user@example.com") {
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: userId, email, role, tokenVersion });
    return signed.token;
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET,
        JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600",
        JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30"
    };
}

test("GET /api/v1/keys returns 401 without authorization", async () => {
    const db = createDatabase();
    const request = new Request("https://edge.example/api/v1/keys", { method: "GET" });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 401);
});

test("GET /api/v1/keys returns empty list for user with no keys", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.code, 0);
    assert.equal(body.data.items.length, 0);
    assert.equal(body.data.total, 0);
});

test("GET /api/v1/keys returns list of keys", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    await insertApiKey(db, { userId, name: "Key 1", key: "sk-key1-1234567890abcdef" });
    await insertApiKey(db, { userId, name: "Key 2", key: "sk-key2-1234567890abcdef" });
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.code, 0);
    assert.equal(body.data.items.length, 2);
    assert.equal(body.data.total, 2);
    assert.equal(body.data.items[0].key.includes("****"), true);
});

test("POST /api/v1/keys creates a new key", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ name: "My New Key" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.code, 0);
    assert.equal(body.data.name, "My New Key");
    assert.ok(body.data.key.startsWith("sk-"));
    assert.equal(body.data.status, "active");
});

test("POST /api/v1/keys rejects duplicate custom key", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    await insertApiKey(db, { userId, key: "sk-custom-key-12345678" });
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ name: "Duplicate", key: "sk-custom-key-12345678" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 409);
});

test("POST /api/v1/keys rejects short custom key", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ name: "Short Key", key: "sk-short" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.reason, "key_too_short");
});

test("POST /api/v1/keys requires name", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({})
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.reason, "name_required");
});

test("GET /api/v1/keys/:id returns key by ID", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const keyId = await insertApiKey(db, { userId, name: "Specific Key", key: "sk-specific-1234567890" });
    const token = await createToken(db, "user", userId);

    const request = new Request(`https://edge.example/api/v1/keys/${keyId}`, {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "Specific Key");
    assert.equal(body.data.key.includes("****"), true);
});

test("GET /api/v1/keys/:id returns 404 for non-existent key", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys/99999", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 404);
});

test("PUT /api/v1/keys/:id updates key name", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const keyId = await insertApiKey(db, { userId, name: "Old Name", key: "sk-updatable-1234567890" });
    const token = await createToken(db, "user", userId);

    const request = new Request(`https://edge.example/api/v1/keys/${keyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ name: "New Name" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "New Name");
});

test("PUT /api/v1/keys/:id updates key status", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const keyId = await insertApiKey(db, { userId, name: "Toggle Key", key: "sk-toggle-1234567890" });
    const token = await createToken(db, "user", userId);

    const request = new Request(`https://edge.example/api/v1/keys/${keyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ status: "disabled" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.status, "disabled");
});

test("PUT /api/v1/keys/:id rejects invalid status", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const keyId = await insertApiKey(db, { userId, key: "sk-invalid-1234567890" });
    const token = await createToken(db, "user", userId);

    const request = new Request(`https://edge.example/api/v1/keys/${keyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ status: "invalid_status" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("DELETE /api/v1/keys/:id deletes key with audit", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const keyId = await insertApiKey(db, { userId, name: "Delete Me", key: "sk-delete-1234567890" });
    const token = await createToken(db, "user", userId);

    const request = new Request(`https://edge.example/api/v1/keys/${keyId}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);

    const audit = await db.prepare("SELECT * FROM deleted_api_key_audits WHERE api_key_id = ?").bind(keyId).first();
    assert.ok(audit);
    assert.equal(audit.key, "sk-delete-1234567890");
    assert.equal(audit.key_name, "Delete Me");
});

test("DELETE /api/v1/keys/:id returns 404 for non-existent key", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys/99999", {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 404);
});

test("PUT /api/v1/keys/:id resets quota usage", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const keyId = await insertApiKey(db, { userId, key: "sk-reset-1234567890" });
    await db.prepare("UPDATE api_keys SET quota_used = 50 WHERE id = ?").bind(keyId).run();
    const token = await createToken(db, "user", userId);

    const request = new Request(`https://edge.example/api/v1/keys/${keyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ reset_quota: true })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.quotaUsed, 0);
});

test("GET /api/v1/keys supports search filter", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    await insertApiKey(db, { userId, name: "Production Key", key: "sk-prod-1234567890abcdef" });
    await insertApiKey(db, { userId, name: "Development Key", key: "sk-dev-1234567890abcdef" });
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys?search=prod", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.items.length, 1);
    assert.equal(body.data.items[0].name, "Production Key");
});

test("GET /api/v1/keys supports status filter", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    await insertApiKey(db, { userId, name: "Active", key: "sk-active-1234567890abcdef", status: "active" });
    await insertApiKey(db, { userId, name: "Disabled", key: "sk-disabled-1234567890abcdef", status: "disabled" });
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys?status=disabled", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.items.length, 1);
    assert.equal(body.data.items[0].name, "Disabled");
});

test("GET /api/v1/keys supports pagination", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    for (let i = 0; i < 5; i++) {
        await insertApiKey(db, { userId, name: `Key ${i}`, key: `sk-page${i}-1234567890abcdef` });
    }
    const token = await createToken(db, "user", userId);

    const request = new Request("https://edge.example/api/v1/keys?page=2&page_size=2", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.items.length, 2);
    assert.equal(body.data.total, 5);
    assert.equal(body.data.page, 2);
});
