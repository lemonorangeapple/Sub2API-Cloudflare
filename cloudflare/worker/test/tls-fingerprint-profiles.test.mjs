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

const JWT_SECRET = "tls-profile-test-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertAdmin(db, overrides = {}) {
    const values = {
        email: "admin@example.com",
        passwordHash: PASSWORD_HASH,
        role: "admin",
        status: "active",
        username: "admin",
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO users (created_at, updated_at, email, password_hash, role, status, username, totp_enabled, totp_secret_encrypted, signup_source, token_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", values.email, values.passwordHash, values.role, values.status, values.username, 0, null, "email").run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function insertUser(db, overrides = {}) {
    const result = await db.prepare(`
        INSERT INTO users (created_at, updated_at, email, password_hash, role, status, username, totp_enabled, totp_secret_encrypted, signup_source, token_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "user@example.com", PASSWORD_HASH, "user", "active", "testuser", 0, null, "email").run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function insertProfile(db, overrides = {}) {
    const now = "2026-07-01T00:00:00.000Z";
    const defaults = {
        name: "Default Profile",
        description: null,
        enable_grease: 0,
        cipher_suites: null,
        curves: null,
        point_formats: null,
        signature_algorithms: null,
        alpn_protocols: null,
        supported_versions: null,
        key_share_groups: null,
        psk_modes: null,
        extensions: null
    };
    const values = { ...defaults, ...overrides };
    const result = await db.prepare(`
        INSERT INTO tls_fingerprint_profiles (created_at, updated_at, name, description, enable_grease, cipher_suites, curves, point_formats, signature_algorithms, alpn_protocols, supported_versions, key_share_groups, psk_modes, extensions)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(now, now, values.name, values.description, values.enable_grease, values.cipher_suites, values.curves, values.point_formats, values.signature_algorithms, values.alpn_protocols, values.supported_versions, values.key_share_groups, values.psk_modes, values.extensions).run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function createAdminToken(db, userId = 1) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion("admin@example.com", PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: userId, email: "admin@example.com", role: "admin", tokenVersion });
    return signed.token;
}

async function createUserToken(db, userId = 1) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion("user@example.com", PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: userId, email: "user@example.com", role: "user", tokenVersion });
    return signed.token;
}

function env(db) {
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" };
}

test("GET /api/v1/admin/tls-fingerprint-profiles returns 401 without auth", async () => {
    const db = createDatabase();
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles"), env(db));
    assert.equal(response.status, 401);
});

test("GET /api/v1/admin/tls-fingerprint-profiles returns 403 for non-admin", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createUserToken(db, userId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(response.status, 403);
});

test("GET /api/v1/admin/tls-fingerprint-profiles returns empty list", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.length, 0);
});

test("GET /api/v1/admin/tls-fingerprint-profiles returns list", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProfile(db, { name: "Profile A" });
    await insertProfile(db, { name: "Profile B" });
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.length, 2);
});

test("GET /api/v1/admin/tls-fingerprint-profiles/:id returns profile", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const id = await insertProfile(db, { name: "My Profile", description: "Test desc" });
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request(`https://edge.example/api/v1/admin/tls-fingerprint-profiles/${id}`, {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "My Profile");
    assert.equal(body.data.description, "Test desc");
});

test("GET /api/v1/admin/tls-fingerprint-profiles/:id returns 404", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles/99999", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(response.status, 404);
});

test("POST /api/v1/admin/tls-fingerprint-profiles creates profile", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "Chrome 120", enable_grease: true, cipher_suites: [0x1301, 0x1302], alpn_protocols: ["h2", "http/1.1"] })
    }), env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "Chrome 120");
    assert.equal(body.data.enableGrease, true);
    assert.deepEqual(body.data.cipherSuites, [0x1301, 0x1302]);
    assert.deepEqual(body.data.alpnProtocols, ["h2", "http/1.1"]);
});

test("POST rejects duplicate name", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProfile(db, { name: "Existing" });
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "Existing" })
    }), env(db));
    assert.equal(response.status, 409);
});

test("POST rejects empty name", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "" })
    }), env(db));
    assert.equal(response.status, 400);
});

test("PUT /api/v1/admin/tls-fingerprint-profiles/:id updates profile", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const id = await insertProfile(db, { name: "Old Name" });
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request(`https://edge.example/api/v1/admin/tls-fingerprint-profiles/${id}`, {
        method: "PUT",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "New Name", enable_grease: true })
    }), env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "New Name");
    assert.equal(body.data.enableGrease, true);
});

test("PUT rejects name conflict", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProfile(db, { name: "Existing" });
    const id = await insertProfile(db, { name: "Target" });
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request(`https://edge.example/api/v1/admin/tls-fingerprint-profiles/${id}`, {
        method: "PUT",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "Existing" })
    }), env(db));
    assert.equal(response.status, 409);
});

test("DELETE /api/v1/admin/tls-fingerprint-profiles/:id deletes profile", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const id = await insertProfile(db, { name: "Delete Me" });
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request(`https://edge.example/api/v1/admin/tls-fingerprint-profiles/${id}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(response.status, 200);
    const check = await db.prepare("SELECT id FROM tls_fingerprint_profiles WHERE id = ?").bind(id).first();
    assert.equal(check, null);
});

test("DELETE returns 404 for non-existent", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const response = await routeRequest(new Request("https://edge.example/api/v1/admin/tls-fingerprint-profiles/99999", {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(response.status, 404);
});
