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

const JWT_SECRET = "admin-backups-test-secret-key-32-bytes-long!";
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

function env(db) {
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30", TOTP_ENCRYPTION_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" };
}

async function createToken(db) {
    const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion("admin@x.com", PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: 1, email: "admin@x.com", role: "admin", tokenVersion });
    return signed.token;
}

const BASE = "https://edge.example/api/v1/admin/backups";

test("admin backup routes", async (t) => {
    // === Auth ===
    await t.test("returns 401 without auth", async () => {
        const d = createDatabase();
        const r = await routeRequest(new Request(`${BASE}/s3-config`), env(d));
        assert.equal(r.status, 401);
    });

    // === S3 Config ===
    await t.test("GET /s3-config returns default disabled config", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3-config`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.enabled, false);
    });

    await t.test("PUT /s3-config updates config and returns masked secret", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3-config`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: true, endpoint: "https://s3.example.com", bucket: "my-bucket", access_key_id: "AKIA123", secret_access_key: "supersecretkey12345678" })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.endpoint, "https://s3.example.com");
        assert.equal(j.data.bucket, "my-bucket");
        assert.equal(j.data.access_key_id, "AKIA123");
        assert.ok(j.data.secret_access_key.includes("****"));
    });

    await t.test("POST /s3-config/test returns not-available in serverless", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3-config/test`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.success, false);
    });

    // === Schedule ===
    await t.test("GET /schedule returns default schedule", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/schedule`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.enabled, false);
        assert.equal(j.data.retain_days, 14);
    });

    await t.test("PUT /schedule updates schedule", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/schedule`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: true, cron_expr: "0 2 * * *", retain_days: 7, retain_count: 30 })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.cron_expr, "0 2 * * *");
        assert.equal(j.data.retain_days, 7);
        assert.equal(j.data.retain_count, 30);
    });

    await t.test("PUT /schedule rejects invalid cron", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/schedule`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ cron_expr: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    // === Backup Records ===
    await t.test("GET / returns empty list", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(BASE, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST / creates a backup record", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(BASE, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ expire_days: 7 })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.status, "running");
        assert.equal(j.data.type, "manual");
        assert.equal(j.data.expire_days, 7);
        assert.ok(j.data.id > 0);
    });

    await t.test("GET / returns created records", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        // Create two backups
        await routeRequest(new Request(BASE, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ expire_days: 14 })
        }), env(d));
        await routeRequest(new Request(BASE, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ expire_days: 7 })
        }), env(d));
        const r = await routeRequest(new Request(BASE, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.total, 2);
        assert.equal(j.data.items.length, 2);
    });

    await t.test("GET /:id returns a backup record", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const createR = await routeRequest(new Request(BASE, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({})
        }), env(d));
        const createJ = await createR.json();
        const id = createJ.data.id;
        const r = await routeRequest(new Request(`${BASE}/${id}`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.id, id);
    });

    await t.test("GET /:id returns 404 for nonexistent", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/999`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("DELETE /:id deletes a backup record", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const createR = await routeRequest(new Request(BASE, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({})
        }), env(d));
        const createJ = await createR.json();
        const id = createJ.data.id;
        const r = await routeRequest(new Request(`${BASE}/${id}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        // Verify it's gone
        const getR = await routeRequest(new Request(`${BASE}/${id}`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(getR.status, 404);
    });

    await t.test("DELETE /:id returns 404 for nonexistent", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /:id/download-url returns not-available", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const createR = await routeRequest(new Request(BASE, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({})
        }), env(d));
        const createJ = await createR.json();
        const id = createJ.data.id;
        const r = await routeRequest(new Request(`${BASE}/${id}/download-url`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.message, "Pre-signed download URLs are not available in serverless mode");
    });

    await t.test("POST /:id/restore returns not-available", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const createR = await routeRequest(new Request(BASE, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({})
        }), env(d));
        const createJ = await createR.json();
        const id = createJ.data.id;
        const r = await routeRequest(new Request(`${BASE}/${id}/restore`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ password: "test123" })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.success, false);
    });

    // === Auth check ===
    await t.test("returns 403 for non-admin user", async () => {
        const d = createDatabase();
        await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind(
            "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "user@x.com", PASSWORD_HASH, "user", "active", "testuser", 0, null, "email"
        ).run();
        const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
        const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
        const tokenVersion = await legacyTokenVersion("user@x.com", PASSWORD_HASH, 0n);
        const signed = await signer.sign({ id: 1, email: "user@x.com", role: "user", tokenVersion });
        const r = await routeRequest(new Request(`${BASE}/s3-config`, {
            method: "GET", headers: { authorization: `Bearer ${signed.token}` }
        }), env(d));
        assert.equal(r.status, 403);
    });
});
