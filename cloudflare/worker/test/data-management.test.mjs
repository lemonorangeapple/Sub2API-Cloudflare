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

const JWT_SECRET = "data-mgmt-test-secret-key-32-bytes-long!";
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
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" };
}

async function createToken(db, userId = 1, email = "admin@x.com", role = "admin") {
    const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: userId, email, role, tokenVersion });
    return signed.token;
}

const BASE = "https://edge.example/api/v1/admin/data-management";

test("data management routes", async (t) => {
    // === Auth ===
    await t.test("returns 401 without auth on non-health routes", async () => {
        const d = createDatabase();
        const r = await routeRequest(new Request(`${BASE}/config`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("returns 403 for non-admin user", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d, 1, "user@x.com", "user");
        const r = await routeRequest(new Request(`${BASE}/config`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 403);
    });

    // === Agent Health (always 200, even without auth) ===
    await t.test("GET /agent/health returns 200 with deprecated reason (no auth required)", async () => {
        const d = createDatabase();
        const r = await routeRequest(new Request(`${BASE}/agent/health`), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.enabled, false);
        assert.equal(j.data.reason, "DATA_MANAGEMENT_DEPRECATED");
        assert.equal(j.data.socket_path, "/tmp/sub2api-datamanagement.sock");
    });

    // === Config ===
    await t.test("GET /config returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/config`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
        const j = await r.json();
        assert.equal(j.error.code, "DATA_MANAGEMENT_DEPRECATED");
    });

    await t.test("PUT /config returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/config`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ source_mode: "sqlite" })
        }), env(d));
        assert.equal(r.status, 503);
    });

    // === Source Profiles (postgres) ===
    await t.test("GET /sources/postgres/profiles returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/sources/postgres/profiles`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("POST /sources/postgres/profiles returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/sources/postgres/profiles`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ name: "test" })
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("PUT /sources/postgres/profiles/:id returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/sources/postgres/profiles/p1`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ name: "updated" })
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("DELETE /sources/postgres/profiles/:id returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/sources/postgres/profiles/p1`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("POST /sources/postgres/profiles/:id/activate returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/sources/postgres/profiles/p1/activate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    // === Source Profiles (redis) ===
    await t.test("GET /sources/redis/profiles returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/sources/redis/profiles`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    // === S3 ===
    await t.test("POST /s3/test returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3/test`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ endpoint: "https://s3.example.com" })
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("GET /s3/profiles returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3/profiles`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("POST /s3/profiles returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3/profiles`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ name: "test-s3" })
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("PUT /s3/profiles/:id returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3/profiles/s3-1`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ name: "updated" })
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("DELETE /s3/profiles/:id returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3/profiles/s3-1`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("POST /s3/profiles/:id/activate returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/s3/profiles/s3-1/activate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    // === Backups ===
    await t.test("POST /backups returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/backups`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "Content-Type": "application/json" },
            body: JSON.stringify({ backup_type: "full" })
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("GET /backups returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/backups`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });

    await t.test("GET /backups/:job_id returns 503 deprecated", async () => {
        const d = createDatabase();
        await insertAdmin(d);
        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/backups/job-123`, {
            method: "GET", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 503);
    });
});
