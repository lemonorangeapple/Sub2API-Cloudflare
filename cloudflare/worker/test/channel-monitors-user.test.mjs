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

const JWT_SECRET = "cm-user-test-secret-key-32-bytes-long!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertUser(db, overrides = {}) {
    const values = { email: "user@x.com", passwordHash: PASSWORD_HASH, role: "user", status: "active", username: "testuser", ...overrides };
    await db.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", values.email, values.passwordHash, values.role, values.status, values.username, 0, null, "email"
    ).run();
}

function env(db) {
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30", TOTP_ENCRYPTION_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" };
}

async function createToken(db, userId = 1, email = "user@x.com", passwordHash = PASSWORD_HASH) {
    const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, passwordHash, 0n);
    const signed = await signer.sign({ id: userId, email, role: "user", tokenVersion });
    return signed.token;
}

const BASE = "https://edge.example/api/v1/channel-monitors";

test("user-facing channel monitors", async (t) => {
    await t.test("GET / returns empty list when no monitors", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(BASE, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data.items));
        assert.equal(j.data.items.length, 0);
    });

    await t.test("GET / returns enabled monitors only", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        await d.prepare(`INSERT INTO channel_monitors (created_at,updated_at,name,provider,api_mode,endpoint,api_key_encrypted,primary_model,extra_models,group_name,enabled,interval_seconds,created_by,extra_headers) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "Monitor A", "openai", "chat_completions", "https://api.openai.com", "enc-key", "gpt-4", "[]", "group1", 1, 60, 1, "{}"
        ).run();
        await d.prepare(`INSERT INTO channel_monitors (created_at,updated_at,name,provider,api_mode,endpoint,api_key_encrypted,primary_model,extra_models,group_name,enabled,interval_seconds,created_by,extra_headers) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "Monitor B", "anthropic", "chat_completions", "https://api.anthropic.com", "enc-key2", "claude-3", '["claude-3-opus"]', "group2", 0, 120, 1, "{}"
        ).run();

        const r = await routeRequest(new Request(BASE, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].name, "Monitor A");
    });

    await t.test("GET / returns monitor with status from history", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        await d.prepare(`INSERT INTO channel_monitors (created_at,updated_at,name,provider,api_mode,endpoint,api_key_encrypted,primary_model,extra_models,group_name,enabled,interval_seconds,created_by,extra_headers) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "Monitor C", "openai", "chat_completions", "https://api.openai.com", "enc", "gpt-4", '["gpt-4-turbo"]', "default", 1, 60, 1, "{}"
        ).run();

        await d.prepare(`INSERT INTO channel_monitor_histories (monitor_id,model,status,latency_ms,checked_at) VALUES(?,?,?,?,?)`).bind(
            1, "gpt-4", "operational", 150, new Date().toISOString()
        ).run();
        await d.prepare(`INSERT INTO channel_monitor_histories (monitor_id,model,status,latency_ms,checked_at) VALUES(?,?,?,?,?)`).bind(
            1, "gpt-4-turbo", "degraded", 500, new Date().toISOString()
        ).run();

        const r = await routeRequest(new Request(BASE, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].primary_status, "operational");
        assert.equal(j.data.items[0].primary_latency_ms, 150);
        assert.equal(j.data.items[0].extra_models.length, 1);
        assert.equal(j.data.items[0].extra_models[0].status, "degraded");
        assert.ok(Array.isArray(j.data.items[0].timeline));
    });

    await t.test("GET /:id/status returns monitor detail", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        await d.prepare(`INSERT INTO channel_monitors (created_at,updated_at,name,provider,api_mode,endpoint,api_key_encrypted,primary_model,extra_models,group_name,enabled,interval_seconds,created_by,extra_headers) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "Monitor D", "gemini", "chat_completions", "https://gemini.example.com", "enc-g", "gemini-pro", "[]", "default", 1, 60, 1, "{}"
        ).run();

        await d.prepare(`INSERT INTO channel_monitor_histories (monitor_id,model,status,latency_ms,checked_at) VALUES(?,?,?,?,?)`).bind(
            1, "gemini-pro", "operational", 200, new Date().toISOString()
        ).run();

        const r = await routeRequest(new Request(`${BASE}/1/status`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.name, "Monitor D");
        assert.equal(j.data.provider, "gemini");
        assert.ok(Array.isArray(j.data.models));
        assert.equal(j.data.models.length, 1);
        assert.equal(j.data.models[0].latest_status, "operational");
    });

    await t.test("GET /:id/status returns 404 for disabled monitor", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        await d.prepare(`INSERT INTO channel_monitors (created_at,updated_at,name,provider,api_mode,endpoint,api_key_encrypted,primary_model,extra_models,group_name,enabled,interval_seconds,created_by,extra_headers) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "Disabled", "openai", "chat_completions", "https://example.com", "enc", "gpt-4", "[]", "default", 0, 60, 1, "{}"
        ).run();

        const r = await routeRequest(new Request(`${BASE}/1/status`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /:id/status returns 404 for non-existent", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/999/status`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("returns 401 without auth", async () => {
        const d = createDatabase();
        for (const path of ["", "/1/status"]) {
            const r = await routeRequest(new Request(`${BASE}${path}`), env(d));
            assert.equal(r.status, 401);
        }
    });
});
