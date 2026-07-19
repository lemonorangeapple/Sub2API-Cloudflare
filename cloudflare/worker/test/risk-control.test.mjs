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

const JWT_SECRET = "risk-control-test-jwt-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertUser(db, overrides = {}) {
    const values = { email: "admin@x.com", passwordHash: PASSWORD_HASH, role: "admin", status: "active", username: "admin", ...overrides };
    await db.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", values.email, values.passwordHash, values.role, values.status, values.username, 0, null, "email"
    ).run();
}

function env(db) {
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30", TOTP_ENCRYPTION_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" };
}

async function createToken(db, role = "admin", userId = 1, email = "admin@x.com", passwordHash = PASSWORD_HASH) {
    const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, passwordHash, 0n);
    const signed = await signer.sign({ id: userId, email, role, tokenVersion });
    return signed.token;
}

const BASE = "https://edge.example/api/v1/admin/risk-control";

test("admin risk control routes", async (t) => {
    await t.test("GET /config returns default config", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/config`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.enabled, false);
        assert.equal(j.data.mode, "off");
    });

    await t.test("PUT /config updates config", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/config`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, mode: "pre_block", base_url: "https://mod.example.com", sample_rate: 50 }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.mode, "pre_block");
        assert.equal(j.data.base_url, "https://mod.example.com");
        assert.equal(j.data.sample_rate, 50);
    });

    await t.test("PUT /config persists across reads", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        await routeRequest(new Request(`${BASE}/config`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ thresholds: { hate: 0.8, self_harm: 0.9 } }),
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/config`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.thresholds.hate, 0.8);
        assert.equal(j.data.thresholds.self_harm, 0.9);
    });

    await t.test("GET /config returns 401 without auth", async () => {
        const d = createDatabase();
        const r = await routeRequest(new Request(`${BASE}/config`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("PUT /config returns 401 without auth", async () => {
        const d = createDatabase();
        const r = await routeRequest(new Request(`${BASE}/config`, {
            method: "PUT",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ enabled: true }),
        }), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("GET /status returns runtime status", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/status`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.mode, "string");
        assert.ok(Array.isArray(j.data.api_key_statuses));
    });

    await t.test("GET /logs returns empty list", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/logs`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.total, 0);
        assert.ok(Array.isArray(j.data.items));
    });

    await t.test("GET /logs returns log entries", async () => {
        const d = createDatabase();
        await insertUser(d);

        await d.prepare(`INSERT INTO content_moderation_logs (created_at,request_id,user_email,api_key_name,group_name,endpoint,provider,model,mode,action,flagged,highest_category,highest_score,category_scores,threshold_snapshot,input_excerpt,error,violation_count,auto_banned,email_sent,matched_keyword) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-18T00:00:00.000Z", "req-001", "user@x.com", "key-1", "default", "/v1/chat/completions", "openai", "gpt-4", "pre_block", "keyword_block", 1, "hate", 0.95, '{"hate":0.95}', '{"hate":0.8}', "test input", "", 3, 0, 0, "badword"
        ).run();

        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/logs`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.total, 1);
        assert.equal(j.data.items[0].request_id, "req-001");
        assert.equal(j.data.items[0].flagged, true);
        assert.equal(j.data.items[0].matched_keyword, "badword");
        assert.equal(j.data.items[0].highest_category, "hate");
    });

    await t.test("GET /logs filters by result", async () => {
        const d = createDatabase();
        await insertUser(d);

        await d.prepare(`INSERT INTO content_moderation_logs (created_at,request_id,user_email,api_key_name,group_name,endpoint,provider,model,mode,action,flagged,highest_category,highest_score,category_scores,threshold_snapshot,input_excerpt,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-18T00:00:00.000Z", "req-hit", "user@x.com", "k1", "g1", "/chat", "openai", "gpt-4", "pre_block", "keyword_block", 1, "hate", 0.9, '{}', '{}', "test", ""
        ).run();
        await d.prepare(`INSERT INTO content_moderation_logs (created_at,request_id,user_email,api_key_name,group_name,endpoint,provider,model,mode,action,flagged,highest_category,highest_score,category_scores,threshold_snapshot,input_excerpt,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            "2026-07-18T00:00:00.000Z", "req-pass", "user@x.com", "k1", "g1", "/chat", "openai", "gpt-4", "pre_block", "allow", 0, "", 0, '{}', '{}', "test", ""
        ).run();

        const tk = await createToken(d);
        const r = await routeRequest(new Request(`${BASE}/logs?result=hit`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.total, 1);
        assert.equal(j.data.items[0].request_id, "req-hit");
    });

    await t.test("POST /users/:id/unban unbans user", async () => {
        const d = createDatabase();
        await insertUser(d); // admin user (id=1)
        await insertUser(d, { email: "banned@x.com", status: "banned", role: "user", username: "banned" }); // banned user (id=2)
        const tk = await createToken(d); // admin token

        const r = await routeRequest(new Request(`${BASE}/users/2/unban`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` },
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.user_id, 2);
        assert.equal(j.data.status, "active");
    });

    await t.test("POST /users/:id/unban returns 404 for missing user", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/users/999/unban`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` },
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("DELETE /hashes deletes a hash", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/hashes`, {
            method: "DELETE",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ input_hash: "abc123" }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.deleted, true);
    });

    await t.test("DELETE /hashes/all clears hashes", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/hashes/all`, {
            method: "DELETE",
            headers: { authorization: `Bearer ${tk}` },
        }), env(d));
        assert.equal(r.status, 200);
    });

    await t.test("POST /api-keys/test returns key statuses", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/api-keys/test`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ api_keys: ["sk-test1", "sk-test2"], prompt: "test" }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.items.length, 2);
        assert.equal(j.data.image_count, 0);
    });

    await t.test("unauthenticated requests return 401", async () => {
        const d = createDatabase();
        for (const path of ["/status", "/logs", "/hashes/all"]) {
            const r = await routeRequest(new Request(`${BASE}${path}`), env(d));
            assert.equal(r.status, 401);
        }
    });
});
