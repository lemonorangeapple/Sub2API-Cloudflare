import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql", "0002_business_supplemental.sql", "0003_ops_usage_supplemental.sql", "0004_runtime_state.sql", "0005_auth_sessions.sql"
].map((n) => readFile(new URL(`../../d1/migrations/${n}`, import.meta.url), "utf8")));

const JWT_SECRET = "dashboard-test-secret-32-bytes-long";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d, email, username) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version,balance) VALUES(?,?,?,?,?,?,?,?,?)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", email, PASSWORD_HASH, "user", "active", username, 0, 10.0).run();
    return Number(r.meta.last_row_id);
}

async function token(d, uid, email, role) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
    const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
    return s.token;
}

const P = "/api/v1/admin/dashboard";

test("admin dashboard", async (t) => {
    await t.test("GET /dashboard/snapshot-v2 returns snapshot", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/snapshot-v2?period=day`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(typeof j.data.total_requests, "number");
        assert.equal(typeof j.data.total_cost, "number");
    });

    await t.test("GET /dashboard/stats returns stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/stats?period=day`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(typeof j.data.total_requests, "number");
    });

    await t.test("GET /dashboard/realtime returns realtime metrics", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/realtime`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(typeof j.data.qps, "number");
    });

    await t.test("GET /dashboard/trend returns trend", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/trend?period=day&granularity=day`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.trend));
    });

    await t.test("GET /dashboard/models returns model stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/models?period=day`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.models));
    });

    await t.test("GET /dashboard/groups returns group stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/groups?period=day`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.groups));
    });

    await t.test("POST /dashboard/api-keys-trend returns trends", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/api-keys-trend`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ api_key_ids: [] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.trends));
    });

    await t.test("GET /dashboard/users-trend returns trends", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/users-trend?start_date=2026-07-21&end_date=2026-07-22&granularity=hour&limit=12`, {
            headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.trend));
    });

    await t.test("GET /dashboard/users-ranking returns ranking", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/users-ranking?limit=10`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.ranking));
    });

    await t.test("POST /dashboard/users-usage returns usage", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/users-usage`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_ids: [] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.usage));
    });

    await t.test("POST /dashboard/api-keys-usage returns usage", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/api-keys-usage`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ api_key_ids: [] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.usage));
    });

    await t.test("GET /dashboard/user-breakdown returns breakdown", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "test@breakdown.com", "breakdownuser");
        const r = await routeRequest(new Request(`${BASE}${P}/user-breakdown?user_id=${uid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.user_id, uid);
    });

    await t.test("GET /dashboard/user-breakdown without user_id returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/user-breakdown`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /dashboard/aggregation/backfill returns result", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/aggregation/backfill`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ from: "2026-01-01", to: "2026-01-02" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(typeof j.data.processed, "number");
    });

    await t.test("POST /dashboard/aggregation/backfill missing dates returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/aggregation/backfill`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({})
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}${P}/snapshot-v2`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("non-admin returns 403", async () => {
        const d = db(); const uid = await insUser(d, "user@test.com", "user"); const tk = await token(d, uid, "user@test.com", "user");
        const r = await routeRequest(new Request(`${BASE}${P}/snapshot-v2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });
});
