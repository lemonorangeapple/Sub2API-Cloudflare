import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql", "0002_business_supplemental.sql", "0004_runtime_state.sql", "0005_auth_sessions.sql"
].map((n) => readFile(new URL(`../../d1/migrations/${n}`, import.meta.url), "utf8")));

const JWT_SECRET = "admin-user-routes-test-secret-32b";
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

const P = "/api/v1/admin/users";

test("admin user routes", async (t) => {
    await t.test("GET /admin/users/:id returns user", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "get@test.com", "getuser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.id, uid);
        assert.equal(j.data.email, "get@test.com");
        assert.equal(typeof j.data.balance, "number");
    });

    await t.test("GET /admin/users/999 returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("POST /admin/users/:id/balance adds balance", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "bal@test.com", "baluser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/balance`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ balance: 5.0, operation: "add", notes: "top-up" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.balance, 15.0);
    });

    await t.test("POST /admin/users/:id/balance set operation", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "set@test.com", "setuser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/balance`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ balance: 100, operation: "set", notes: "set balance" })
        }), env(d));
        const j = await r.json();
        assert.equal(j.data.balance, 100);
    });

    await t.test("POST /admin/users/:id/balance negative result returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "neg@test.com", "neguser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/balance`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ balance: 100, operation: "subtract", notes: "too much" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/users/:id/usage returns stub", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "usage@test.com", "usageuser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/usage`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.period, "month");
        assert.equal(j.data.total_requests, 0);
    });

    await t.test("GET /admin/users/:id/balance-history returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "hist@test.com", "histuser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/balance-history`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
        assert.equal(typeof j.data.total_recharged, "number");
    });

    await t.test("POST /admin/users/batch-concurrency updates users", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid1 = await insUser(d, "bc1@test.com", "bc1");
        const uid2 = await insUser(d, "bc2@test.com", "bc2");
        const r = await routeRequest(new Request(`${BASE}${P}/batch-concurrency`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_ids: [uid1, uid2], concurrency: 10, mode: "set" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.affected, 2);
    });

    await t.test("POST /admin/users/batch-concurrency with empty returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/batch-concurrency`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_ids: [], concurrency: 5, mode: "set" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/users/:id/platform-quotas returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "pq@test.com", "pquser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/platform-quotas`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.platform_quotas, []);
    });

    await t.test("PUT /admin/users/:id/platform-quotas upserts quotas", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "pqup@test.com", "pqupuser");
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/platform-quotas`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ quotas: [{ platform: "openai", daily_limit_usd: 10, weekly_limit_usd: 50, monthly_limit_usd: 200 }] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.platform_quotas.length, 1);
        assert.equal(j.data.platform_quotas[0].platform, "openai");
    });

    await t.test("POST /admin/users/:id/platform-quotas/reset resets window", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "pqr@test.com", "pqruser");
        await routeRequest(new Request(`${BASE}${P}/${uid}/platform-quotas`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ quotas: [{ platform: "anthropic", daily_limit_usd: 10, weekly_limit_usd: null, monthly_limit_usd: null }] })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${P}/${uid}/platform-quotas/reset`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ platform: "anthropic", window: "daily" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(j.data.platform_quotas.length >= 1);
    });

    await t.test("without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}${P}/1`, {}), env(d));
        assert.equal(r.status, 401);
    });
});
