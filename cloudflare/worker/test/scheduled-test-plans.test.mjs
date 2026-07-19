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

const JWT_SECRET = "scheduled-test-secret-32-bytes-long!!!!!!!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "user@x.com", PASSWORD_HASH, "user", "active", "testuser", 0).run();
    return Number(r.meta.last_row_id);
}

async function token(d, uid, email, role) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
    const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
    return s.token;
}

async function insAccount(d) {
    const now = "2026-07-01T00:00:00.000Z";
    const r = await d.prepare(
        `INSERT INTO accounts (name,notes,platform,type,credentials,extra,concurrency,priority,rate_multiplier,status,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind("test-account", "", "openai", "apikey", "{}", "{}", 3, 50, 1.0, "active", now, now, null).run();
    return Number(r.meta.last_row_id);
}

test("scheduled test plans", async (t) => {
    await t.test("GET /admin/accounts/:id/scheduled-test-plans returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${accountId}/scheduled-test-plans`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data, []);
    });

    await t.test("POST /admin/scheduled-test-plans creates a plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, model_id: "gpt-4o", cron_expression: "*/30 * * * *", enabled: true, max_results: 100 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.accountId, accountId);
        assert.equal(j.data.modelId, "gpt-4o");
        assert.equal(j.data.cronExpression, "*/30 * * * *");
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.maxResults, 100);
        assert.equal(j.data.autoRecover, false);
    });

    await t.test("POST applies defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "0 * * * *" })
        }), env(d));
        const j = await r.json();
        assert.equal(j.data.modelId, "");
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.maxResults, 50);
        assert.equal(j.data.autoRecover, false);
    });

    await t.test("POST rejects missing account_id", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ cron_expression: "*/30 * * * *" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST rejects missing cron_expression", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST rejects invalid cron expression", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/scheduled-test-plans/:id returns plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "*/30 * * * *" })
        }), env(d));
        const pid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/${pid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.id, pid);
    });

    await t.test("GET /admin/scheduled-test-plans/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/scheduled-test-plans/:id updates fields", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "*/30 * * * *" })
        }), env(d));
        const pid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/${pid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: false, max_results: 200, auto_recover: true })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, false);
        assert.equal(j.data.maxResults, 200);
        assert.equal(j.data.autoRecover, true);
    });

    await t.test("PUT rejects invalid cron", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "*/30 * * * *" })
        }), env(d));
        const pid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/${pid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ cron_expression: "bad" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("DELETE /admin/scheduled-test-plans/:id deletes plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "*/30 * * * *" })
        }), env(d));
        const pid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/${pid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const g = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/${pid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(g.status, 404);
    });

    await t.test("DELETE returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/99999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/scheduled-test-plans/:id/results returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "*/30 * * * *" })
        }), env(d));
        const pid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/${pid}/results`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data, []);
    });

    await t.test("GET results returns 404 for nonexistent plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans/99999/results`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/accounts/:id/scheduled-test-plans lists by account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const accountId = await insAccount(d);
        await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_id: accountId, cron_expression: "*/30 * * * *" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${accountId}/scheduled-test-plans`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.length, 1);
        assert.equal(j.data[0].accountId, accountId);
    });

    await t.test("non-admin gets 403", async () => {
        const d = db(); const uid = await insUser(d); const tk = await token(d, uid, "user@x.com", "user");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });

    await t.test("missing auth gets 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/scheduled-test-plans`), env(d));
        assert.equal(r.status, 401);
    });
});
