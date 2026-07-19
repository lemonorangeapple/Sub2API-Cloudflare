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

const JWT_SECRET = "channel-monitor-test-secret-32-bytes!!";
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

const MONITOR_BODY = {
    name: "Test Monitor",
    provider: "openai",
    endpoint: "https://api.openai.com",
    api_key: "sk-test-key-12345",
    primary_model: "gpt-4o",
    interval_seconds: 300,
};

test("channel monitors", async (t) => {
    await t.test("GET /admin/channel-monitors returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/channel-monitors creates a monitor", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify(MONITOR_BODY)
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "Test Monitor");
        assert.equal(j.data.provider, "openai");
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.primaryModel, "gpt-4o");
        assert.equal(j.data.intervalSeconds, 300);
        assert.equal(j.data.apiKeyMasked, "***");
    });

    await t.test("POST rejects missing name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ...MONITOR_BODY, name: "" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST rejects invalid provider", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ...MONITOR_BODY, provider: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST rejects invalid interval", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ...MONITOR_BODY, interval_seconds: 5 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST rejects responses mode for non-openai", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ...MONITOR_BODY, provider: "anthropic", api_mode: "responses" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/channel-monitors/:id returns monitor", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify(MONITOR_BODY)
        }), env(d));
        const cid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.id, cid);
        assert.equal(j.data.name, "Test Monitor");
    });

    await t.test("GET returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/channel-monitors/:id updates fields", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify(MONITOR_BODY)
        }), env(d));
        const cid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/${cid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Updated Monitor", enabled: false, interval_seconds: 600 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "Updated Monitor");
        assert.equal(j.data.enabled, false);
        assert.equal(j.data.intervalSeconds, 600);
    });

    await t.test("DELETE /admin/channel-monitors/:id deletes monitor", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify(MONITOR_BODY)
        }), env(d));
        const cid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/${cid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const g = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(g.status, 404);
    });

    await t.test("DELETE returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/99999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/channel-monitors supports pagination", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        for (let i = 0; i < 5; i++) {
            await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
                method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
                body: JSON.stringify({ ...MONITOR_BODY, name: `Monitor ${i}` })
            }), env(d));
        }
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.items.length, 2);
        assert.equal(j.data.total, 5);
    });

    await t.test("GET /admin/channel-monitors filters by provider", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ...MONITOR_BODY, name: "OA" })
        }), env(d));
        await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ...MONITOR_BODY, name: "ANT", provider: "anthropic" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors?provider=anthropic`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].provider, "anthropic");
    });

    await t.test("GET /admin/channel-monitors/:id/history returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify(MONITOR_BODY)
        }), env(d));
        const cid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/${cid}/history`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data, []);
    });

    await t.test("POST /admin/channel-monitors/:id/run executes in worker", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const cr = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ...MONITOR_BODY, endpoint: "http://127.0.0.1:1" })
        }), env(d));
        const cid = (await cr.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors/${cid}/run`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.results.length, 1);
        assert.equal(j.data.results[0].status, "error");
        const history = await d.prepare("SELECT COUNT(*) AS count FROM channel_monitor_histories WHERE monitor_id = ?").bind(cid).first();
        assert.equal(history.count, 1);
    });

    await t.test("non-admin gets 403", async () => {
        const d = db(); const uid = await insUser(d); const tk = await token(d, uid, "user@x.com", "user");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });

    await t.test("missing auth gets 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channel-monitors`), env(d));
        assert.equal(r.status, 401);
    });
});
