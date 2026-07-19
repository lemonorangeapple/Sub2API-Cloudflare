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

const JWT_SECRET = "cmt-test-secret-32-bytes-long-123456";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function token(d, uid, email, role) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
    const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
    return s.token;
}

const BASE_URL = "/api/v1/admin/channel-monitor-templates";

test("channel monitor templates", async (t) => {
    await t.test("GET /admin/channel-monitor-templates returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
    });

    await t.test("POST /admin/channel-monitor-templates creates template", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Test Template", provider: "openai", api_mode: "chat_completions", description: "desc" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "Test Template");
        assert.equal(j.data.provider, "openai");
        assert.equal(j.data.associatedMonitors, 0);
    });

    await t.test("POST without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({ name: "X", provider: "openai" })
        }), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("POST with invalid provider returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "X", provider: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
        const j = await r.json();
        assert.equal(j.reason, "CHANNEL_MONITOR_TEMPLATE_INVALID_PROVIDER");
    });

    await t.test("POST with invalid api_mode returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "X", provider: "openai", api_mode: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST with responses mode for non-openai returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "X", provider: "anthropic", api_mode: "responses" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST with duplicate name returns 409", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Dup Template", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Dup Template", provider: "openai" })
        }), env(d));
        assert.equal(r.status, 409);
    });

    await t.test("GET /admin/channel-monitor-templates/:id returns template", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Get Me", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/1`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "Get Me");
    });

    await t.test("GET /admin/channel-monitor-templates/999 returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET with provider filter returns matching templates", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "OA Filter", provider: "openai" })
        }), env(d));
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "AN Filter", provider: "anthropic" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}?provider=openai`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].provider, "openai");
    });

    await t.test("PUT /admin/channel-monitor-templates/:id updates template", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Before", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/1`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "After", description: "Updated" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "After");
        assert.equal(j.data.description, "Updated");
    });

    await t.test("PUT with empty name returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Empty Name Test", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/1`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "   " })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/channel-monitor-templates/:id/monitors returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Monitors Test", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/1/monitors`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
    });

    await t.test("POST /admin/channel-monitor-templates/:id/apply with empty array returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Apply Test", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/1/apply`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ monitor_ids: [] })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/channel-monitor-templates/:id/apply with non-existent monitors returns affected 0", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Apply Nonexist", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/1/apply`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ monitor_ids: [999] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.affected, 0);
    });

    await t.test("DELETE /admin/channel-monitor-templates/:id deletes template", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${BASE_URL}`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Delete Me", provider: "openai" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/1`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const g = await routeRequest(new Request(`${BASE}${BASE_URL}/1`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(g.status, 404);
    });

    await t.test("DELETE /admin/channel-monitor-templates/999 returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/channel-monitor-templates/999 returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${BASE_URL}/999`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "X" })
        }), env(d));
        assert.equal(r.status, 404);
    });
});
