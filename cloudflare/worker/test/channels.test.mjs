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

const JWT_SECRET = "channel-test-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", overrides.email ?? "user@x.com", PASSWORD_HASH, "user", "active", overrides.username ?? "testuser", 0).run();
    return Number(r.meta.last_row_id);
}

function token(d, uid, email, role) {
    return async () => {
        const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
        const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
        const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
        return s.token;
    };
}

async function insGroup(d) {
    const cols = ["name","description","platform","rate_multiplier","status","created_at","updated_at","supported_model_scopes","messages_dispatch_model_config","models_list_config"];
    const phs = ["?","?","?","?","?","?","?","?","?","?"];
    const vals = ["test-group", "", "openai", 1.0, "active", "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "[]", "{}", "{}"];
    const r = await d.prepare(`INSERT INTO groups (${cols.join(",")}) VALUES (${phs.join(",")})`).bind(...vals).run();
    return Number(r.meta.last_row_id);
}

test("admin channels", async (t) => {
    await t.test("GET /admin/channels returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/channels creates a channel", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "My Channel", description: "A test channel" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.name, "My Channel");
        assert.equal(j.data.description, "A test channel");
        assert.equal(j.data.status, "active");
        assert.deepEqual(j.data.groupIds, []);
        assert.deepEqual(j.data.modelPricing, []);
    });

    await t.test("POST /admin/channels creates with group IDs", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Ch With Groups", group_ids: [gid] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.groupIds, [gid]);
    });

    await t.test("POST /admin/channels creates with model pricing", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({
                name: "Ch With Pricing",
                model_pricing: [{
                    platform: "anthropic", models: ["claude-sonnet-4"], billing_mode: "token",
                    input_price: 0.003, output_price: 0.015
                }]
            })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.modelPricing.length, 1);
        assert.equal(j.data.modelPricing[0].platform, "anthropic");
        assert.deepEqual(j.data.modelPricing[0].models, ["claude-sonnet-4"]);
        assert.equal(j.data.modelPricing[0].inputPrice, 0.003);
    });

    await t.test("POST /admin/channels creates with pricing intervals", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({
                name: "Ch With Intervals",
                model_pricing: [{
                    platform: "openai", models: ["gpt-4o"], billing_mode: "token",
                    input_price: 0.0025, output_price: 0.01,
                    intervals: [
                        { min_tokens: 0, max_tokens: 100000, tier_label: "base", input_price: 0.0025, output_price: 0.01, sort_order: 0 },
                        { min_tokens: 100000, tier_label: "large", input_price: 0.005, output_price: 0.015, sort_order: 1 }
                    ]
                }]
            })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.modelPricing[0].intervals.length, 2);
        assert.equal(j.data.modelPricing[0].intervals[0].minTokens, 0);
        assert.equal(j.data.modelPricing[0].intervals[0].maxTokens, 100000);
        assert.equal(j.data.modelPricing[0].intervals[1].minTokens, 100000);
    });

    await t.test("POST /admin/channels rejects duplicate name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "DupCh" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "DupCh" })
        }), env(d));
        assert.equal(r.status, 409);
    });

    await t.test("POST /admin/channels requires name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ description: "no name" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/channels/:id returns channel", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "GetCh" })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "GetCh");
    });

    await t.test("GET /admin/channels/:id returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/channels/:id updates fields", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "UpdCh" })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ description: "Updated desc", status: "disabled" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.description, "Updated desc");
        assert.equal(j.data.status, "disabled");
    });

    await t.test("PUT /admin/channels/:id replaces group IDs", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d);
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "GrpCh" })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_ids: [gid] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.groupIds, [gid]);
    });

    await t.test("PUT /admin/channels/:id replaces model pricing", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "PrcCh" })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ model_pricing: [{ platform: "openai", models: ["gpt-4o"], input_price: 0.01 }] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.modelPricing.length, 1);
        assert.equal(j.data.modelPricing[0].platform, "openai");
    });

    await t.test("PUT /admin/channels/:id validates status", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "BadSt" })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ status: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("PUT /admin/channels/:id rejects duplicate name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "UniqueA" })
        }), env(d));
        const c2 = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "UniqueB" })
        }), env(d));
        const cid2 = (await c2.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid2}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "UniqueA" })
        }), env(d));
        assert.equal(r.status, 409);
    });

    await t.test("DELETE /admin/channels/:id deletes channel", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "DelCh" })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const g = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(g.status, 404);
    });

    await t.test("DELETE /admin/channels/:id returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels/99999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/channels lists with pagination", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        for (let i = 0; i < 5; i++) {
            await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
                method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
                body: JSON.stringify({ name: `PagCh${i}` })
            }), env(d));
        }
        const r1 = await routeRequest(new Request(`${BASE}/api/v1/admin/channels?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j1 = await r1.json();
        assert.equal(j1.data.items.length, 2);
        assert.equal(j1.data.total, 5);
    });

    await t.test("GET /admin/channels filters by status", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "ActCh" })
        }), env(d));
        const c2 = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "DisCh" })
        }), env(d));
        const cid2 = (await c2.json()).data.id;
        await routeRequest(new Request(`${BASE}/api/v1/admin/channels/${cid2}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ status: "disabled" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels?status=active`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.ok(j.data.items.every((i) => i.status === "active"));
    });

    await t.test("GET /admin/channels searches by name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "SearchXYZ" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels?search=SearchXYZ`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].name, "SearchXYZ");
    });

    await t.test("non-admin gets 403", async () => {
        const d = db(); const uid = await insUser(d); const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });

    await t.test("missing auth gets 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/channels`), env(d));
        assert.equal(r.status, 401);
    });
});
