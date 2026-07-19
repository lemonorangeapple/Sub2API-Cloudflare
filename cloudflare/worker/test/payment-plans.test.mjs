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

const JWT_SECRET = "payment-plans-test-secret-that-is-at-least-32-bytes!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insGroup(d, id) {
    await d.prepare(`INSERT INTO groups (id, created_at, updated_at, name, description, status, supported_model_scopes, messages_dispatch_model_config, models_list_config) VALUES(?,?,?,?,?,?,?,?,?)`).bind(id, "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "test-group", "test", "active", "", "{}", "{}").run();
}

function token(d, uid, email, role) {
    return async () => {
        const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
        const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
        const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
        return s.token;
    };
}

test("admin payment plans", async (t) => {
    await t.test("GET /admin/payment/plans returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(Array.isArray(j.data), true);
        assert.equal(j.data.length, 0);
    });

    await t.test("POST /admin/payment/plans creates a plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, 1);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_id: 1, name: "Pro Monthly", price: 29.99, validity_days: 30 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.name, "Pro Monthly");
        assert.equal(j.data.price, 29.99);
        assert.equal(j.data.validityDays, 30);
        assert.equal(j.data.groupId, 1);
    });

    await t.test("POST /admin/payment/plans requires name, price, group_id", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ price: 10 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/payment/plans/:id returns a plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, 1);
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_id: 1, name: "Basic", price: 9.99 })
        }), env(d));
        const cj = await c.json();
        const rid = cj.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans/${rid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.id, rid);
        assert.equal(j.data.name, "Basic");
    });

    await t.test("PUT /admin/payment/plans/:id updates a plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, 1);
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_id: 1, name: "Basic", price: 9.99 })
        }), env(d));
        const cj = await c.json();
        const rid = cj.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans/${rid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ price: 19.99, name: "Basic Plus" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.name, "Basic Plus");
        assert.equal(j.data.price, 19.99);
    });

    await t.test("DELETE /admin/payment/plans/:id deletes a plan", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, 1);
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_id: 1, name: "Temp", price: 5 })
        }), env(d));
        const cj = await c.json();
        const rid = cj.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans/${rid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);

        const r2 = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans/${rid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r2.status, 404);
    });

    await t.test("DELETE /admin/payment/plans/:id returns 404 for non-existent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans/99999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("returns 401 without auth", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("list includes created plans", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, 1); await insGroup(d, 2);
        await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_id: 1, name: "Plan A", price: 10, sort_order: 2 })
        }), env(d));
        await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_id: 2, name: "Plan B", price: 20, sort_order: 1 })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/plans`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.length, 2);
        assert.equal(j.data[0].name, "Plan B");
        assert.equal(j.data[1].name, "Plan A");
    });
});
