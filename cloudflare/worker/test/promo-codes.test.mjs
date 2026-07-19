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

const JWT_SECRET = "promo-test-secret-that-is-at-least-32-bytes";
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

test("admin promo codes", async (t) => {
    await t.test("GET /admin/promo-codes returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/promo-codes creates a promo code with auto-generated code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ bonus_amount: 50.0, max_uses: 100, notes: "Welcome bonus" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.bonusAmount, 50.0);
        assert.equal(j.data.maxUses, 100);
        assert.equal(j.data.usedCount, 0);
        assert.equal(j.data.status, "active");
        assert.equal(j.data.notes, "Welcome bonus");
        assert.ok(j.data.code.length > 0);
    });

    await t.test("POST /admin/promo-codes creates a promo code with custom code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "WELCOME100", bonus_amount: 100, max_uses: 50 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.code, "WELCOME100");
        assert.equal(j.data.bonusAmount, 100);
    });

    await t.test("POST /admin/promo-codes rejects duplicate code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "DUP1", bonus_amount: 10 })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "dup1", bonus_amount: 20 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/promo-codes requires bonus_amount", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "NOBONUS" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/promo-codes/:id returns a promo code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "GETONE", bonus_amount: 75 })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.code, "GETONE");
        assert.equal(j.data.bonusAmount, 75);
    });

    await t.test("GET /admin/promo-codes/:id returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/promo-codes/:id updates fields", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "UPDME", bonus_amount: 10 })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/${cid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ bonus_amount: 200, notes: "Updated", status: "disabled" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.bonusAmount, 200);
        assert.equal(j.data.notes, "Updated");
        assert.equal(j.data.status, "disabled");
    });

    await t.test("PUT /admin/promo-codes/:id validates status", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "BADSTATUS", bonus_amount: 10 })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/${cid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ status: "invalid_status" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("DELETE /admin/promo-codes/:id deletes a promo code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "DELME", bonus_amount: 10 })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/${cid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const g = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(g.status, 404);
    });

    await t.test("DELETE /admin/promo-codes/:id returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/99999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/promo-codes lists with pagination", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        for (let i = 0; i < 5; i++) {
            await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
                method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
                body: JSON.stringify({ code: `PAGE${i}`, bonus_amount: i * 10 })
            }), env(d));
        }
        const r1 = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j1 = await r1.json();
        assert.equal(j1.data.items.length, 2);
        assert.equal(j1.data.total, 5);

        const r2 = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes?page=3&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j2 = await r2.json();
        assert.equal(j2.data.items.length, 1);
    });

    await t.test("GET /admin/promo-codes filters by status", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "ACTIVE1", bonus_amount: 10 })
        }), env(d));
        const c2 = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "DISABLED1", bonus_amount: 20 })
        }), env(d));
        const cid2 = (await c2.json()).data.id;
        await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/${cid2}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ status: "disabled" })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes?status=active`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.ok(j.data.items.every((i) => i.status === "active"));
    });

    await t.test("GET /admin/promo-codes searches by code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "SEARCHXYZ", bonus_amount: 10 })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes?search=SEARCHXYZ`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].code, "SEARCHXYZ");
    });

    await t.test("GET /admin/promo-codes/:id/usages returns empty list for new code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const c = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "USAGES1", bonus_amount: 10 })
        }), env(d));
        const cid = (await c.json()).data.id;
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/${cid}/usages`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("GET /admin/promo-codes/:id/usages returns 404 for nonexistent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes/99999/usages`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("non-admin gets 403", async () => {
        const d = db(); const uid = await insUser(d); const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });

    await t.test("missing auth gets 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/promo-codes`), env(d));
        assert.equal(r.status, 401);
    });
});
