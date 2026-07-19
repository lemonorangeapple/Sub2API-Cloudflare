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

const JWT_SECRET = "aff-test-secret-32-bytes-long-123456";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d, email, username) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", email, PASSWORD_HASH, "user", "active", username, 0).run();
    return Number(r.meta.last_row_id);
}

async function insAffiliate(d, userId, code) {
    await d.prepare(`INSERT INTO user_affiliates (user_id, aff_code, inviter_id, aff_count, aff_quota, aff_history_quota, created_at, updated_at, aff_code_custom) VALUES(?,?,?,?,?,?,datetime('now'),datetime('now'),?)`).bind(userId, code, null, 0, 0, 0, 0).run();
}

async function token(d, uid, email, role) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
    const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
    return s.token;
}

const URL_PREFIX = "/api/v1/admin/affiliates";

test("affiliate management", async (t) => {
    await t.test("GET /admin/affiliates/users returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/affiliates/users/batch-rate with empty returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/batch-rate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_ids: [] })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/affiliates/users/batch-rate without rate returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/batch-rate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_ids: [1, 2] })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/affiliates/users/lookup with empty q returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/lookup`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data, []);
    });

    await t.test("GET /admin/affiliates/users/lookup with q returns matching users", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "bob@test.com", "bobuser");
        await insAffiliate(d, uid, "BOB123");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/lookup?q=bob`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(j.data.length >= 1);
        assert.equal(j.data.some((u) => u.email === "bob@test.com"), true);
    });

    await t.test("PUT /admin/affiliates/users/:user_id with invalid code returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "short@test.com", "short");
        await insAffiliate(d, uid, "SHRT123");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/${uid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ aff_code: "X" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("PUT /admin/affiliates/users/:user_id updates settings", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "update@test.com", "updateuser");
        await insAffiliate(d, uid, "UPD12345");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/${uid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ aff_code: "CUSTOM1", aff_rebate_rate_percent: 25 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.userId, uid);
    });

    await t.test("DELETE /admin/affiliates/users/:user_id clears settings", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "clear@test.com", "clearuser");
        await insAffiliate(d, uid, "CLR12345");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/${uid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.userId, uid);
    });

    await t.test("GET /admin/affiliates/users/:user_id/overview returns 404 for non-existent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/999/overview`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/affiliates/users/:user_id/overview returns overview", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const uid = await insUser(d, "overview@test.com", "overviewuser");
        await insAffiliate(d, uid, "OVW12345");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users/${uid}/overview`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.userId, uid);
        assert.equal(j.data.affCode, "OVW12345");
    });

    await t.test("GET /admin/affiliates/invites returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/invites`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
        assert.equal(j.data.total, 0);
    });

    await t.test("GET /admin/affiliates/rebates returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/rebates`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
        assert.equal(j.data.total, 0);
    });

    await t.test("GET /admin/affiliates/transfers returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/transfers`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
        assert.equal(j.data.total, 0);
    });

    await t.test("GET /admin/affiliates/users returns paginated results", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        for (let i = 0; i < 3; i++) {
            const uid = await insUser(d, `pag${i}@test.com`, `paguser${i}`);
            await insAffiliate(d, uid, `PG${i}CODE`);
            await d.prepare(`UPDATE user_affiliates SET aff_code_custom = 1 WHERE user_id = ?`).bind(uid).run();
        }
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(j.data.items.length <= 2);
        assert.ok(j.data.total >= 3);
        assert.ok(j.data.pages >= 2);
    });

    await t.test("without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}${URL_PREFIX}/users`, {}), env(d));
        assert.equal(r.status, 401);
    });
});
