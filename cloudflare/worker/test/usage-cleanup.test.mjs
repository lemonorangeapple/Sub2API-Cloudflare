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

const JWT_SECRET = "usage-test-32-bytes-long-key-123456";
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

async function token(d, uid, email, role) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
    const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
    return s.token;
}

const P = "/api/v1/admin/usage";

test("usage cleanup management", async (t) => {
    // ===== Search Users =====
    await t.test("GET /admin/usage/search-users with empty q returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/search-users`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data, []);
    });

    await t.test("GET /admin/usage/search-users with q returns matching users", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await insUser(d, "search@test.com", "searchuser");
        const r = await routeRequest(new Request(`${BASE}${P}/search-users?q=search`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(j.data.length >= 1);
        assert.equal(j.data.some((u) => u.email === "search@test.com"), true);
    });

    // ===== Cleanup Tasks =====
    await t.test("GET /admin/usage/cleanup-tasks returns empty", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/cleanup-tasks`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.items, []);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/usage/cleanup-tasks creates task", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/cleanup-tasks`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ start_date: "2025-01-01", end_date: "2025-01-31" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.status, "pending");
        assert.equal(j.data.filters.start_date, "2025-01-01");
    });

    await t.test("POST /admin/usage/cleanup-tasks without dates returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/cleanup-tasks`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ model: "gpt-4" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/usage/cleanup-tasks/:id/cancel cancels task", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const cr = await routeRequest(new Request(`${BASE}${P}/cleanup-tasks`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ start_date: "2025-01-01", end_date: "2025-01-31" })
        }), env(d));
        const cj = await cr.json();
        const taskId = cj.data.id;
        const r = await routeRequest(new Request(`${BASE}${P}/cleanup-tasks/${taskId}/cancel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.status, "canceled");
    });

    await t.test("POST /admin/usage/cleanup-tasks/999/cancel returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/cleanup-tasks/999/cancel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}${P}/cleanup-tasks`, {}), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("GET /admin/usage/search-users without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}${P}/search-users?q=test`, {}), env(d));
        assert.equal(r.status, 401);
    });
});
