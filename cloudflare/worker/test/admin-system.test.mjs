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

const JWT_SECRET = "admin-system-test-secret-at-least-32-bytes!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";
const NOW = "2026-07-15T12:00:00.000Z";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version,balance) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
        NOW, NOW, "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, 0
    ).run();
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

test("admin system routes", async (t) => {
    await t.test("GET /admin/system/version returns version", async () => {
        const d = db();
        const aid = await insAdmin(d);
        const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/version`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.version, "string");
    });

    await t.test("GET /admin/system/check-updates returns stub", async () => {
        const d = db();
        const aid = await insAdmin(d);
        const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/check-updates`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.has_update, false);
        assert.equal(typeof j.data.warning, "string");
    });

    await t.test("GET /admin/system/rollback-versions returns empty array", async () => {
        const d = db();
        const aid = await insAdmin(d);
        const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/rollback-versions`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.deepEqual(j.data.versions, []);
    });

    await t.test("POST /admin/system/update returns stub", async () => {
        const d = db();
        const aid = await insAdmin(d);
        const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/update`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.need_restart, false);
    });

    await t.test("POST /admin/system/rollback returns stub", async () => {
        const d = db();
        const aid = await insAdmin(d);
        const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/rollback`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ version: "1.0.0" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.need_restart, false);
    });

    await t.test("POST /admin/system/restart returns stub", async () => {
        const d = db();
        const aid = await insAdmin(d);
        const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/restart`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.message, "string");
    });

    await t.test("non-admin users return 401", async () => {
        const d = db();
        const uid = await (async () => {
            const r2 = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version,balance) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
                NOW, NOW, "user@x.com", PASSWORD_HASH, "user", "active", "user", 0, 0
            ).run();
            return Number(r2.meta.last_row_id);
        })();
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/version`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/system/version`), env(d));
        assert.equal(r.status, 401);
    });
});
