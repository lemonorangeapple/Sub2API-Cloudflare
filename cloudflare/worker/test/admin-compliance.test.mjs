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

const JWT_SECRET = "compliance-test-secret-32-bytes-long!!!!!!!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";
const ACK_ZH = "我已阅读、理解并同意 Sub2API 部署与运营合规承诺";
const ACK_EN = "I have read, understood, and agree to the Sub2API Deployment and Operation Compliance Commitment";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d, email = "admin@x.com") {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", email, PASSWORD_HASH, "admin", "active", email.split("@")[0], 0, null, "email").run();
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

test("admin compliance", async (t) => {
    await t.test("GET /admin/compliance returns required=true when not acknowledged", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.required, true);
        assert.equal(j.data.version, "v2026.06.10");
        assert.equal(j.data.acknowledgement, null);
    });

    await t.test("POST /admin/compliance/accept with correct EN phrase succeeds", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance/accept`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ phrase: ACK_EN, language: "en" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.required, false);
        assert.equal(j.data.acknowledgement.version, "v2026.06.10");
        assert.equal(j.data.acknowledgement.admin_user_id, aid);
    });

    await t.test("POST /admin/compliance/accept with correct ZH phrase succeeds", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance/accept`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ phrase: ACK_ZH, language: "zh" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.required, false);
        assert.equal(j.data.acknowledgement.version, "v2026.06.10");
    });

    await t.test("POST /admin/compliance/accept with wrong phrase returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance/accept`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ phrase: "wrong phrase", language: "en" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/compliance returns required=false after acknowledgement", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}/api/v1/admin/compliance/accept`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ phrase: ACK_EN, language: "en" })
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.required, false);
        assert.ok(j.data.acknowledgement);
        assert.equal(j.data.acknowledgement.admin_user_id, aid);
    });

    await t.test("compliance is per-admin-user", async () => {
        const d = db();
        const aid1 = await insAdmin(d, "admin1@x.com");
        const aid2 = await insAdmin(d, "admin2@x.com");
        const tk1 = await token(d, aid1, "admin1@x.com", "admin");
        const tk2 = await token(d, aid2, "admin2@x.com", "admin");

        await routeRequest(new Request(`${BASE}/api/v1/admin/compliance/accept`, {
            method: "POST", headers: { authorization: `Bearer ${tk1}`, "content-type": "application/json" },
            body: JSON.stringify({ phrase: ACK_EN, language: "en" })
        }), env(d));

        const r1 = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance`, { headers: { authorization: `Bearer ${tk1}` } }), env(d));
        const j1 = await r1.json();
        assert.equal(j1.data.required, false);

        const r2 = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance`, { headers: { authorization: `Bearer ${tk2}` } }), env(d));
        const j2 = await r2.json();
        assert.equal(j2.data.required, true);
    });

    await t.test("non-admin gets 403", async () => {
        const d = db(); const uid = await insUser(d); const tk = await token(d, uid, "user@x.com", "user");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });

    await t.test("missing auth gets 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/compliance`), env(d));
        assert.equal(r.status, 401);
    });
});
