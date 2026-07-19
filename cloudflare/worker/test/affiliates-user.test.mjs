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

const JWT_SECRET = "aff-user-test-secret-at-least-32-bytes!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";
const NOW = "2026-07-15T12:00:00.000Z";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version,balance) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
        NOW, NOW,
        overrides.email ?? "user@x.com", PASSWORD_HASH,
        "user", "active", overrides.username ?? "testuser", 0,
        overrides.balance ?? 100
    ).run();
    return Number(r.meta.last_row_id);
}

async function insAff(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO user_affiliates (user_id, aff_code, aff_quota, aff_frozen_quota, aff_history_quota, aff_count, inviter_id, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
        overrides.user_id, overrides.aff_code ?? "TESTCODE1234",
        overrides.aff_quota ?? 50, overrides.aff_frozen_quota ?? 0,
        overrides.aff_history_quota ?? 0, overrides.aff_count ?? 3,
        overrides.inviter_id ?? null, NOW, NOW
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

test("user-facing affiliate routes", async (t) => {
    await t.test("GET /user/aff returns affiliate detail", async () => {
        const d = db();
        const uid = await insUser(d);
        await insAff(d, { user_id: uid, aff_quota: 100 });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/user/aff`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.affCode, "TESTCODE1234");
        assert.equal(j.data.affQuota, 100);
        assert.equal(j.data.affCount, 3);
        assert.ok(Array.isArray(j.data.invitees));
    });

    await t.test("GET /user/aff creates affiliate profile on-demand", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/user/aff`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(typeof j.data.affCode === "string");
        assert.equal(j.data.affQuota, 0);
        assert.equal(j.data.affCount, 0);
    });

    await t.test("POST /user/aff/transfer transfers quota to balance", async () => {
        const d = db();
        const uid = await insUser(d, { balance: 100 });
        await insAff(d, { user_id: uid, aff_quota: 50 });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/user/aff/transfer`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.transferredQuota, 50);
    });

    await t.test("unauthenticated requests get 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/user/aff`), env(d));
        assert.equal(r.status, 401);
    });
});
