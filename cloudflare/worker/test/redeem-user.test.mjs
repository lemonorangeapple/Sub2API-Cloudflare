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

const JWT_SECRET = "redeem-user-test-secret-at-least-32-bytes!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";
const NOW = "2026-07-15T12:00:00.000Z";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version,balance,concurrency) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(
        NOW, NOW,
        overrides.email ?? "user@x.com", PASSWORD_HASH,
        "user", "active", overrides.username ?? "testuser", 0,
        overrides.balance ?? 100, overrides.concurrency ?? 5
    ).run();
    return Number(r.meta.last_row_id);
}

async function insGroup(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO groups (name, platform, rate_multiplier, status, supported_model_scopes, messages_dispatch_model_config, models_list_config, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
        overrides.name ?? "Standard", overrides.platform ?? "openai", overrides.rate_multiplier ?? 1,
        "active", "[]", "{}", "[]", NOW, NOW
    ).run();
    return Number(r.meta.last_row_id);
}

async function insCode(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO redeem_codes (code, type, value, status, created_at, expires_at, validity_days, group_id, used_by, used_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.code ?? "TEST-CODE-1234", overrides.type ?? "balance",
        overrides.value ?? 50, overrides.status ?? "unused",
        overrides.created_at ?? NOW, overrides.expires_at ?? null,
        overrides.validity_days ?? 30, overrides.group_id ?? null,
        overrides.used_by ?? null, overrides.used_at ?? null
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

test("user-facing redeem routes", async (t) => {
    await t.test("POST /redeem redeems a balance code", async () => {
        const d = db();
        const uid = await insUser(d, { balance: 100 });
        await insCode(d, { code: "BAL-CODE-001", type: "balance", value: 50 });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/redeem`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "BAL-CODE-001" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.type, "balance");
        assert.equal(j.data.value, 50);
    });

    await t.test("POST /redeem redeems a subscription code", async () => {
        const d = db();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        await insCode(d, { code: "SUB-CODE-001", type: "subscription", value: 30, group_id: gid, validity_days: 30 });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/redeem`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "SUB-CODE-001" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.type, "subscription");
    });

    await t.test("POST /redeem rejects used code", async () => {
        const d = db();
        const uid = await insUser(d);
        await insCode(d, { code: "USED-CODE", status: "used" });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/redeem`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "USED-CODE" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /redeem rejects non-existent code", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/redeem`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "NONEXISTENT" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /redeem/history returns redeem history", async () => {
        const d = db();
        const uid = await insUser(d);
        await insCode(d, { code: "HIST-001", type: "balance", value: 10, status: "used", used_by: uid, used_at: NOW });
        await insCode(d, { code: "HIST-002", type: "balance", value: 20, status: "used", used_by: uid, used_at: NOW });
        await insCode(d, { code: "UNUSED-FOR-OTHER", status: "unused" });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/redeem/history`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.length, 2);
    });

    await t.test("unauthenticated requests get 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/redeem`, { method: "POST", body: JSON.stringify({ code: "X" }), headers: { "content-type": "application/json" } }), env(d));
        assert.equal(r.status, 401);
    });
});
