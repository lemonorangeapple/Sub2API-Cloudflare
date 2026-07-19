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

const JWT_SECRET = "subs-user-test-secret-at-least-32-bytes!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z",
        overrides.email ?? "user@x.com", PASSWORD_HASH,
        "user", "active", overrides.username ?? "testuser", 0
    ).run();
    return Number(r.meta.last_row_id);
}

async function insGroup(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO groups (name, platform, rate_multiplier, status, supported_model_scopes, messages_dispatch_model_config, models_list_config, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
        overrides.name ?? "Standard", overrides.platform ?? "openai", overrides.rate_multiplier ?? 1,
        "active", "[]", "{}", "[]", "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"
    ).run();
    return Number(r.meta.last_row_id);
}

async function insSub(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO user_subscriptions (user_id, group_id, starts_at, expires_at, status, daily_window_start, weekly_window_start, monthly_window_start, daily_usage_usd, weekly_usage_usd, monthly_usage_usd, assigned_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.user_id ?? 1, overrides.group_id ?? 1,
        overrides.starts_at ?? "2026-06-01T00:00:00.000Z",
        overrides.expires_at ?? "2026-12-01T00:00:00.000Z",
        overrides.status ?? "active",
        overrides.daily_window_start ?? "2026-07-01T00:00:00.000Z",
        overrides.weekly_window_start ?? "2026-07-01T00:00:00.000Z",
        overrides.monthly_window_start ?? "2026-07-01T00:00:00.000Z",
        overrides.daily_usage_usd ?? 0, overrides.weekly_usage_usd ?? 0, overrides.monthly_usage_usd ?? 0,
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"
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

test("user-facing subscription routes", async (t) => {
    await t.test("GET /subscriptions returns all user subscriptions", async () => {
        const d = db();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        await insSub(d, { user_id: uid, group_id: gid });
        await insSub(d, { user_id: uid, group_id: gid, status: "expired", expires_at: "2026-01-01T00:00:00.000Z" });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/subscriptions`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.length, 2);
    });

    await t.test("GET /subscriptions/active returns active only", async () => {
        const d = db();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        await insSub(d, { user_id: uid, group_id: gid });
        await insSub(d, { user_id: uid, group_id: gid, status: "expired", expires_at: "2026-01-01T00:00:00.000Z" });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/subscriptions/active`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.length, 1);
        assert.equal(j.data[0].group_name, "Standard");
    });

    await t.test("GET /subscriptions/progress returns progress", async () => {
        const d = db();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        await insSub(d, { user_id: uid, group_id: gid });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/subscriptions/progress`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data));
        assert.ok(j.data.length >= 1);
        assert.equal(typeof j.data[0].expiresInDays, "number");
    });

    await t.test("GET /subscriptions/summary returns summary", async () => {
        const d = db();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        await insSub(d, { user_id: uid, group_id: gid, monthly_usage_usd: 5 });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/subscriptions/summary`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.active_count, 1);
        assert.equal(j.data.total_used_usd, 5);
        assert.equal(j.data.subscriptions.length, 1);
    });

    await t.test("unauthenticated requests get 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/subscriptions`), env(d));
        assert.equal(r.status, 401);
    });
});
