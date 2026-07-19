import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql", "0002_business_supplemental.sql", "0003_ops_usage_supplemental.sql",
    "0004_runtime_state.sql", "0005_auth_sessions.sql"
].map((n) => readFile(new URL(`../../d1/migrations/${n}`, import.meta.url), "utf8")));

const JWT_SECRET = "usage-user-test-secret-at-least-32-bytes!!";
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

async function insAPIKey(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO api_keys (created_at,updated_at,key,name,status,user_id,group_id) VALUES(?,?,?,?,?,?,?)`).bind(
        NOW, NOW,
        overrides.key ?? "sk-test-key-12345", overrides.name ?? "test-key",
        overrides.status ?? "active", overrides.user_id ?? 1,
        overrides.group_id ?? null
    ).run();
    return Number(r.meta.last_row_id);
}

async function insAccount(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO accounts (created_at,updated_at,name,platform,type,credentials,extra) VALUES(?,?,?,?,?,?,?)`).bind(
        NOW, NOW,
        overrides.name ?? "test-account", overrides.platform ?? "openai",
        overrides.type ?? "manual", JSON.stringify({ api_key: "sk-test" }), "{}"
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

test("user-facing usage routes", async (t) => {
    await t.test("GET /usage returns empty list for new user", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/usage`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.deepEqual(j.data.items, []);
        assert.equal(j.data.total, 0);
    });

    await t.test("GET /usage returns usage records", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream,duration_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0, 500
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].model, "gpt-4");
        assert.equal(j.data.items[0].input_tokens, 100);
        assert.equal(j.data.items[0].total_cost, 0.015);
        assert.equal(j.data.items[0].stream, false);
    });

    await t.test("GET /usage/stats returns aggregated stats", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0
        ).run();
        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-002", "claude-3", uid, kid, aid, 200, 100, 0.03, 0.02, 0, 1
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/stats`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.total_requests, 2);
        assert.equal(j.data.total_input_tokens, 300);
        assert.equal(j.data.total_output_tokens, 150);
        assert.equal(j.data.total_cost, 0.045);
    });

    await t.test("GET /usage/dashboard/stats returns dashboard stats", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid, status: "active" });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/dashboard/stats`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.total_api_keys >= 1, true);
        assert.equal(j.data.total_requests, 1);
        assert.equal(j.data.total_cost, 0.015);
    });

    await t.test("GET /usage/dashboard/models returns model stats", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/dashboard/models`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].model, "gpt-4");
    });

    await t.test("GET /usage/dashboard/trend returns trend data", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0
        ).run();

        // Trend for today period
        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/dashboard/trend?period=today`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data.items));
    });

    await t.test("GET /usage/dashboard/snapshot-v2 returns combined data", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/dashboard/snapshot-v2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data.trend));
        assert.ok(Array.isArray(j.data.model_stats));
    });

    await t.test("GET /usage/:id returns single record", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream,duration_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0, 500
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/1`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.id, 1);
        assert.equal(j.data.model, "gpt-4");
    });

    await t.test("GET /user/api-keys/:id/usage/daily returns daily usage", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO usage_logs (created_at,request_id,model,user_id,api_key_id,account_id,input_tokens,output_tokens,total_cost,actual_cost,billing_type,stream) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, "req-001", "gpt-4", uid, kid, aid, 100, 50, 0.015, 0.01, 0, 0
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/user/api-keys/${kid}/usage/daily`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data.items));
    });

    await t.test("GET /usage/errors returns empty list for new user", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/errors`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.total, 0);
        assert.ok(Array.isArray(j.data.items));
    });

    await t.test("GET /usage/errors/:id returns 404 for non-existent", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/errors/999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /usage/errors/:id returns error detail", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO ops_error_logs (created_at,user_id,api_key_id,account_id,model,platform,error_phase,error_type,status_code,error_message,error_body,stream,user_agent,inbound_endpoint,upstream_status_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
            NOW, uid, kid, aid, "gpt-4", "openai", "upstream", "upstream_error", 502, "Bad Gateway", '{"error":"upstream_fail"}', 0, "test-agent", "/chat/completions", 502
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/errors/1`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.message, "Bad Gateway");
        assert.equal(j.data.category, "upstream");
    });

    await t.test("GET /user/platform-quotas returns quotas", async () => {
        const d = db();
        const uid = await insUser(d);
        const aid = await insAccount(d);
        const kid = await insAPIKey(d, { user_id: uid });
        const tk = await token(d, uid, "user@x.com", "user")();

        await d.prepare(`INSERT INTO user_platform_quotas (created_at,updated_at,user_id,platform,daily_limit_usd,weekly_limit_usd,monthly_limit_usd) VALUES(?,?,?,?,?,?,?)`).bind(
            NOW, NOW, uid, "openai", 10.0, 50.0, 200.0
        ).run();

        const r = await routeRequest(new Request(`${BASE}/api/v1/user/platform-quotas`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data.platform_quotas));
        assert.equal(j.data.platform_quotas.length, 1);
        assert.equal(j.data.platform_quotas[0].platform, "openai");
        assert.equal(j.data.platform_quotas[0].daily_limit_usd, 10.0);
    });

    await t.test("without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/usage/stats`), env(d));
        assert.equal(r.status, 401);
    });
});
