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

const JWT_SECRET = "grp-test-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

function token(d, uid, email, role) {
    return async () => {
        const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
        const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
        const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
        return s.token;
    };
}

async function insGroup(d, overrides = {}) {
    const cols = ["name","description","platform","rate_multiplier","status","created_at","updated_at","supported_model_scopes","messages_dispatch_model_config","models_list_config"];
    const phs = ["?","?","?","?","?","?","?","?","?","?"];
    const vals = [overrides.name ?? "test-group", overrides.description ?? "", overrides.platform ?? "anthropic", overrides.rate_multiplier ?? 1.0, overrides.status ?? "active", "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "[]", "{}", "{}"];
    if (overrides.sort_order !== undefined) { cols.push("sort_order"); phs.push("?"); vals.push(overrides.sort_order); }
    const r = await d.prepare(`INSERT INTO groups (${cols.join(",")}) VALUES (${phs.join(",")})`).bind(...vals).run();
    return r.meta.last_row_id;
}

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z",
        overrides.email ?? "user@x.com", PASSWORD_HASH,
        overrides.role ?? "user", overrides.status ?? "active", overrides.username ?? "user", 0
    ).run();
    return Number(r.meta.last_row_id);
}

async function insAccount(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO accounts (created_at,updated_at,name,platform,type,credentials,extra) VALUES(?,?,?,?,?,?,?)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z",
        overrides.name ?? "account-x", overrides.platform ?? "openai", overrides.type ?? "manual",
        JSON.stringify({ api_key: "sk-test" }), "{}"
    ).run();
    return Number(r.meta.last_row_id);
}

async function insAPIKey(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO api_keys (created_at,updated_at,key,name,status,user_id,group_id) VALUES(?,?,?,?,?,?,?)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z",
        overrides.key ?? "sk-test-key-12345", overrides.name ?? "key-x",
        overrides.status ?? "active", overrides.user_id ?? 1,
        overrides.group_id ?? null
    ).run();
    return Number(r.meta.last_row_id);
}

async function insUsageLog(d, overrides = {}) {
    const cols = ["created_at", "request_id", "model", "user_id", "api_key_id", "account_id", "group_id", "input_tokens", "output_tokens", "cache_creation_tokens", "cache_read_tokens", "total_cost", "actual_cost", "billing_type", "stream"];
    const vals = [
        overrides.created_at ?? "2026-07-01T00:00:00.000Z",
        overrides.request_id ?? `req-${Math.random().toString(16).slice(2)}`,
        overrides.model ?? "gpt-4o",
        overrides.user_id ?? 1,
        overrides.api_key_id ?? 1,
        overrides.account_id ?? 1,
        overrides.group_id ?? 1,
        overrides.input_tokens ?? 10,
        overrides.output_tokens ?? 20,
        overrides.cache_creation_tokens ?? 0,
        overrides.cache_read_tokens ?? 0,
        overrides.total_cost ?? 0.5,
        overrides.actual_cost ?? 0.4,
        overrides.billing_type ?? 0,
        overrides.stream ?? 0,
    ];
    const phs = cols.map(() => "?");
    await d.prepare(`INSERT INTO usage_logs (${cols.join(",")}) VALUES (${phs.join(",")})`).bind(...vals).run();
}

test("admin groups", async (t) => {
    await t.test("GET /admin/groups returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/groups creates a group", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "my-group", platform: "anthropic" })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.name, "my-group");
        assert.equal(j.data.platform, "anthropic");
        assert.ok(j.data.id > 0);
    });

    await t.test("POST /admin/groups returns 409 on duplicate name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, { name: "dup" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "dup" })
        }), env(d));
        assert.equal(r.status, 409);
    });

    await t.test("POST /admin/groups returns 400 on invalid platform", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "bad", platform: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/groups/:id returns group", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "get-me" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/${gid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.name, "get-me");
        assert.equal(j.data.id, gid);
    });

    await t.test("GET /admin/groups/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/groups/:id updates group", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "before" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/${gid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "after", rate_multiplier: 2.5 })
        }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.name, "after");
        assert.equal(j.data.rate_multiplier, 2.5);
    });

    await t.test("PUT /admin/groups/:id returns 404 on missing group", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/99999`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "ghost" })
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("DELETE /admin/groups/:id soft-deletes group", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "delete-me" });
        const r1 = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/${gid}`, { method: "DELETE", headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r1.status, 200);
        const r2 = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/${gid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r2.status, 404);
    });

    await t.test("GET /admin/groups lists with pagination", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, { name: "aaa" }); await insGroup(d, { name: "bbb" }); await insGroup(d, { name: "ccc" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.items.length, 2);
        assert.equal(j.data.total, 3);
    });

    await t.test("GET /admin/groups filters by platform", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, { name: "openai-g", platform: "openai" });
        await insGroup(d, { name: "anthropic-g", platform: "anthropic" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups?platform=openai`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].platform, "openai");
    });

    await t.test("GET /admin/groups/all returns all active groups", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, { name: "g1" }); await insGroup(d, { name: "g2", status: "disabled" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/all`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.length, 1);
    });

    await t.test("GET /admin/groups/all includes inactive when requested", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, { name: "g1" }); await insGroup(d, { name: "g2", status: "disabled" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/all?include_inactive=true`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(j.data.length, 2);
    });

    await t.test("GET /admin/groups/:id/stats returns stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "stats-g" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/${gid}/stats`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 200);
        const j = await r.json();
        assert.equal(typeof j.data.total_api_keys, "number");
    });

    await t.test("GET /admin/groups/:id/models-list-candidates returns candidates", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "cand-g", platform: "anthropic" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/${gid}/models-list-candidates`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.models));
        assert.ok(j.data.models.length > 0);
    });

    await t.test("GET /admin/groups/usage-summary returns summaries", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "usage-g" });
        const uid = await insUser(d, { email: "usage-user@x.com", username: "usage-user" });
        const acc = await insAccount(d, { name: "usage-account" });
        const kid = await insAPIKey(d, { user_id: uid, group_id: gid });
        await insUsageLog(d, { user_id: uid, api_key_id: kid, account_id: acc, group_id: gid, total_cost: 1.25, actual_cost: 1.1, created_at: "2026-07-01T01:00:00.000Z" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/usage-summary`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data));
        assert.ok(j.data.some((row) => row.group_id === gid));
    });

    await t.test("GET /admin/groups/capacity-summary returns summaries", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, { name: "cap-g" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/capacity-summary`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data));
        assert.equal(typeof j.data[0]?.concurrency_max, "number");
    });

    await t.test("PUT /admin/groups/sort-order updates orders", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insGroup(d, { name: "z", sort_order: 10 });
        await insGroup(d, { name: "a", sort_order: 20 });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/sort-order`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ updates: [{ id: 1, sort_order: 1 }, { id: 2, sort_order: 2 }] })
        }), env(d));
        assert.equal(r.status, 200);
    });

    await t.test("unauthenticated requests return 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("non-admin users return 403", async () => {
        const d = db();
        await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "user@x.com", PASSWORD_HASH, "user", "active", "user", 0, null, "email").run();
        const uid_r = await d.prepare("SELECT id FROM users WHERE email = 'user@x.com'").first();
        const tk = await token(d, uid_r.id, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });
});
