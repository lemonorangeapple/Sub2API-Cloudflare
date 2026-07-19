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

const JWT_SECRET = "acct-test-secret-that-is-at-least-32-bytes";
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

async function insAccount(d, overrides = {}) {
    const cols = ["name","notes","platform","type","credentials","extra","concurrency","priority","rate_multiplier","status","created_at","updated_at","deleted_at"];
    const phs = ["?","?","?","?","?","?","?","?","?","?","?","?","?"];
    const vals = [
        overrides.name ?? "test-account", overrides.notes ?? "", overrides.platform ?? "openai", overrides.type ?? "apikey",
        overrides.credentials ?? "{}", overrides.extra ?? "{}", overrides.concurrency ?? 3,
        overrides.priority ?? 50, overrides.rate_multiplier ?? 1.0, overrides.status ?? "active",
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", null
    ];
    const r = await d.prepare(`INSERT INTO accounts (${cols.join(",")}) VALUES (${phs.join(",")})`).bind(...vals).run();
    return r.meta.last_row_id;
}

test("admin accounts", async (t) => {
    await t.test("GET /admin/accounts returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/accounts creates an account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "my-account", platform: "openai", type: "apikey", credentials: { api_key: "sk-test" } })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.name, "my-account");
        assert.equal(j.data.platform, "openai");
        assert.ok(j.data.id > 0);
    });

    await t.test("POST /admin/accounts returns 409 on duplicate name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insAccount(d, { name: "dup" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "dup", platform: "openai", type: "apikey", credentials: {} })
        }), env(d));
        assert.equal(r.status, 409);
    });

    await t.test("POST /admin/accounts returns 400 on invalid platform", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "bad", platform: "invalid", type: "apikey", credentials: {} })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/accounts returns 400 on invalid type", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "bad", platform: "openai", type: "invalid", credentials: {} })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/accounts returns 400 on invalid credentials JSON", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "bad", platform: "openai", type: "apikey", credentials: "not-json" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/accounts/:id returns account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insAccount(d, { name: "get-me" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${gid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.name, "get-me");
        assert.equal(j.data.id, gid);
    });

    await t.test("GET /admin/accounts/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/accounts/:id updates account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insAccount(d, { name: "before" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${gid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "after", rate_multiplier: 2.5 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.name, "after");
        assert.equal(j.data.rate_multiplier, 2.5);
    });

    await t.test("PUT /admin/accounts/:id returns 404 on missing account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/99999`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "ghost" })
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("DELETE /admin/accounts/:id soft-deletes account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insAccount(d, { name: "delete-me" });
        const r1 = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${gid}`, { method: "DELETE", headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r1.status, 200);
        const r2 = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${gid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r2.status, 404);
    });

    await t.test("GET /admin/accounts lists with pagination", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insAccount(d, { name: "aaa" }); await insAccount(d, { name: "bbb" }); await insAccount(d, { name: "ccc" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 2);
        assert.equal(j.data.total, 3);
    });

    await t.test("GET /admin/accounts filters by platform", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insAccount(d, { name: "openai-acc", platform: "openai" });
        await insAccount(d, { name: "anthropic-acc", platform: "anthropic" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts?platform=openai`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].platform, "openai");
    });

    await t.test("GET /admin/accounts filters by type", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insAccount(d, { name: "oauth-acc", type: "oauth" });
        await insAccount(d, { name: "apikey-acc", type: "apikey" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts?type=oauth`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].type, "oauth");
    });

    await t.test("GET /admin/accounts filters by status", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insAccount(d, { name: "active-acc", status: "active" });
        await insAccount(d, { name: "inactive-acc", status: "inactive" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts?status=inactive`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].status, "inactive");
    });

    await t.test("GET /admin/accounts filters by group", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "grp1" });
        const acc1 = await insAccount(d, { name: "in-group" });
        const acc2 = await insAccount(d, { name: "out-group" });
        await d.prepare(`INSERT INTO account_groups (account_id, group_id, priority, created_at) VALUES (?, ?, 50, ?)`).bind(acc1, gid, "2026-07-01T00:00:00.000Z").run();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts?group=${gid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 1);
        assert.equal(j.data.items[0].name, "in-group");
    });

    await t.test("GET /admin/accounts/:id/groups returns groups", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "grp1" });
        const acc = await insAccount(d, { name: "acc-with-groups" });
        await d.prepare(`INSERT INTO account_groups (account_id, group_id, priority, created_at) VALUES (?, ?, 50, ?)`).bind(acc, gid, "2026-07-01T00:00:00.000Z").run();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/groups`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.length, 1);
        assert.equal(j.data[0].groupId, gid);
    });

    await t.test("POST /admin/accounts/:id/groups sets groups", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid1 = await insGroup(d, { name: "grp1" });
        const gid2 = await insGroup(d, { name: "grp2" });
        const acc = await insAccount(d, { name: "acc-set-groups" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/groups`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_ids: [gid1, gid2] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        const r2 = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/groups`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j2 = await r2.json();
        assert.equal(j2.data.length, 2);
    });

    await t.test("GET /admin/accounts/:id/stats returns stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insAccount(d, { name: "stats-acc" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${gid}/stats`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.summary.total_requests, "number");
        assert.ok(Array.isArray(j.data.history));
    });

    await t.test("GET /admin/accounts/:id/usage returns usage info", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const acc = await insAccount(d, { name: "usage-acc" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/usage`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.updated_at, "string");
        assert.equal(j.data.five_hour.utilization, 0);
    });

    await t.test("POST /admin/accounts/check-mixed-channel returns no risk by default", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "risk-group" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/check-mixed-channel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ platform: "openai", group_ids: [gid] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.has_risk, false);
    });

    await t.test("POST /admin/accounts/check-mixed-channel detects another platform", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d, { name: "mixed-group" });
        const anthropic = await insAccount(d, { name: "anthropic-in-group", platform: "anthropic" });
        await d.prepare(`INSERT INTO account_groups (account_id, group_id, priority, created_at) VALUES (?, ?, 50, ?)`).bind(anthropic, gid, "2026-07-01T00:00:00.000Z").run();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/check-mixed-channel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ platform: "openai", group_ids: [gid] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.has_risk, true);
        assert.equal(j.data.details.otherPlatform, "anthropic");
    });

    await t.test("POST /admin/accounts/:id/clear-error recovers account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const acc = await insAccount(d, { name: "error-acc", status: "error" });
        await d.prepare(`UPDATE accounts SET error_message = 'bad token' WHERE id = ?`).bind(acc).run();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/clear-error`, { method: "POST", headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.status, "active");
        assert.equal(j.data.error_message, null);
    });

    await t.test("POST /admin/accounts/:id/apply-oauth-credentials merges extra", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const acc = await insAccount(d, { name: "reauth", type: "oauth", credentials: JSON.stringify({ refresh_token: "old" }), extra: JSON.stringify({ base_rpm: 10 }) });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/apply-oauth-credentials`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ type: "oauth", credentials: { access_token: "new" }, extra: { privacy_mode: "set" } })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.credentials.refresh_token, "old");
        assert.equal(j.data.credentials.access_token, "new");
        assert.equal(j.data.extra.base_rpm, 10);
        assert.equal(j.data.extra.privacy_mode, "set");
    });

    await t.test("POST /admin/accounts/bulk-update updates schedulable and returns IDs", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const a1 = await insAccount(d, { name: "bulk-a" });
        const a2 = await insAccount(d, { name: "bulk-b" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/bulk-update`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_ids: [a1, a2], schedulable: false })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.success_ids, [a1, a2]);
        assert.equal(j.data.failed, 0);
        const row = await d.prepare(`SELECT schedulable FROM accounts WHERE id = ?`).bind(a1).first();
        assert.equal(row.schedulable, 0);
    });

    await t.test("GET /admin/accounts/:id/today-stats returns window stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const acc = await insAccount(d, { name: "today-acc" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/today-stats`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data, { requests: 0, tokens: 0, cost: 0, actual_cost: 0, user_cost: 0 });
    });

    await t.test("POST /admin/accounts/:id/shadow creates a spark child", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const parent = await insAccount(d, { name: "parent" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${parent}/shadow`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "spark-child", concurrency: 2 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.quota_dimension, "spark");
        assert.equal(j.data.parent_account_id, parent);
        assert.equal(j.data.concurrency, 2);
    });

    await t.test("GET /admin/accounts/data exports accounts and skips shadows", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const parent = await insAccount(d, { name: "export-parent", credentials: JSON.stringify({ api_key: "secret" }) });
        await d.prepare(`INSERT INTO accounts (name,notes,platform,type,credentials,extra,concurrency,priority,rate_multiplier,status,quota_dimension,parent_account_id,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind("shadow", "", "openai", "apikey", "{}", "{}", 1, 50, 1, "active", "spark", parent, "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", null).run();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/data?include_proxies=false`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.accounts.length, 1);
        assert.equal(j.data.accounts[0].credentials.api_key, "secret");
        assert.equal(j.data.skipped_shadows, 1);
    });

    await t.test("GET /admin/accounts/:id/models uses credential model mapping", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const acc = await insAccount(d, { name: "mapped-models", credentials: JSON.stringify({ model_mapping: { "public-model": "upstream-model" } }) });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${acc}/models`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.map((item) => item.id), ["public-model"]);
    });

    await t.test("GET /admin/accounts/antigravity/default-model-mapping returns canonical mapping", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/antigravity/default-model-mapping`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data["claude-opus-4-6"], "claude-opus-4-6-thinking");
        assert.equal(j.data["gemini-3.1-pro-high"], "gemini-pro-agent");
    });

    await t.test("POST /admin/accounts/data imports an exported account", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const payload = {
            data: {
                exported_at: "2026-07-01T00:00:00.000Z",
                proxies: [],
                accounts: [{ name: "imported", platform: "openai", type: "apikey", credentials: { api_key: "k" }, extra: { base_rpm: 5 }, concurrency: 4, priority: 30 }]
            }
        };
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/data`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" }, body: JSON.stringify(payload)
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.account_created, 1);
        assert.equal(j.data.account_failed, 0);
        const row = await d.prepare(`SELECT credentials, extra, concurrency FROM accounts WHERE name = 'imported'`).first();
        assert.equal(JSON.parse(row.credentials).api_key, "k");
        assert.equal(JSON.parse(row.extra).base_rpm, 5);
        assert.equal(row.concurrency, 4);
    });

    await t.test("upstream-only account operations return 501", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const acc = await insAccount(d, { name: "external-op", type: "oauth" });
        for (const path of [`${acc}/refresh`, `${acc}/set-privacy`, `${acc}/models/sync-upstream`]) {
            const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/${path}`, { method: "POST", headers: { authorization: `Bearer ${tk}` } }), env(d));
            assert.equal(r.status, 501, path);
        }
    });

    await t.test("POST /admin/accounts/import/codex-session reports invalid sessions", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/import/codex-session`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ contents: ["{}"] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.failed, 1);
    });

    await t.test("POST /admin/accounts/batch creates multiple accounts", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/batch`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ accounts: [
                { name: "batch-1", platform: "openai", type: "apikey", credentials: { api_key: "k1" } },
                { name: "batch-2", platform: "anthropic", type: "apikey", credentials: { api_key: "k2" } }
            ]})
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.success, 2);
        assert.equal(j.data.results.length, 2);
    });

    await t.test("POST /admin/accounts/batch-update-credentials updates credentials", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const acc1 = await insAccount(d, { name: "cred-1" });
        const acc2 = await insAccount(d, { name: "cred-2" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts/batch-update-credentials`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ account_ids: [acc1, acc2], field: "account_uuid", value: "new-uuid" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(j.data.updated >= 0);
    });

    await t.test("unauthenticated requests return 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("non-admin users return 403", async () => {
        const d = db();
        await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "user@x.com", PASSWORD_HASH, "user", "active", "user", 0, null, "email").run();
        const uid_r = await d.prepare("SELECT id FROM users WHERE email = 'user@x.com'").first();
        const tk = await token(d, uid_r.id, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/accounts`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });
});
