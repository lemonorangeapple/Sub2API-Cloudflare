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

const JWT_SECRET = "sub-test-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d, overrides = {}) {
    const cols = ["created_at","updated_at","email","password_hash","role","status","username","token_version"];
    const phs = ["?","?","?","?","?","?","?","?"];
    const vals = [
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z",
        overrides.email ?? "user@x.com", PASSWORD_HASH, "user", "active", overrides.username ?? "testuser", 0
    ];
    const r = await d.prepare(`INSERT INTO users (${cols.join(",")}) VALUES (${phs.join(",")})`).bind(...vals).run();
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

async function insGroup(d, overrides = {}) {
    const cols = ["name","description","platform","rate_multiplier","status","created_at","updated_at","supported_model_scopes","messages_dispatch_model_config","models_list_config"];
    const phs = ["?","?","?","?","?","?","?","?","?","?"];
    const vals = [overrides.name ?? "test-group", overrides.description ?? "", overrides.platform ?? "openai", overrides.rate_multiplier ?? 1.0, overrides.status ?? "active", "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "[]", "{}", "{}"];
    const r = await d.prepare(`INSERT INTO groups (${cols.join(",")}) VALUES (${phs.join(",")})`).bind(...vals).run();
    return Number(r.meta.last_row_id);
}

test("admin subscriptions", async (t) => {
    await t.test("GET /admin/subscriptions returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/subscriptions/assign creates a subscription", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.user_id, uid);
        assert.equal(j.data.group_id, gid);
        assert.equal(j.data.status, "active");
        assert.ok(j.data.id > 0);
    });

    await t.test("POST /admin/subscriptions/assign validates required fields", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ group_id: 1 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/subscriptions/assign validates user exists", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const gid = await insGroup(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: 99999, group_id: gid, validity_days: 30 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/subscriptions/assign validates group exists", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: 99999, validity_days: 30 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/subscriptions/:id returns subscription", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d, { name: "sub-group" });
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const sid = created.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.id, sid);
        assert.equal(j.data.user_id, uid);
        assert.equal(j.data.group_id, gid);
    });

    await t.test("GET /admin/subscriptions/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("POST /admin/subscriptions/:id/extend extends subscription", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const sid = created.data.id;
        const origExpires = created.data.expires_at;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}/extend`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ days: 10 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(new Date(j.data.expires_at) > new Date(origExpires));
    });

    await t.test("POST /admin/subscriptions/:id/reset-quota resets usage", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const sid = created.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}/reset-quota`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ daily: true, weekly: true, monthly: true })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.daily_usage_usd, 0);
        assert.equal(j.data.weekly_usage_usd, 0);
        assert.equal(j.data.monthly_usage_usd, 0);
    });

    await t.test("POST /admin/subscriptions/:id/reset-quota validates at least one flag", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${created.data.id}/reset-quota`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ daily: false })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/subscriptions/:id/revoke revokes subscription", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const sid = created.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}/revoke`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.message, "Subscription revoked successfully");

        const getR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(getR.status, 404);
    });

    await t.test("POST /admin/subscriptions/:id/restore restores subscription", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const sid = created.data.id;

        await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}/revoke`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}/restore`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.id, sid);
        assert.equal(j.data.status, "active");
    });

    await t.test("DELETE /admin/subscriptions/:id revokes subscription (backward compat)", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const sid = created.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
    });

    await t.test("POST /admin/subscriptions/bulk-assign creates multiple subscriptions", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid1 = await insUser(d, { email: "user1@x.com" });
        const uid2 = await insUser(d, { email: "user2@x.com" });
        const gid = await insGroup(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/bulk-assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_ids: [uid1, uid2], group_id: gid, validity_days: 30 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.successCount, 2);
        assert.equal(j.data.createdCount, 2);
        assert.equal(j.data.failedCount, 0);
    });

    await t.test("GET /admin/groups/:id/subscriptions lists by group", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d, { name: "group-for-test" });
        await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/groups/${gid}/subscriptions`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(j.data.items.length >= 1);
        assert.equal(j.data.items[0].group_id, gid);
    });

    await t.test("GET /admin/users/:id/subscriptions lists by user", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d, { username: "list-user" });
        const gid = await insGroup(d);
        await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/users/${uid}/subscriptions`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data));
        assert.ok(j.data.length >= 1);
        assert.equal(j.data[0].user_id, uid);
    });

    await t.test("GET /admin/subscriptions lists with pagination", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        for (let i = 0; i < 3; i++) {
            await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
                method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
                body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
            }), env(d));
        }

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.items.length, 2);
        assert.equal(j.data.total, 3);
    });

    await t.test("GET /admin/subscriptions/:id/progress returns progress", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const gid = await insGroup(d);
        const createR = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/assign`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ user_id: uid, group_id: gid, validity_days: 30 })
        }), env(d));
        const created = await createR.json();
        const sid = created.data.id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions/${sid}/progress`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.id, sid);
        assert.ok(typeof j.data.expiresInDays === "number");
    });

    await t.test("unauthenticated requests return 401", async () => {
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions`), env(db()));
        assert.equal(r.status, 401);
    });

    await t.test("non-admin users return 403", async () => {
        const d = db(); const uid = await insUser(d, { email: "nonadmin@x.com", username: "nonadmin" }); const tk = await token(d, uid, "nonadmin@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/subscriptions`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });
});
