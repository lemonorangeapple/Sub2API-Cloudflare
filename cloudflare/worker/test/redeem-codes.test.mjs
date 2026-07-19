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

const JWT_SECRET = "rc-test-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", overrides.email ?? "user@x.com", PASSWORD_HASH, "user", "active", overrides.username ?? "testuser", 0).run();
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

async function insGroup(d) {
    const cols = ["name","description","platform","rate_multiplier","status","created_at","updated_at","supported_model_scopes","messages_dispatch_model_config","models_list_config"];
    const phs = ["?","?","?","?","?","?","?","?","?","?"];
    const vals = ["test-group", "", "openai", 1.0, "active", "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "[]", "{}", "{}"];
    const r = await d.prepare(`INSERT INTO groups (${cols.join(",")}) VALUES (${phs.join(",")})`).bind(...vals).run();
    return Number(r.meta.last_row_id);
}

test("admin redeem codes", async (t) => {
    await t.test("GET /admin/redeem-codes returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("POST /admin/redeem-codes/generate creates codes", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 3, type: "balance", value: 10 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.length, 3);
        for (const c of j.data) {
            assert.equal(c.type, "balance");
            assert.equal(c.value, 10);
            assert.equal(c.status, "unused");
            assert.ok(c.code.length > 0);
        }
    });

    await t.test("POST /admin/redeem-codes/generate validates count", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 0, type: "balance", value: 10 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/redeem-codes/generate validates type", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 1, type: "invalid", value: 10 })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/redeem-codes/create-and-redeem creates and redeems", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d, { email: "target@x.com" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/create-and-redeem`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "MY-CUSTOM-CODE", value: 100, user_id: uid })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.code, "MY-CUSTOM-CODE");
        assert.equal(j.data.status, "used");
        assert.equal(j.data.used_by, uid);
    });

    await t.test("POST /admin/redeem-codes/create-and-redeem validates required fields", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/create-and-redeem`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ code: "X" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/redeem-codes/:id returns code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const genR = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 1, type: "balance", value: 5 })
        }), env(d));
        const genJ = await genR.json();
        const cid = genJ.data[0].id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.id, cid);
        assert.equal(j.data.status, "unused");
    });

    await t.test("GET /admin/redeem-codes/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/redeem-codes/stats returns stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/stats`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(typeof j.data.totalCodes === "number");
    });

    await t.test("POST /admin/redeem-codes/:id/expire expires a code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const genR = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 1, type: "balance", value: 5 })
        }), env(d));
        const genJ = await genR.json();
        const cid = genJ.data[0].id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/${cid}/expire`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.status, "expired");
    });

    await t.test("DELETE /admin/redeem-codes/:id deletes a code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const genR = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 1, type: "balance", value: 5 })
        }), env(d));
        const genJ = await genR.json();
        const cid = genJ.data[0].id;

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/${cid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);

        const getR = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/${cid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(getR.status, 404);
    });

    await t.test("POST /admin/redeem-codes/batch-delete deletes multiple", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const genR = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 3, type: "balance", value: 5 })
        }), env(d));
        const genJ = await genR.json();
        const ids = genJ.data.map(c => c.id);

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/batch-delete`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ids })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.deleted, 3);
    });

    await t.test("POST /admin/redeem-codes/batch-update updates multiple", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const genR = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 2, type: "balance", value: 5 })
        }), env(d));
        const genJ = await genR.json();
        const ids = genJ.data.map(c => c.id);

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/batch-update`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ ids, fields: { status: "disabled" } })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.updated, 2);
    });

    await t.test("GET /admin/redeem-codes exports CSV", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 2, type: "balance", value: 5 })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/export`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 200);
        assert.equal(r.headers.get("content-type"), "text/csv");
        const csv = await r.text();
        assert.ok(csv.includes("id,code,type"));
        const lines = csv.split("\n");
        assert.ok(lines.length >= 3);
    });

    await t.test("GET /admin/redeem-codes lists with pagination", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 5, type: "balance", value: 5 })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes?page=1&page_size=2`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.items.length, 2);
        assert.equal(j.data.total, 5);
    });

    await t.test("GET /admin/redeem-codes filters by type", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 1, type: "balance", value: 5 })
        }), env(d));
        await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 1, type: "concurrency", value: 2 })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes?type=balance`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.total, 1);
        assert.equal(j.data.items[0].type, "balance");
    });

    await t.test("GET /admin/redeem-codes filters by status", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes/generate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ count: 1, type: "balance", value: 5 })
        }), env(d));

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes?status=unused`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(j.data.total >= 1);
    });

    await t.test("unauthenticated requests return 401", async () => {
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes`), env(db()));
        assert.equal(r.status, 401);
    });

    await t.test("non-admin users return 403", async () => {
        const d = db(); const uid = await insUser(d, { email: "nonadmin@x.com", username: "nonadmin" }); const tk = await token(d, uid, "nonadmin@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/redeem-codes`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });
});
