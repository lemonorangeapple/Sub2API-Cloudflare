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

const JWT_SECRET = "ua-test-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d, e = "user@x.com", u = "user") {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", e, PASSWORD_HASH, "user", "active", u, 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

function token(d, uid, e, r) {
    return async () => {
        const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
        const tv = await legacyTokenVersion(e, PASSWORD_HASH, 0n);
        const s = await signer.sign({ id: uid, email: e, role: r, tokenVersion: tv });
        return s.token;
    };
}

test("GET /admin/user-attributes returns 401 without auth", async () => {
    const d = db(); const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`), env(d)); assert.equal(r.status, 401);
});

test("GET /admin/user-attributes returns empty list", async () => {
    const d = db(); const aid = await insAdmin(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, { headers: { authorization: `Bearer ${t}` } }), env(d));
    assert.equal(r.status, 200); const b = await r.json(); assert.equal(b.data.length, 0);
});

test("POST /admin/user-attributes creates definition", async () => {
    const d = db(); const aid = await insAdmin(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, {
        method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ key: "bio", name: "Biography", type: "textarea", required: true })
    }), env(d));
    assert.equal(r.status, 200); const b = await r.json();
    assert.equal(b.data.key, "bio"); assert.equal(b.data.name, "Biography"); assert.equal(b.data.required, true);
});

test("POST rejects duplicate key", async () => {
    const d = db(); const aid = await insAdmin(d); const t = await token(d, aid, "admin@x.com", "admin")();
    await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, {
        method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ key: "bio", name: "Bio", type: "textarea" })
    }), env(d));
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, {
        method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ key: "bio", name: "Bio 2", type: "text" })
    }), env(d));
    assert.equal(r.status, 409);
});

test("POST rejects invalid type", async () => {
    const d = db(); const aid = await insAdmin(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, {
        method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ key: "bad", name: "Bad", type: "invalid" })
    }), env(d));
    assert.equal(r.status, 400);
});

test("PUT /admin/user-attributes/:id updates def", async () => {
    const d = db(); const aid = await insAdmin(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const c = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, {
        method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ key: "color", name: "Color", type: "select", options: [{ value: "r", label: "Red" }] })
    }), env(d));
    const { id } = (await c.json()).data;
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes/${id}`, {
        method: "PUT", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "Favourite Color" })
    }), env(d));
    assert.equal((await r.json()).data.name, "Favourite Color");
});

test("DELETE /admin/user-attributes/:id soft-deletes def", async () => {
    const d = db(); const aid = await insAdmin(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const c = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, {
        method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ key: "tmp", name: "Temp", type: "text" })
    }), env(d));
    const { id } = (await c.json()).data;
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes/${id}`, { method: "DELETE", headers: { authorization: `Bearer ${t}` } }), env(d));
    assert.equal(r.status, 200);
    const chk = await d.prepare("SELECT deleted_at FROM user_attribute_definitions WHERE id=?").bind(id).first();
    assert.notEqual(chk.deleted_at, null);
});

test("PUT /admin/user-attributes/reorder reorders", async () => {
    const d = db(); const aid = await insAdmin(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const c1 = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, { method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: JSON.stringify({ key: "a", name: "A", type: "text" }) }), env(d));
    const c2 = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, { method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: JSON.stringify({ key: "b", name: "B", type: "text" }) }), env(d));
    const id1 = (await c1.json()).data.id, id2 = (await c2.json()).data.id;
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes/reorder`, {
        method: "PUT", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ ids: [id2, id1] })
    }), env(d));
    assert.equal(r.status, 200);
    const list = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, { headers: { authorization: `Bearer ${t}` } }), env(d));
    const items = (await list.json()).data;
    assert.equal(items[0].id, id2);
    assert.equal(items[1].id, id1);
});

test("POST /admin/user-attributes/batch returns batch attrs", async () => {
    const d = db(); const aid = await insAdmin(d); const uid = await insUser(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const c = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, { method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: JSON.stringify({ key: "k1", name: "K1", type: "text" }) }), env(d));
    const attrId = (await c.json()).data.id;
    await d.prepare("INSERT INTO user_attribute_values (created_at,updated_at,value,user_id,attribute_id) VALUES(?,?,?,?,?)").bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "val1", uid, attrId).run();
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes/batch`, {
        method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ user_ids: [uid] })
    }), env(d));
    assert.equal(r.status, 200);
    const b = await r.json();
    assert.equal(b.data.attributes[uid][attrId], "val1");
});

test("GET /admin/users/:id/attributes returns user attrs", async () => {
    const d = db(); const aid = await insAdmin(d); const uid = await insUser(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const c = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, { method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: JSON.stringify({ key: "k2", name: "K2", type: "text" }) }), env(d));
    const attrId = (await c.json()).data.id;
    await d.prepare("INSERT INTO user_attribute_values (created_at,updated_at,value,user_id,attribute_id) VALUES(?,?,?,?,?)").bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "hello", uid, attrId).run();
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/users/${uid}/attributes`, { headers: { authorization: `Bearer ${t}` } }), env(d));
    assert.equal(r.status, 200);
    const items = (await r.json()).data;
    assert.equal(items.length, 1);
    assert.equal(items[0].value, "hello");
});

test("PUT /admin/users/:id/attributes upserts user attrs", async () => {
    const d = db(); const aid = await insAdmin(d); const uid = await insUser(d); const t = await token(d, aid, "admin@x.com", "admin")();
    const c = await routeRequest(new Request(`${BASE}/api/v1/admin/user-attributes`, { method: "POST", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" }, body: JSON.stringify({ key: "k3", name: "K3", type: "text" }) }), env(d));
    const attrId = (await c.json()).data.id;
    const r = await routeRequest(new Request(`${BASE}/api/v1/admin/users/${uid}/attributes`, {
        method: "PUT", headers: { authorization: `Bearer ${t}`, "content-type": "application/json" },
        body: JSON.stringify({ values: { [attrId]: "world" } })
    }), env(d));
    assert.equal(r.status, 200);
    const items = (await r.json()).data;
    assert.equal(items.length, 1);
    assert.equal(items[0].value, "world");
});
