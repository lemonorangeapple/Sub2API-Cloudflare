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

const JWT_SECRET = "error-passthrough-test-secret-32-bytes-long!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
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

async function insRule(d, overrides = {}) {
    const now = "2026-07-01T00:00:00.000Z";
    const defaults = {
        name: "Test Rule", enabled: 1, priority: 0,
        error_codes: JSON.stringify([422]), keywords: JSON.stringify(["context limit"]),
        match_mode: "any", platforms: null,
        passthrough_code: 1, response_code: null, passthrough_body: 1,
        custom_message: null, skip_monitoring: 0, description: null,
        ...overrides
    };
    const cols = Object.keys(defaults);
    const phs = cols.map(() => "?");
    const vals = Object.values(defaults);
    const r = await d.prepare(`INSERT INTO error_passthrough_rules (created_at,updated_at,${cols.join(",")}) VALUES (?,?,${phs.join(",")})`).bind(now, now, ...vals).run();
    return Number(r.meta.last_row_id);
}

test("error passthrough rules", async (t) => {
    await t.test("GET /admin/error-passthrough-rules returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.deepEqual(j.data, []);
    });

    await t.test("POST /admin/error-passthrough-rules creates a rule", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Context Limit", error_codes: [422], keywords: ["context limit"], match_mode: "all" })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "Context Limit");
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.matchMode, "all");
        assert.deepEqual(j.data.errorCodes, [422]);
        assert.deepEqual(j.data.keywords, ["context limit"]);
        assert.equal(j.data.passthroughCode, true);
        assert.equal(j.data.passthroughBody, true);
    });

    await t.test("POST /admin/error-passthrough-rules applies defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Default Rule", error_codes: [400] })
        }), env(d));
        const j = await r.json();
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.priority, 0);
        assert.equal(j.data.matchMode, "any");
        assert.equal(j.data.passthroughCode, true);
        assert.equal(j.data.passthroughBody, true);
        assert.equal(j.data.skipMonitoring, false);
        assert.deepEqual(j.data.keywords, []);
        assert.deepEqual(j.data.platforms, []);
    });

    await t.test("POST /admin/error-passthrough-rules rejects empty name", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "", error_codes: [400] })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/error-passthrough-rules rejects missing conditions", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "No Conditions", error_codes: [], keywords: [] })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/error-passthrough-rules rejects invalid match_mode", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Bad Mode", error_codes: [400], match_mode: "maybe" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST rejects passthrough_code=false without response_code", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "No Code", error_codes: [400], passthrough_code: false })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST rejects passthrough_body=false without custom_message", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, {
            method: "POST", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "No Body", error_codes: [400], passthrough_body: false })
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /admin/error-passthrough-rules/:id returns rule", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const rid = await insRule(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules/${rid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.id, rid);
        assert.equal(j.data.name, "Test Rule");
    });

    await t.test("GET /admin/error-passthrough-rules/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("PUT /admin/error-passthrough-rules/:id updates fields", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const rid = await insRule(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules/${rid}`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Updated Rule", enabled: false, skip_monitoring: true })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.name, "Updated Rule");
        assert.equal(j.data.enabled, false);
        assert.equal(j.data.skipMonitoring, true);
    });

    await t.test("PUT /admin/error-passthrough-rules/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules/99999`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ name: "Nope" })
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("DELETE /admin/error-passthrough-rules/:id deletes rule", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const rid = await insRule(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules/${rid}`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const g = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules/${rid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(g.status, 404);
    });

    await t.test("DELETE /admin/error-passthrough-rules/:id returns 404", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules/99999`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("GET /admin/error-passthrough-rules returns list ordered by priority", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await insRule(d, { name: "Low", priority: 10, error_codes: JSON.stringify([500]) });
        await insRule(d, { name: "High", priority: 1, error_codes: JSON.stringify([400]) });
        await insRule(d, { name: "Mid", priority: 5, error_codes: JSON.stringify([422]) });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.length, 3);
        assert.equal(j.data[0].name, "High");
        assert.equal(j.data[1].name, "Mid");
        assert.equal(j.data[2].name, "Low");
    });

    await t.test("non-admin gets 403", async () => {
        const d = db(); const uid = await insUser(d); const tk = await token(d, uid, "user@x.com", "user");
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });

    await t.test("missing auth gets 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/error-passthrough-rules`), env(d));
        assert.equal(r.status, 401);
    });
});
