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

const JWT_SECRET = "settings-feat-test-32-bytes-long-key";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function token(d, uid, email, role) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
    const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
    return s.token;
}

const P = "/api/v1/admin/settings";

test("admin settings features", async (t) => {
    // ===== Overload Cooldown =====
    await t.test("GET /admin/settings/overload-cooldown returns defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/overload-cooldown`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, false);
        assert.equal(typeof j.data.cooldownMinutes, "number");
    });

    await t.test("PUT /admin/settings/overload-cooldown updates and returns", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/overload-cooldown`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, cooldown_minutes: 30 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.cooldownMinutes, 30);
    });

    await t.test("PUT /admin/settings/overload-cooldown clamps values", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/overload-cooldown`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, cooldown_minutes: 500 })
        }), env(d));
        const j = await r.json();
        assert.equal(j.data.cooldownMinutes, 120);
    });

    // ===== Rate Limit 429 Cooldown =====
    await t.test("GET /admin/settings/rate-limit-429-cooldown returns defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/rate-limit-429-cooldown`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, false);
        assert.equal(typeof j.data.cooldownSeconds, "number");
    });

    await t.test("PUT /admin/settings/rate-limit-429-cooldown updates", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/rate-limit-429-cooldown`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, cooldown_seconds: 300 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.cooldownSeconds, 300);
    });

    // ===== Stream Timeout =====
    await t.test("GET /admin/settings/stream-timeout returns defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/stream-timeout`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, false);
        assert.equal(j.data.action, "temp_unsched");
    });

    await t.test("PUT /admin/settings/stream-timeout updates", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/stream-timeout`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, action: "error", temp_unsched_minutes: 20 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.action, "error");
    });

    await t.test("PUT /admin/settings/stream-timeout invalid action returns 400", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/stream-timeout`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, action: "invalid" })
        }), env(d));
        assert.equal(r.status, 400);
    });

    // ===== Rectifier =====
    await t.test("GET /admin/settings/rectifier returns defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/rectifier`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, false);
        assert.ok(Array.isArray(j.data.apikeySignaturePatterns));
    });

    await t.test("PUT /admin/settings/rectifier updates", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/rectifier`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, thinking_signature_enabled: true, thinking_budget_enabled: false, apikey_signature_enabled: true, apikey_signature_patterns: ["test-pattern"] })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.thinkingSignatureEnabled, true);
        assert.deepEqual(j.data.apikeySignaturePatterns, ["test-pattern"]);
    });

    // ===== Beta Policy =====
    await t.test("GET /admin/settings/beta-policy returns defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/beta-policy`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(j.data.rules));
    });

    await t.test("PUT /admin/settings/beta-policy updates", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const rules = [{ beta_token: "tok1", action: "pass", scope: "all" }];
        const r = await routeRequest(new Request(`${BASE}${P}/beta-policy`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ rules })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.deepEqual(j.data.rules, rules);
    });

    // ===== Admin API Key =====
    await t.test("GET /admin/settings/admin-api-key returns not exists", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/admin-api-key`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.exists, false);
    });

    await t.test("POST /admin/settings/admin-api-key/regenerate creates key", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/admin-api-key/regenerate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.ok(j.data.key.startsWith("admin-"));
        assert.ok(j.data.key.length > 10);
    });

    await t.test("GET /admin/settings/admin-api-key returns exists after regenerate", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${P}/admin-api-key/regenerate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${P}/admin-api-key`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.exists, true);
        assert.ok(j.data.maskedKey.includes("..."));
    });

    await t.test("DELETE /admin/settings/admin-api-key removes key", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        await routeRequest(new Request(`${BASE}${P}/admin-api-key/regenerate`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const r = await routeRequest(new Request(`${BASE}${P}/admin-api-key`, {
            method: "DELETE", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);
        const g = await routeRequest(new Request(`${BASE}${P}/admin-api-key`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await g.json();
        assert.equal(j.data.exists, false);
    });

    // ===== Web Search Emulation =====
    await t.test("GET /admin/settings/web-search-emulation returns defaults", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const r = await routeRequest(new Request(`${BASE}${P}/web-search-emulation`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, false);
        assert.ok(Array.isArray(j.data.providers));
    });

    await t.test("PUT /admin/settings/web-search-emulation updates", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin");
        const providers = [{ type: "brave", api_key: "BSA123", quota_limit: 1000 }];
        const r = await routeRequest(new Request(`${BASE}${P}/web-search-emulation`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, providers })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.enabled, true);
        assert.equal(j.data.providers[0].apiKeyConfigured, true);
        assert.equal(j.data.providers[0].type, "brave");
    });

    // ===== Auth =====
    await t.test("without auth returns 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}${P}/overload-cooldown`, {}), env(d));
        assert.equal(r.status, 401);
    });
});
