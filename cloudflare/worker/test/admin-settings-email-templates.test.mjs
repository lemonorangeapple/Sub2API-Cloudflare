import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

const JWT_SECRET = "admin-settings-email-templates-test-jwt-secret";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertUser(db, overrides = {}) {
    const values = { email: "admin@x.com", passwordHash: PASSWORD_HASH, role: "admin", status: "active", username: "admin", ...overrides };
    await db.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", values.email, values.passwordHash, values.role, values.status, values.username, 0, null, "email"
    ).run();
}

function env(db) {
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30", TOTP_ENCRYPTION_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" };
}

async function createToken(db, role = "admin", userId = 1, email = "admin@x.com", passwordHash = PASSWORD_HASH) {
    const { Hs256JwtSigner } = await import("../src/services/jwt.ts");
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, passwordHash, 0n);
    const signed = await signer.sign({ id: userId, email, role, tokenVersion });
    return signed.token;
}

const BASE = "https://edge.example/api/v1/admin/settings";

test("admin settings email templates", async (t) => {
    await t.test("GET /email-templates returns list with events and locales", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/email-templates`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data.events));
        assert.equal(j.data.events.length, 13);
        assert.equal(j.data.events[0].value, "auth.verify_code");
        assert.deepEqual(j.data.locales, ["en", "zh"]);
        assert.ok(Array.isArray(j.data.templates));
        assert.equal(j.data.templates.length, 26);
        assert.ok(Array.isArray(j.data.placeholders));
    });

    await t.test("GET /email-templates returns 401 without auth", async () => {
        const d = createDatabase();
        const r = await routeRequest(new Request(`${BASE}/email-templates`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("GET /email-templates/:event/:locale returns official template", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/en`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.event, "auth.verify_code");
        assert.equal(j.data.locale, "en");
        assert.equal(j.data.is_custom, false);
        assert.ok(j.data.subject.includes("verification code"));
        assert.ok(j.data.html.includes("<!DOCTYPE html>"));
        assert.ok(Array.isArray(j.data.placeholders));
    });

    await t.test("GET /email-templates/:event/:locale returns zh template", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/zh`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.locale, "zh");
        assert.ok(j.data.subject.includes("验证码"));
    });

    await t.test("PUT /email-templates/:event/:locale saves custom template", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/en`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ subject: "[{{site_name}}] Custom subject", html: "<p>Custom body {{recipient_name}}</p>" }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.subject, "[{{site_name}}] Custom subject");
        assert.equal(j.data.is_custom, true);
        assert.ok(j.data.updated_at);

        // Verify persisted
        const stored = await d.prepare("SELECT value FROM settings WHERE key = ?").bind("notification_email_template:auth.verify_code:en").first();
        assert.ok(stored !== null);
        assert.ok(stored.value.includes("Custom subject"));
    });

    await t.test("PUT /email-templates/:event/:locale validates required fields", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/en`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ subject: "", html: "" }),
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("GET /email-templates/:event/:locale returns custom template after update", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        // Save custom
        await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/en`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ subject: "[{{site_name}}] Custom subj", html: "<p>Custom html {{recipient_name}}</p>" }),
        }), env(d));

        // Read back
        const r = await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/en`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.is_custom, true);
        assert.equal(j.data.subject, "[{{site_name}}] Custom subj");
    });

    await t.test("POST /email-templates/:event/:locale/restore-official restores built-in", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        // Save custom
        await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/en`, {
            method: "PUT",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ subject: "[{{site_name}}] Custom", html: "<p>Custom</p>" }),
        }), env(d));

        // Restore
        const r = await routeRequest(new Request(`${BASE}/email-templates/auth.verify_code/en/restore-official`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` },
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.is_custom, false);
        assert.ok(j.data.subject.includes("verification code"));
    });

    await t.test("POST /email-template-preview renders with variables", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/email-template-preview`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({
                event: "auth.verify_code",
                locale: "en",
                subject: "[{{site_name}}] Test {{verification_code}}",
                html: "<p>Code: {{verification_code}}</p>",
            }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(j.data.subject.includes("Test"));
        assert.ok(j.data.html.includes("Code:"));
    });

    await t.test("GET /email-templates/:event/:locale returns 400 for unknown event", async () => {
        const d = createDatabase();
        await insertUser(d);
        const tk = await createToken(d);

        const r = await routeRequest(new Request(`${BASE}/email-templates/unknown.event/en`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("unauthenticated requests return 401", async () => {
        const d = createDatabase();
        for (const path of ["/email-templates", "/email-templates/auth.verify_code/en", "/email-template-preview"]) {
            const r = await routeRequest(new Request(`${BASE}${path}`, { method: "GET" }), env(d));
            assert.equal(r.status, 401);
        }
    });
});
