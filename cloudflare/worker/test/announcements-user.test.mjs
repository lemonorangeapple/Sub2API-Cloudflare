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

const JWT_SECRET = "announce-user-test-secret-at-least-32-bytes!!";
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
        overrides.balance ?? 0
    ).run();
    return Number(r.meta.last_row_id);
}

async function insAnnouncement(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO announcements (created_at,updated_at,title,content,status,notify_mode,targeting,starts_at,ends_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
        overrides.created_at ?? NOW, overrides.updated_at ?? NOW,
        overrides.title ?? "Test Announcement",
        overrides.content ?? "Test content",
        overrides.status ?? "active",
        overrides.notify_mode ?? "silent",
        overrides.targeting ?? null,
        overrides.starts_at ?? "2026-07-01T00:00:00.000Z",
        overrides.ends_at ?? "2026-12-31T23:59:59.000Z"
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

test("user-facing announcement routes", async (t) => {
    await t.test("GET /announcements returns visible announcements", async () => {
        const d = db();
        const uid = await insUser(d, { balance: 500 });
        const a1 = await insAnnouncement(d, { id: 1, title: "All Users", targeting: null });
        const a2 = await insAnnouncement(d, { id: 2, title: "Balance >= 100", targeting: JSON.stringify({ anyOf: [{ allOf: [{ type: "balance", operator: "gte", value: 100 }] }] }) });
        await insAnnouncement(d, { id: 3, title: "Balance >= 1000", targeting: JSON.stringify({ anyOf: [{ allOf: [{ type: "balance", operator: "gte", value: 1000 }] }] }) });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/announcements`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.length, 2);
        assert.equal(j.data[0].title, "Balance >= 100");
        assert.equal(j.data[1].title, "All Users");
    });

    await t.test("GET /announcements unread_only filter", async () => {
        const d = db();
        const uid = await insUser(d, { balance: 500 });
        const a1 = await insAnnouncement(d, { title: "Readable", targeting: null });
        await insAnnouncement(d, { title: "Also readable", targeting: null });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r1 = await routeRequest(new Request(`${BASE}/api/v1/announcements?unread_only=true`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j1 = await r1.json();
        assert.equal(r1.status, 200);
        assert.equal(j1.data.length, 2);

        await d.prepare(`INSERT INTO announcement_reads (read_at,created_at,announcement_id,user_id) VALUES(?,?,?,?)`).bind(NOW, NOW, a1, uid).run();
        const r2 = await routeRequest(new Request(`${BASE}/api/v1/announcements?unread_only=true`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j2 = await r2.json();
        assert.equal(r2.status, 200);
        assert.equal(j2.data.length, 1);
    });

    await t.test("POST /announcements/:id/read marks as read", async () => {
        const d = db();
        const uid = await insUser(d, { balance: 500 });
        const a1 = await insAnnouncement(d, { title: "Read me", targeting: null });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/announcements/${a1}/read`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 200);

        const row = await d.prepare(`SELECT COUNT(*) as c FROM announcement_reads WHERE announcement_id=? AND user_id=?`).bind(a1, uid).first();
        assert.equal(row.c, 1);
    });

    await t.test("POST /announcements/:id/read validates targeting", async () => {
        const d = db();
        const uid = await insUser(d, { balance: 10 });
        const a1 = await insAnnouncement(d, { title: "Only rich", targeting: JSON.stringify({ anyOf: [{ allOf: [{ type: "balance", operator: "gte", value: 100 }] }] }) });
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/announcements/${a1}/read`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("unauthenticated requests get 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/announcements`), env(d));
        assert.equal(r.status, 401);
    });
});
