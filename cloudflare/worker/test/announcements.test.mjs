import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

const JWT_SECRET = "announcement-test-secret-that-is-at-least-32-bytes";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertAdmin(db) {
    const result = await db.prepare(
        `INSERT INTO users (created_at, updated_at, email, password_hash, role, status, username, totp_enabled, totp_secret_encrypted, signup_source, token_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
    ).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@example.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function insertUser(db, overrides = {}) {
    const email = overrides.email ?? "user@example.com";
    const username = overrides.username ?? "testuser";
    const result = await db.prepare(
        `INSERT INTO users (created_at, updated_at, email, password_hash, role, status, username, totp_enabled, totp_secret_encrypted, signup_source, token_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
    ).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", email, PASSWORD_HASH, "user", "active", username, 0, null, "email").run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function insertAnnouncement(db, overrides = {}) {
    const now = "2026-07-01T00:00:00.000Z";
    const defaults = {
        title: "Test Announcement",
        content: "Test content",
        status: "draft",
        notify_mode: "silent",
        targeting: null,
        starts_at: null,
        ends_at: null,
        created_by: null,
        updated_by: null
    };
    const values = { ...defaults, ...overrides };
    const result = await db.prepare(
        `INSERT INTO announcements (created_at, updated_at, title, content, status, notify_mode, targeting, starts_at, ends_at, created_by, updated_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(now, now, values.title, values.content, values.status, values.notify_mode, values.targeting, values.starts_at, values.ends_at, values.created_by, values.updated_by).run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function markRead(db, announcementId, userId) {
    const now = "2026-07-02T00:00:00.000Z";
    await db.prepare(
        `INSERT INTO announcement_reads (read_at, created_at, announcement_id, user_id)
         VALUES (?, ?, ?, ?)`
    ).bind(now, now, announcementId, userId).run();
}

async function createAdminToken(db, userId = 1) {
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion("admin@example.com", PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: userId, email: "admin@example.com", role: "admin", tokenVersion });
    return signed.token;
}

function env(db) {
    return { DB: db, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" };
}

test("GET /api/v1/admin/announcements returns 401 without auth", async () => {
    const db = createDatabase();
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements"), env(db));
    assert.equal(res.status, 401);
});

test("GET /api/v1/admin/announcements returns empty list", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.items.length, 0);
});

test("GET /api/v1/admin/announcements returns list", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertAnnouncement(db, { title: "A1" });
    await insertAnnouncement(db, { title: "A2" });
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    const body = await res.json();
    assert.equal(body.data.items.length, 2);
});

test("POST /api/v1/admin/announcements creates announcement", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ title: "Hello", content: "World", status: "active", notify_mode: "popup" })
    }), env(db));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.title, "Hello");
    assert.equal(body.data.content, "World");
    assert.equal(body.data.status, "active");
    assert.equal(body.data.notifyMode, "popup");
});

test("POST validates required title", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ title: "", content: "Test" })
    }), env(db));
    assert.equal(res.status, 400);
});

test("POST validates required content", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ title: "Test", content: "" })
    }), env(db));
    assert.equal(res.status, 400);
});

test("POST validates status enum", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ title: "Test", content: "Test", status: "invalid" })
    }), env(db));
    assert.equal(res.status, 400);
});

test("GET /api/v1/admin/announcements/:id returns by ID", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const id = await insertAnnouncement(db, { title: "Specific" });
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request(`https://edge.example/api/v1/admin/announcements/${id}`, {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.title, "Specific");
});

test("GET /api/v1/admin/announcements/:id returns 404", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements/99999", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(res.status, 404);
});

test("PUT /api/v1/admin/announcements/:id updates announcement", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const id = await insertAnnouncement(db, { title: "Old" });
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request(`https://edge.example/api/v1/admin/announcements/${id}`, {
        method: "PUT",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ title: "New Title", status: "active" })
    }), env(db));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.title, "New Title");
    assert.equal(body.data.status, "active");
});

test("DELETE /api/v1/admin/announcements/:id deletes announcement", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const id = await insertAnnouncement(db, { title: "Delete Me" });
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request(`https://edge.example/api/v1/admin/announcements/${id}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(res.status, 200);
    const check = await db.prepare("SELECT id FROM announcements WHERE id = ?").bind(id).first();
    assert.equal(check, null);
});

test("DELETE returns 404 for non-existent", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements/99999", {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(res.status, 404);
});

test("GET /api/v1/admin/announcements/:id/read-status returns readers", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const userId = await insertUser(db);
    const id = await insertAnnouncement(db, { title: "Read Status Test" });
    await markRead(db, id, userId);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request(`https://edge.example/api/v1/admin/announcements/${id}/read-status`, {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.items.length, 1);
    assert.equal(body.data.items[0].email, "user@example.com");
    assert.equal(body.data.read_count, 1);
});

test("GET /api/v1/admin/announcements/:id/read-status returns 404 for non-existent", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements/99999/read-status", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    assert.equal(res.status, 404);
});

test("GET /api/v1/admin/announcements supports pagination", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    for (let i = 0; i < 5; i++) await insertAnnouncement(db, { title: `A${i}` });
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements?page=2&page_size=2", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    const body = await res.json();
    assert.equal(body.data.items.length, 2);
    assert.equal(body.data.total, 5);
});

test("GET /api/v1/admin/announcements supports status filter", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertAnnouncement(db, { title: "Draft", status: "draft" });
    await insertAnnouncement(db, { title: "Active", status: "active" });
    const token = await createAdminToken(db, adminId);
    const res = await routeRequest(new Request("https://edge.example/api/v1/admin/announcements?status=active", {
        headers: { authorization: `Bearer ${token}` }
    }), env(db));
    const body = await res.json();
    assert.equal(body.data.items.length, 1);
    assert.equal(body.data.items[0].title, "Active");
});
