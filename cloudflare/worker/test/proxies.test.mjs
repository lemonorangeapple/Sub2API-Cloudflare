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

const JWT_SECRET = "proxy-test-jwt-secret-that-is-at-least-32-bytes-long";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertAdmin(db, overrides = {}) {
    const values = {
        email: "admin@example.com",
        passwordHash: PASSWORD_HASH,
        role: "admin",
        status: "active",
        username: "admin",
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, totp_enabled, totp_secret_encrypted, signup_source, token_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        values.email,
        values.passwordHash,
        values.role,
        values.status,
        values.username,
        0,
        null,
        "email"
    ).run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function insertUser(db, overrides = {}) {
    const values = {
        email: "user@example.com",
        passwordHash: PASSWORD_HASH,
        role: "user",
        status: "active",
        username: "testuser",
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, totp_enabled, totp_secret_encrypted, signup_source, token_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        values.email,
        values.passwordHash,
        values.role,
        values.status,
        values.username,
        0,
        null,
        "email"
    ).run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function insertProxy(db, overrides = {}) {
    const values = {
        name: "Test Proxy",
        protocol: "http",
        host: "192.168.1.1",
        port: 8080,
        username: "",
        password: "",
        status: "active",
        ...overrides
    };
    const result = await db.prepare(`
        INSERT INTO proxies (
            created_at, updated_at, name, protocol, host, port,
            username, password, status, expires_at, fallback_mode,
            expiry_warn_days, backup_proxy_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        values.name,
        values.protocol,
        values.host,
        values.port,
        values.username ?? null,
        values.password ?? null,
        values.status,
        null,
        "none",
        7,
        null
    ).run();
    return Number(result.meta?.last_row_id ?? 0);
}

async function createAdminToken(db, userId = 1, email = "admin@example.com") {
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: userId, email, role: "admin", tokenVersion });
    return signed.token;
}

async function createUserToken(db, userId = 1, email = "user@example.com") {
    const signer = new Hs256JwtSigner(JWT_SECRET, 7 * 24 * 60 * 60);
    const tokenVersion = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
    const signed = await signer.sign({ id: userId, email, role: "user", tokenVersion });
    return signed.token;
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET,
        JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600",
        JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30"
    };
}

test("GET /api/v1/admin/proxies returns 401 without authorization", async () => {
    const db = createDatabase();
    const request = new Request("https://edge.example/api/v1/admin/proxies", { method: "GET" });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 401);
});

test("GET /api/v1/admin/proxies returns 403 for non-admin user", async () => {
    const db = createDatabase();
    const userId = await insertUser(db);
    const token = await createUserToken(db, userId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 403);
});

test("GET /api/v1/admin/proxies returns empty list", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.code, 0);
    assert.equal(body.data.items.length, 0);
    assert.equal(body.data.total, 0);
});

test("GET /api/v1/admin/proxies returns list of proxies", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProxy(db, { name: "Proxy 1", host: "10.0.0.1" });
    await insertProxy(db, { name: "Proxy 2", host: "10.0.0.2" });
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.items.length, 2);
    assert.equal(body.data.total, 2);
});

test("GET /api/v1/admin/proxies/all returns all proxies", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProxy(db, { name: "Proxy 1", host: "10.0.0.1" });
    await insertProxy(db, { name: "Proxy 2", host: "10.0.0.2" });
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies/all", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.length, 2);
});

test("GET /api/v1/admin/proxies/:id returns proxy by ID", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const proxyId = await insertProxy(db, { name: "Specific Proxy", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}`, {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "Specific Proxy");
    assert.equal(body.data.host, "10.0.0.1");
    assert.equal(body.data.protocol, "http");
    assert.equal(body.data.port, 8080);
});

test("GET /api/v1/admin/proxies/:id returns 404 for non-existent proxy", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies/99999", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 404);
});

test("POST /api/v1/admin/proxies creates a proxy", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            name: "My Proxy",
            protocol: "socks5",
            host: "proxy.example.com",
            port: 1080,
            username: "user",
            password: "pass"
        })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "My Proxy");
    assert.equal(body.data.protocol, "socks5");
    assert.equal(body.data.host, "proxy.example.com");
    assert.equal(body.data.port, 1080);
    assert.equal(body.data.username, "user");
    assert.equal(body.data.password, "pass");
    assert.equal(body.data.status, "active");
});

test("POST /api/v1/admin/proxies validates required name", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            protocol: "http",
            host: "proxy.example.com",
            port: 8080
        })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("POST /api/v1/admin/proxies validates protocol", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            name: "Bad Proxy",
            protocol: "invalid",
            host: "proxy.example.com",
            port: 8080
        })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("POST /api/v1/admin/proxies validates port range", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            name: "Bad Port",
            protocol: "http",
            host: "proxy.example.com",
            port: 70000
        })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("POST /api/v1/admin/proxies validates backup proxy exists", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            name: "Backup Test",
            protocol: "http",
            host: "proxy.example.com",
            port: 8080,
            fallback_mode: "proxy",
            backup_proxy_id: 99999
        })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("PUT /api/v1/admin/proxies/:id updates proxy name", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const proxyId = await insertProxy(db, { name: "Old Name", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ name: "New Name" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.name, "New Name");
});

test("PUT /api/v1/admin/proxies/:id updates proxy status", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const proxyId = await insertProxy(db, { name: "Status Test", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ status: "inactive" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.status, "inactive");
});

test("PUT /api/v1/admin/proxies/:id rejects invalid status", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const proxyId = await insertProxy(db, { name: "Invalid Status", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ status: "invalid_status" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("PUT /api/v1/admin/proxies/:id rejects self-referencing backup", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const proxyId = await insertProxy(db, { name: "Self Reference", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ backup_proxy_id: proxyId })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 400);
});

test("PUT /api/v1/admin/proxies/:id with backup proxy", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const backupId = await insertProxy(db, { name: "Backup", host: "10.0.0.2" });
    const proxyId = await insertProxy(db, { name: "Main", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}`, {
        method: "PUT",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ backup_proxy_id: backupId, fallback_mode: "proxy" })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.backupProxyId, backupId);
    assert.equal(body.data.fallbackMode, "proxy");
});

test("DELETE /api/v1/admin/proxies/:id soft-deletes proxy", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const proxyId = await insertProxy(db, { name: "Delete Me", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);

    const list = await db.prepare("SELECT deleted_at FROM proxies WHERE id = ?").bind(proxyId).first();
    assert.ok(list);
    assert.notEqual(list.deleted_at, null);
});

test("DELETE /api/v1/admin/proxies/:id returns 404 for non-existent", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies/99999", {
        method: "DELETE",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 404);
});

test("POST /api/v1/admin/proxies/batch-delete deletes multiple proxies", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const id1 = await insertProxy(db, { name: "Batch 1", host: "10.0.0.1" });
    const id2 = await insertProxy(db, { name: "Batch 2", host: "10.0.0.2" });
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies/batch-delete", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({ ids: [id1, id2] })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.deletedIds.length, 2);

    const remaining = await db.prepare("SELECT COUNT(*) as count FROM proxies WHERE deleted_at IS NULL").first();
    assert.equal(remaining.count, 0);
});

test("POST /api/v1/admin/proxies/batch creates multiple proxies", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies/batch", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            proxies: [
                { protocol: "http", host: "10.0.0.1", port: 8080 },
                { protocol: "socks5", host: "10.0.0.2", port: 1080, username: "user", password: "pass" }
            ]
        })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.created, 2);
    assert.equal(body.data.skipped, 0);
});

test("POST /api/v1/admin/proxies/batch skips duplicates", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProxy(db, { name: "Existing", protocol: "http", host: "10.0.0.1", port: 8080 });
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies/batch", {
        method: "POST",
        headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
        },
        body: JSON.stringify({
            proxies: [
                { protocol: "http", host: "10.0.0.1", port: 8080 },
                { protocol: "http", host: "10.0.0.3", port: 8080 }
            ]
        })
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.created, 1);
    assert.equal(body.data.skipped, 1);
});

test("GET /api/v1/admin/proxies supports search filter", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProxy(db, { name: "Production", host: "10.0.0.1" });
    await insertProxy(db, { name: "Development", host: "10.0.0.2" });
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies?search=prod", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.items.length, 1);
    assert.equal(body.data.items[0].name, "Production");
});

test("GET /api/v1/admin/proxies supports protocol filter", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    await insertProxy(db, { name: "HTTP", protocol: "http", host: "10.0.0.1" });
    await insertProxy(db, { name: "SOCKS5", protocol: "socks5", host: "10.0.0.2" });
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies?protocol=socks5", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.items.length, 1);
    assert.equal(body.data.items[0].name, "SOCKS5");
});

test("GET /api/v1/admin/proxies supports pagination", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    for (let i = 0; i < 5; i++) {
        await insertProxy(db, { name: `Proxy ${i}`, host: `10.0.0.${i}` });
    }
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies?page=2&page_size=2", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.items.length, 2);
    assert.equal(body.data.total, 5);
    assert.equal(body.data.page, 2);
});

test("unmatched proxy routes return a local 404", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const token = await createAdminToken(db, adminId);

    const request = new Request("https://edge.example/api/v1/admin/proxies/data", {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 404);
    const body = await response.json();
    assert.equal(body.error.code, "route_not_found");
});

test("unmatched proxy action routes return a local 404", async () => {
    const db = createDatabase();
    const adminId = await insertAdmin(db);
    const proxyId = await insertProxy(db, { name: "Stats Test", host: "10.0.0.1" });
    const token = await createAdminToken(db, adminId);

    const request = new Request(`https://edge.example/api/v1/admin/proxies/${proxyId}/stats`, {
        method: "GET",
        headers: { authorization: `Bearer ${token}` }
    });
    const response = await routeRequest(request, env(db));
    assert.equal(response.status, 404);
    const body = await response.json();
    assert.equal(body.error.code, "route_not_found");
});
