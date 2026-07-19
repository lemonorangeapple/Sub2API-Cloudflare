import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

async function fixture() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    const now = "2026-07-18T00:00:00.000Z";
    const user = await db.prepare(`
        INSERT INTO users (created_at, updated_at, email, password_hash, role, status, username, totp_enabled, signup_source, token_version)
        VALUES (?, ?, ?, ?, 'user', 'active', 'gateway-user', 0, 'email', 0)
    `).bind(now, now, "gateway@example.com", "hash").run();
    const userId = Number(user.meta.last_row_id);
    await db.prepare(`
        INSERT INTO api_keys (created_at, updated_at, key, name, status, user_id, quota, quota_used, rate_limit_5h, rate_limit_1d, rate_limit_7d, usage_5h, usage_1d, usage_7d)
        VALUES (?, ?, 'sk-gateway', 'Gateway', 'active', ?, 0, 0, 0, 0, 0, 0, 0, 0)
    `).bind(now, now, userId).run();
    await db.prepare(`
        INSERT INTO accounts (created_at, updated_at, name, notes, platform, type, credentials, extra, concurrency, priority, rate_multiplier, status, auto_pause_on_expired, schedulable, quota_dimension)
        VALUES (?, ?, 'openai-main', '', 'openai', 'apikey', ?, '{}', 3, 50, 1, 'active', 1, 1, 'global')
    `).bind(now, now, JSON.stringify({ api_key: "upstream-secret", base_url: "https://upstream.example" })).run();
    return db;
}

test("gateway requires an API key", async () => {
    const db = await fixture();
    const response = await routeRequest(new Request("https://edge.example/v1/chat/completions", { method: "POST", body: "{}" }), { DB: db });
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error.code, "invalid_api_key");
});

test("gateway selects an account and forwards credentials and body", async (t) => {
    const db = await fixture();
    const originalFetch = globalThis.fetch;
    let captured;
    globalThis.fetch = async (url, init) => {
        captured = { url: String(url), init, body: await new Response(init.body).text() };
        return new Response(JSON.stringify({ id: "chatcmpl-1" }), {
            status: 200,
            headers: { "content-type": "application/json", "x-upstream": "ok" }
        });
    };
    t.after(() => { globalThis.fetch = originalFetch; });

    const response = await routeRequest(new Request("https://edge.example/v1/chat/completions?trace=1", {
        method: "POST",
        headers: { authorization: "Bearer sk-gateway", "content-type": "application/json" },
        body: JSON.stringify({ model: "gpt-4.1", messages: [] })
    }), { DB: db });

    assert.equal(response.status, 200);
    assert.equal(captured.url, "https://upstream.example/v1/chat/completions?trace=1");
    assert.equal(captured.init.headers.get("authorization"), "Bearer upstream-secret");
    assert.deepEqual(JSON.parse(captured.body), { model: "gpt-4.1", messages: [] });
    assert.equal(response.headers.get("x-upstream"), "ok");
    assert.equal(response.headers.get("x-sub2api-account-id"), "1");
    const key = await db.prepare("SELECT last_used_at FROM api_keys WHERE key = 'sk-gateway'").first();
    assert.equal(typeof key.last_used_at, "string");
});
