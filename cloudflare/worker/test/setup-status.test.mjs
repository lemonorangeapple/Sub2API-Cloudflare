import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const coreMigration = await readFile(
    new URL("../../d1/migrations/0001_ent_core.sql", import.meta.url),
    "utf8"
);

function createDatabase() {
    const db = new SQLiteD1Database();
    db.exec(coreMigration);
    return db;
}

async function insertUser(db, { email, role }) {
    await db.prepare(`
        INSERT INTO users (
            created_at,
            updated_at,
            email,
            password_hash,
            role,
            status
        ) VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
        "2026-07-15T00:00:00Z",
        "2026-07-15T00:00:00Z",
        email,
        "test-password-hash",
        role,
        "active"
    ).run();
}

test("GET setup status reports welcome when D1 has no administrator", async () => {
    const db = createDatabase();
    let backendCalled = false;

    const response = await routeRequest(
        new Request("https://edge.example/setup/status?cache_bust=1"),
        {
            DB: db,
            BACKEND: {
                async fetch() {
                    backendCalled = true;
                    return new Response("unexpected");
                }
            }
        }
    );

    assert.equal(response.status, 200);
    assert.equal(backendCalled, false);
    assert.deepEqual(await response.json(), {
        code: 0,
        message: "success",
        data: {
            needs_setup: true,
            step: "welcome"
        }
    });
    db.close();
});

test("GET setup status reports completed when any administrator exists", async () => {
    const db = createDatabase();
    await insertUser(db, { email: "user@example.com", role: "user" });

    const beforeAdmin = await routeRequest(
        new Request("https://edge.example/setup/status"),
        { DB: db }
    );
    assert.equal((await beforeAdmin.json()).data.needs_setup, true);

    await insertUser(db, { email: "admin@example.com", role: "admin" });
    const afterAdmin = await routeRequest(
        new Request("https://edge.example/setup/status"),
        { DB: db }
    );

    assert.deepEqual(await afterAdmin.json(), {
        code: 0,
        message: "success",
        data: {
            needs_setup: false,
            step: "completed"
        }
    });
    db.close();
});

test("setup status never falls back to BACKEND for method or D1 configuration errors", async () => {
    let backendCalls = 0;
    const env = {
        BACKEND: {
            async fetch() {
                backendCalls += 1;
                return new Response("unexpected");
            }
        }
    };

    const methodResponse = await routeRequest(
        new Request("https://edge.example/setup/status", { method: "POST" }),
        env
    );
    assert.equal(methodResponse.status, 405);
    assert.equal(methodResponse.headers.get("allow"), "GET");
    assert.equal((await methodResponse.json()).error.code, "method_not_allowed");

    const missingDatabaseResponse = await routeRequest(
        new Request("https://edge.example/setup/status"),
        env
    );
    assert.equal(missingDatabaseResponse.status, 503);
    assert.equal((await missingDatabaseResponse.json()).error.code, "database_not_configured");
    assert.equal(backendCalls, 0);
});
