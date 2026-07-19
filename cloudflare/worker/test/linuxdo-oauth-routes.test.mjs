import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    routeStagedLinuxDoOAuth,
    STAGED_LINUXDO_OAUTH_PATHS
} from "../src/router/staged-linuxdo-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const FIXED_NOW = Date.parse("2026-07-16T02:00:00.000Z");

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function insertSetting(db, key, value) {
    await db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).bind(key, value, "2026-07-16T00:00:00.000Z").run();
}

async function configure(db) {
    await insertSetting(db, "linuxdo_connect_enabled", "true");
    await insertSetting(db, "linuxdo_connect_client_id", "client-id");
    await insertSetting(db, "linuxdo_connect_redirect_url", "https://api.example/api/v1/auth/oauth/linuxdo/callback");
    await insertSetting(db, "email_verify_enabled", "false");
    await insertSetting(db, "force_email_on_third_party_signup", "false");
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET: "linuxdo-route-test-secret-that-is-at-least-32-bytes",
        LINUXDO_CLIENT_SECRET: "client-secret",
        LINUXDO_AUTHORIZE_URL: "https://connect.example/oauth2/authorize",
        LINUXDO_TOKEN_URL: "https://connect.example/oauth2/token",
        LINUXDO_USERINFO_URL: "https://connect.example/api/user",
        LINUXDO_FRONTEND_REDIRECT_URL: "/auth/linuxdo/callback",
        LINUXDO_USE_PKCE: "true"
    };
}

function cookies(response) {
    return response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
}

test("LinuxDo start and callback create a browser-bound D1 pending choice without raw token storage", async () => {
    const db = createDatabase();
    await configure(db);
    const opaque = ["a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(48)];
    const dependencies = {
        clock: () => FIXED_NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: async (input) => String(input).includes("token")
            ? new Response(JSON.stringify({ access_token: "provider-access" }))
            : new Response(JSON.stringify({
                id: "member_42",
                email: "member@example.com",
                username: "member",
                name: "Member Name",
                avatar_url: "https://cdn.example/member.png"
            }))
    };

    const start = await routeStagedLinuxDoOAuth(new Request(
        `https://api.example${STAGED_LINUXDO_OAUTH_PATHS.start}?redirect=%2Fprofile&promo_code=PROMO`
    ), env(db), dependencies);
    assert.equal(start.status, 302);
    const providerUrl = new URL(start.headers.get("location"));
    assert.equal(providerUrl.searchParams.get("state"), "a".repeat(64));
    assert.equal(providerUrl.searchParams.get("code_challenge_method"), "S256");
    const startCookies = cookies(start);
    assert.match(startCookies, /linuxdo_oauth_state=/u);
    assert.match(startCookies, /oauth_pending_browser_session=/u);

    const callback = await routeStagedLinuxDoOAuth(new Request(
        `https://api.example${STAGED_LINUXDO_OAUTH_PATHS.callback}?code=provider-code&state=${"a".repeat(64)}`,
        { headers: { cookie: startCookies } }
    ), env(db), dependencies);
    assert.equal(callback.status, 302, await callback.clone().text());
    assert.equal(callback.headers.get("location"), "https://api.example/auth/linuxdo/callback");
    const callbackCookies = cookies(callback);
    assert.match(callbackCookies, /oauth_pending_session=d{48}/u);

    const pending = await db.prepare(`
        SELECT
            session_token AS sessionToken,
            provider_subject AS providerSubject,
            resolved_email AS resolvedEmail,
            browser_session_key AS browserSessionKey,
            local_flow_state AS localFlowState
        FROM pending_auth_sessions
    `).first();
    assert.equal(pending.sessionToken, createHash("sha256").update("d".repeat(48)).digest("hex"));
    assert.equal(pending.sessionToken.includes("d".repeat(48)), false);
    assert.equal(pending.providerSubject, "member_42");
    assert.equal(pending.resolvedEmail, "linuxdo-member_42@linuxdo-connect.invalid");
    assert.equal(pending.browserSessionKey, "b".repeat(64));
    const flow = JSON.parse(pending.localFlowState);
    assert.equal(flow.promo_code, "PROMO");
    assert.equal(flow.completion_response.step, "choose_account_action_required");
    assert.equal(flow.completion_response.suggested_display_name, "Member Name");

    const replay = await routeStagedLinuxDoOAuth(new Request(
        `https://api.example${STAGED_LINUXDO_OAUTH_PATHS.callback}?code=provider-code&state=${"a".repeat(64)}`,
        { headers: { cookie: startCookies } }
    ), env(db), dependencies);
    assert.equal(replay.status, 302);
    assert.match(new URL(replay.headers.get("location")).hash, /invalid_state/u);
});

test("LinuxDo callback targets the existing auth identity owner", async () => {
    const db = createDatabase();
    await configure(db);
    const inserted = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status, username, signup_source
        ) VALUES (?, ?, ?, ?, 'user', 'active', 'member', 'linuxdo')
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        "linuxdo-member_42@linuxdo-connect.invalid",
        "unused-password-hash"
    ).run();
    await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key,
            provider_subject, metadata, user_id
        ) VALUES (?, ?, 'linuxdo', 'linuxdo', 'member_42', '{}', ?)
    `).bind(
        "2026-07-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z",
        inserted.meta.last_row_id
    ).run();
    const opaque = ["1".repeat(64), "2".repeat(64), "3".repeat(64), "4".repeat(48)];
    const dependencies = {
        clock: () => FIXED_NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: async (input) => String(input).includes("token")
            ? new Response(JSON.stringify({ access_token: "provider-access" }))
            : new Response(JSON.stringify({ id: "member_42", username: "member" }))
    };
    const start = await routeStagedLinuxDoOAuth(new Request(
        `https://api.example${STAGED_LINUXDO_OAUTH_PATHS.start}`
    ), env(db), dependencies);
    const callback = await routeStagedLinuxDoOAuth(new Request(
        `https://api.example${STAGED_LINUXDO_OAUTH_PATHS.callback}?code=x&state=${"1".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.equal(callback.status, 302, await callback.clone().text());
    const pending = await db.prepare(`
        SELECT target_user_id AS targetUserId, local_flow_state AS localFlowState
        FROM pending_auth_sessions
    `).first();
    assert.equal(pending.targetUserId, inserted.meta.last_row_id);
    assert.equal(JSON.parse(pending.localFlowState).completion_response.step, undefined);
});
