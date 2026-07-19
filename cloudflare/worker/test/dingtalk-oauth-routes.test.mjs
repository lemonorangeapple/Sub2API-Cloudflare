import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    routeStagedDingTalkOAuth,
    STAGED_DINGTALK_OAUTH_PATHS
} from "../src/router/staged-dingtalk-oauth.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0002_business_supplemental.sql",
    "0004_runtime_state.sql",
    "0005_auth_sessions.sql",
    "0006_user_email_integrity.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const NOW = Date.parse("2026-07-16T22:00:00.000Z");

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function setting(db, key, value) {
    await db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).bind(key, value, new Date(NOW).toISOString()).run();
}

async function configure(db, overrides = {}) {
    const values = {
        dingtalk_connect_enabled: "true",
        dingtalk_connect_client_id: "ding-client",
        dingtalk_connect_redirect_url: "https://api.example/api/v1/auth/oauth/dingtalk/callback",
        dingtalk_connect_corp_restriction_policy: "none",
        dingtalk_connect_bypass_registration: "false",
        registration_enabled: "false",
        invitation_code_enabled: "false",
        email_verify_enabled: "false",
        force_email_on_third_party_signup: "false",
        backend_mode_enabled: "false",
        promo_code_enabled: "false",
        default_balance: "0",
        default_concurrency: "5",
        default_user_rpm_limit: "0",
        default_subscriptions: "[]",
        default_platform_quotas: "{}",
        ...overrides
    };
    for (const [key, value] of Object.entries(values)) await setting(db, key, value);
}

function env(db, overrides = {}) {
    return {
        DB: db,
        JWT_SECRET: "dingtalk-route-secret-that-is-at-least-32-bytes",
        DINGTALK_CLIENT_SECRET: "ding-secret",
        DINGTALK_AUTHORIZE_URL: "https://ding.example/authorize",
        DINGTALK_TOKEN_URL: "https://ding.example/user-token",
        DINGTALK_USERINFO_URL: "https://ding.example/me",
        DINGTALK_APP_TOKEN_URL: "https://ding.example/app-token",
        DINGTALK_USER_BY_UNIONID_URL: "https://ding.example/by-union",
        DINGTALK_STAFF_INFO_URL: "https://ding.example/staff",
        DINGTALK_FRONTEND_REDIRECT_URL: "/auth/dingtalk/callback",
        ...overrides
    };
}

function cookies(response) {
    return response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
}

function upstream(identity = {}) {
    return async (input, init = {}) => {
        const url = String(input);
        if (url.endsWith("/user-token")) return json({ accessToken: "user-access", corpId: "ding-corp" });
        if (url.endsWith("/me")) return json({ unionId: identity.subject ?? "union_member", nick: "Member Nick" });
        if (url.endsWith("/app-token")) return json({ accessToken: "app-access" });
        if (url.includes("/by-union")) return json({ errcode: 0, result: { userid: "staff-1" } });
        if (url.includes("/department")) {
            const departmentId = JSON.parse(init.body).dept_id;
            return departmentId === 42
                ? json({ errcode: 0, result: { dept_id: 42, name: "Engineering", parent_id: 1 } })
                : json({ errcode: 0, result: { dept_id: 1, name: "Example Corp", parent_id: 0 } });
        }
        return json({
            errcode: 0,
            result: {
                userid: "staff-1",
                name: "Enterprise Member",
                org_email: identity.email ?? "member@corp.example",
                dept_id_list: [42]
            }
        });
    };
}

test("DingTalk callback consumes browser-bound D1 state and blocks signup with bind-login", async () => {
    const db = createDatabase();
    await configure(db);
    const opaque = ["a".repeat(64), "b".repeat(64), "c".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: upstream()
    };
    const start = await routeStagedDingTalkOAuth(new Request(
        `https://api.example${STAGED_DINGTALK_OAUTH_PATHS.start}?redirect=%2Fprofile&promo_code=PROMO`
    ), env(db), dependencies);
    assert.equal(start.status, 302);
    assert.equal(new URL(start.headers.get("location")).searchParams.get("state"), "a".repeat(64));

    const callback = await routeStagedDingTalkOAuth(new Request(
        `https://api.example${STAGED_DINGTALK_OAUTH_PATHS.callback}?code=provider-code&state=${"a".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "https://api.example/auth/dingtalk/callback");
    const pending = await db.prepare(`
        SELECT provider_type AS providerType, provider_key AS providerKey,
            provider_subject AS providerSubject, resolved_email AS resolvedEmail,
            local_flow_state AS localFlowState
        FROM pending_auth_sessions
    `).first();
    assert.deepEqual({
        providerType: pending.providerType,
        providerKey: pending.providerKey,
        providerSubject: pending.providerSubject,
        resolvedEmail: pending.resolvedEmail
    }, {
        providerType: "dingtalk",
        providerKey: "dingtalk",
        providerSubject: "union_member",
        resolvedEmail: "member@corp.example"
    });
    const flow = JSON.parse(pending.localFlowState);
    assert.equal(flow.promo_code, "PROMO");
    assert.equal(flow.completion_response.step, "bind_login_required");
    assert.equal(flow.registration_bypass_allowed, undefined);

    const replay = await routeStagedDingTalkOAuth(new Request(
        `https://api.example${STAGED_DINGTALK_OAUTH_PATHS.callback}?code=x&state=${"a".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.match(new URL(replay.headers.get("location")).hash, /invalid_state/u);
});

test("DingTalk internal-only bypass creates and binds a synthetic account atomically", async () => {
    const db = createDatabase();
    await configure(db, {
        dingtalk_connect_corp_restriction_policy: "internal_only",
        dingtalk_connect_bypass_registration: "true",
        dingtalk_connect_sync_corp_email: "true",
        dingtalk_connect_sync_display_name: "true",
        dingtalk_connect_sync_dept: "true"
    });
    for (const [key, name] of [
        ["dingtalk_name", "DingTalk Name"],
        ["dingtalk_email", "DingTalk Email"],
        ["dingtalk_department", "DingTalk Department"]
    ]) {
        await db.prepare(`
            INSERT INTO user_attribute_definitions (
                created_at, updated_at, key, name, type, options, validation
            ) VALUES (?, ?, ?, ?, 'text', '[]', '{}')
        `).bind(new Date(NOW).toISOString(), new Date(NOW).toISOString(), key, name).run();
    }
    const opaque = ["d".repeat(64), "e".repeat(64), "f".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        nonceFactory: () => "dingtalk-route-bypass-nonce",
        fetchImplementation: upstream({ subject: "internal_member" })
    };
    const start = await routeStagedDingTalkOAuth(
        new Request(`https://api.example${STAGED_DINGTALK_OAUTH_PATHS.start}`),
        env(db, { DINGTALK_REQUIRE_EMAIL: "false" }),
        dependencies
    );
    const callback = await routeStagedDingTalkOAuth(new Request(
        `https://api.example${STAGED_DINGTALK_OAUTH_PATHS.callback}?code=x&state=${"d".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db, { DINGTALK_REQUIRE_EMAIL: "false" }), dependencies);
    assert.equal(callback.status, 302);
    const fragment = new URLSearchParams(new URL(callback.headers.get("location")).hash.slice(1));
    assert.ok(fragment.get("access_token"));
    assert.ok(fragment.get("refresh_token"));
    const user = await db.prepare(`SELECT email, username, signup_source AS source FROM users`).first();
    assert.deepEqual({ ...user }, {
        email: "dingtalk-internal_member@dingtalk-connect.invalid",
        username: "Member Nick",
        source: "dingtalk"
    });
    const identity = await db.prepare(`
        SELECT provider_type AS providerType, provider_key AS providerKey,
            provider_subject AS providerSubject FROM auth_identities
    `).first();
    assert.deepEqual({ ...identity }, {
        providerType: "dingtalk",
        providerKey: "dingtalk",
        providerSubject: "internal_member"
    });
    const attributes = await db.prepare(`
        SELECT definition.key, value.value
        FROM user_attribute_values AS value
        JOIN user_attribute_definitions AS definition ON definition.id = value.attribute_id
        ORDER BY definition.key
    `).all();
    assert.deepEqual(attributes.results.map((row) => ({ ...row })), [
        { key: "dingtalk_department", value: "Engineering" },
        { key: "dingtalk_email", value: "member@corp.example" },
        { key: "dingtalk_name", value: "Enterprise Member" }
    ]);
    assert.ok((await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first()).consumedAt);
});

test("DingTalk bind-start authenticates the handoff token and stores its target in D1", async () => {
    const db = createDatabase();
    await configure(db);
    const created = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, signup_source, token_version
        ) VALUES (?, ?, 'bind@example.com', 'bind-password-hash', 'user', 'active', '', 'email', 0)
    `).bind(new Date(NOW).toISOString(), new Date(NOW).toISOString()).run();
    const tokenVersion = await legacyTokenVersion("bind@example.com", "bind-password-hash", 0n);
    const access = await new Hs256JwtSigner(env(db).JWT_SECRET, 3600, () => NOW).sign({
        id: created.meta.last_row_id,
        email: "bind@example.com",
        role: "user",
        tokenVersion
    });
    const opaque = ["g".repeat(64), "h".repeat(64)];
    const response = await routeStagedDingTalkOAuth(new Request(
        `https://api.example${STAGED_DINGTALK_OAUTH_PATHS.bindStart}`,
        { headers: { cookie: `oauth_bind_access_token=${access.token}` } }
    ), env(db), { clock: () => NOW, opaqueTokenFactory: () => opaque.shift() });
    assert.equal(response.status, 302);
    const stored = await db.prepare(`SELECT value_json AS value FROM runtime_expiring_values`).first();
    const state = JSON.parse(stored.value);
    assert.equal(state.intent, "bind_current_user");
    assert.equal(state.bindUserId, created.meta.last_row_id);
});

function json(value) {
    return new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
}
