import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeStagedPendingOAuth, STAGED_PENDING_OAUTH_PATHS } from "../src/router/staged-pending-oauth.ts";
import {
    routeStagedWeChatOAuth,
    STAGED_WECHAT_OAUTH_PATHS
} from "../src/router/staged-wechat-oauth.ts";
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
const NOW = Date.parse("2026-07-16T18:00:00.000Z");

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
        wechat_connect_enabled: "true",
        wechat_connect_open_enabled: "true",
        wechat_connect_mp_enabled: "false",
        wechat_connect_open_app_id: "open-app",
        wechat_connect_mp_app_id: "mp-app",
        wechat_connect_redirect_url: "https://api.example/api/v1/auth/oauth/wechat/callback",
        registration_enabled: "true",
        email_verify_enabled: "false",
        force_email_on_third_party_signup: "false",
        invitation_code_enabled: "false",
        ...overrides
    };
    for (const [key, value] of Object.entries(values)) await setting(db, key, value);
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET: "wechat-route-secret-that-is-at-least-32-bytes",
        WECHAT_CONNECT_OPEN_APP_SECRET: "open-secret",
        WECHAT_CONNECT_MP_APP_SECRET: "mp-secret",
        WECHAT_CONNECT_OPEN_AUTHORIZE_URL: "https://wechat.example/open-authorize",
        WECHAT_CONNECT_MP_AUTHORIZE_URL: "https://wechat.example/mp-authorize",
        WECHAT_CONNECT_TOKEN_URL: "https://wechat.example/token",
        WECHAT_CONNECT_USERINFO_URL: "https://wechat.example/userinfo",
        WECHAT_CONNECT_FRONTEND_REDIRECT_URL: "/auth/wechat/callback"
    };
}

function cookies(response) {
    return response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
}

function providerFetch({ openId = "openid-1", unionId = "unionid-1" } = {}) {
    return async (input) => String(input).includes("/token")
        ? new Response(JSON.stringify({ access_token: "provider-access", openid: openId, unionid: unionId }))
        : new Response(JSON.stringify({
            openid: openId,
            unionid: unionId,
            nickname: "微信用户",
            headimgurl: "https://cdn.example/wechat.png"
        }));
}

test("WeChat open callback creates and atomically completes a channel-backed D1 account", async () => {
    const db = createDatabase();
    await configure(db);
    const opaque = ["a".repeat(64), "b".repeat(64), "c".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        nonceFactory: () => "wechat-account-finalization",
        fetchImplementation: providerFetch()
    };
    const start = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.start}?mode=open&redirect=%2Fprofile&promo_code=PROMO`
    ), env(db), dependencies);
    assert.equal(start.status, 302);
    const authorize = new URL(start.headers.get("location"));
    assert.equal(authorize.searchParams.get("appid"), "open-app");
    assert.equal(authorize.searchParams.get("scope"), "snsapi_login");
    assert.equal(authorize.hash, "#wechat_redirect");

    const callback = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.callback}?code=provider-code&state=${"a".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "https://api.example/auth/wechat/callback");
    const pending = await db.prepare(`
        SELECT provider_type AS providerType, provider_key AS providerKey,
            provider_subject AS providerSubject, upstream_identity_claims AS claims,
            local_flow_state AS flow
        FROM pending_auth_sessions
    `).first();
    assert.deepEqual([pending.providerType, pending.providerKey, pending.providerSubject],
        ["wechat", "wechat-main", "unionid-1"]);
    assert.equal(JSON.parse(pending.claims).channel_subject, "openid-1");
    assert.equal(JSON.parse(pending.flow).completion_response.step, "choose_account_action_required");

    const completed = await routeStagedPendingOAuth(new Request(
        `https://api.example${STAGED_PENDING_OAUTH_PATHS.wechatCompleteRegistration}`,
        {
            method: "POST",
            headers: { "content-type": "application/json", cookie: cookies(callback) },
            body: JSON.stringify({ adopt_display_name: true, adopt_avatar: true })
        }
    ), env(db), dependencies);
    assert.equal(completed.status, 200);
    const body = await completed.json();
    assert.ok(body.data.access_token);
    const user = await db.prepare(`SELECT email, username, signup_source AS signupSource FROM users`).first();
    assert.deepEqual({ ...user }, {
        email: "wechat-unionid-1@wechat-connect.invalid",
        username: "微信用户",
        signupSource: "wechat"
    });
    const channel = await db.prepare(`
        SELECT provider_key AS providerKey, channel, channel_app_id AS appId,
            channel_subject AS subject
        FROM auth_identity_channels
    `).first();
    assert.deepEqual({ ...channel }, {
        providerKey: "wechat-main", channel: "open", appId: "open-app", subject: "openid-1"
    });
});

test("WeChat MP callback requires unionid when Open and MP channels are both enabled", async () => {
    const db = createDatabase();
    await configure(db, { wechat_connect_mp_enabled: "true" });
    const opaque = ["d".repeat(64), "e".repeat(64), "f".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: providerFetch({ openId: "mp-openid", unionId: "" })
    };
    const start = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.start}?mode=mp`,
        { headers: { "user-agent": "MicroMessenger" } }
    ), env(db), dependencies);
    assert.equal(new URL(start.headers.get("location")).searchParams.get("scope"), "snsapi_userinfo");
    const callback = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.callback}?code=x&state=${"d".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.match(new URL(callback.headers.get("location")).hash, /wechat_missing_unionid/u);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM pending_auth_sessions`).first()).count, 0);
});

test("WeChat callback recognizes a legacy channel owner and upgrades it through pending exchange", async () => {
    const db = createDatabase();
    await configure(db);
    const now = new Date(NOW).toISOString();
    const inserted = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, signup_source, token_version
        ) VALUES (?, ?, 'legacy@example.com', 'legacy-hash', 'user', 'active', 'Legacy', 'wechat', 0)
    `).bind(now, now).run();
    const userId = inserted.meta.last_row_id;
    const identity = await db.prepare(`
        INSERT INTO auth_identities (
            created_at, updated_at, provider_type, provider_key, provider_subject,
            verified_at, issuer, metadata, user_id
        ) VALUES (?, ?, 'wechat', 'wechat', 'legacy-subject', ?, NULL, '{}', ?)
    `).bind(now, now, now, userId).run();
    await db.prepare(`
        INSERT INTO auth_identity_channels (
            created_at, updated_at, provider_type, provider_key, channel,
            channel_app_id, channel_subject, metadata, identity_id
        ) VALUES (?, ?, 'wechat', 'wechat', 'open', 'open-app', 'same-openid', '{}', ?)
    `).bind(now, now, identity.meta.last_row_id).run();
    const opaque = ["g".repeat(64), "h".repeat(64), "i".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        nonceFactory: () => "legacy-upgrade-finalization",
        fetchImplementation: providerFetch({ openId: "same-openid", unionId: "new-unionid" })
    };
    const start = await routeStagedWeChatOAuth(
        new Request(`https://api.example${STAGED_WECHAT_OAUTH_PATHS.start}?mode=open`),
        env(db), dependencies
    );
    const callback = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.callback}?code=x&state=${"g".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.equal((await db.prepare(`SELECT target_user_id AS targetUserId FROM pending_auth_sessions`).first())
        .targetUserId, userId);

    const exchanged = await routeStagedPendingOAuth(new Request(
        `https://api.example${STAGED_PENDING_OAUTH_PATHS.exchange}`,
        {
            method: "POST",
            headers: { "content-type": "application/json", cookie: cookies(callback) },
            body: JSON.stringify({ adopt_display_name: false, adopt_avatar: false })
        }
    ), env(db), dependencies);
    assert.equal(exchanged.status, 200);
    assert.ok((await exchanged.json()).data.access_token);
    const upgraded = await db.prepare(`
        SELECT user_id AS userId FROM auth_identities
        WHERE provider_key = 'wechat-main' AND provider_subject = 'new-unionid'
    `).first();
    assert.equal(upgraded.userId, userId);
});

test("WeChat bind-start authenticates the handoff token and stores its D1 target", async () => {
    const db = createDatabase();
    await configure(db);
    const now = new Date(NOW).toISOString();
    const inserted = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, signup_source, token_version
        ) VALUES (?, ?, 'bind@example.com', 'bind-hash', 'user', 'active', '', 'email', 0)
    `).bind(now, now).run();
    const tokenVersion = await legacyTokenVersion("bind@example.com", "bind-hash", 0n);
    const access = await new Hs256JwtSigner(env(db).JWT_SECRET, 3600, () => NOW).sign({
        id: inserted.meta.last_row_id,
        email: "bind@example.com",
        role: "user",
        tokenVersion
    });
    const opaque = ["j".repeat(64), "k".repeat(64)];
    const response = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.bindStart}?mode=open&redirect=%2Fprofile`,
        { headers: { cookie: `oauth_bind_access_token=${access.token}` } }
    ), env(db), { clock: () => NOW, opaqueTokenFactory: () => opaque.shift() });
    assert.equal(response.status, 302);
    const stored = JSON.parse((await db.prepare(`SELECT value_json AS value FROM runtime_expiring_values`).first()).value);
    assert.equal(stored.intent, "bind_current_user");
    assert.equal(stored.bindUserId, inserted.meta.last_row_id);
    assert.ok(response.headers.getSetCookie().some((value) => value.startsWith("oauth_bind_access_token=;")));
});

test("WeChat payment OAuth stores context in D1 and returns a signed resume token", async () => {
    const db = createDatabase();
    await configure(db, { wechat_connect_mp_enabled: "true" });
    const paymentEnv = {
        ...env(db),
        PAYMENT_RESUME_SIGNING_KEY: "payment-resume-route-key"
    };
    const opaque = ["m".repeat(64), "n".repeat(64)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: async () => new Response(JSON.stringify({
            access_token: "payment-access",
            openid: "payment-openid",
            scope: "snsapi_base"
        }))
    };
    const start = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.paymentStart}`
        + "?payment_type=wxpay_direct&amount=12.5&order_type=subscription&plan_id=7"
        + "&scope=snsapi_base&redirect=%2Fpayment%3Ftab%3Dplans"
    ), paymentEnv, dependencies);
    assert.equal(start.status, 302);
    const authorize = new URL(start.headers.get("location"));
    assert.equal(authorize.searchParams.get("redirect_uri"),
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.paymentCallback}`);
    assert.equal(authorize.searchParams.get("scope"), "snsapi_base");
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM runtime_expiring_values`).first()).count, 1);

    const callback = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.paymentCallback}?code=pay-code&state=${"m".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), paymentEnv, dependencies);
    assert.equal(callback.status, 302);
    const redirected = new URL(callback.headers.get("location"));
    assert.equal(redirected.pathname, "/auth/wechat/payment/callback");
    const fragment = new URLSearchParams(redirected.hash.slice(1));
    assert.equal(fragment.get("redirect"), "/purchase?tab=plans");
    const token = fragment.get("wechat_resume_token");
    assert.ok(token);
    const claims = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    assert.deepEqual({
        openid: claims.openid,
        pt: claims.pt,
        amt: claims.amt,
        ot: claims.ot,
        pid: claims.pid,
        rd: claims.rd,
        scp: claims.scp,
        ttl: claims.exp - claims.iat
    }, {
        openid: "payment-openid",
        pt: "wxpay",
        amt: "12.5",
        ot: "subscription",
        pid: 7,
        rd: "/purchase?tab=plans",
        scp: "snsapi_base",
        ttl: 900
    });
    assert.ok(callback.headers.getSetCookie().some((value) => value.startsWith("wechat_payment_oauth_state=;")));

    const replay = await routeStagedWeChatOAuth(new Request(
        `https://api.example${STAGED_WECHAT_OAUTH_PATHS.paymentCallback}?code=x&state=${"m".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), paymentEnv, dependencies);
    assert.match(new URL(replay.headers.get("location")).hash, /invalid_state/u);
});
