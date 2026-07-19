import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeStagedEmailOAuth, STAGED_EMAIL_OAUTH_PATHS } from "../src/router/staged-email-oauth.ts";
import { routeStagedPendingOAuth, STAGED_PENDING_OAUTH_PATHS } from "../src/router/staged-pending-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql", "0002_business_supplemental.sql", "0004_runtime_state.sql",
    "0005_auth_sessions.sql", "0006_user_email_integrity.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const NOW = Date.parse("2026-07-16T15:00:00.000Z");
const NOW_ISO = new Date(NOW).toISOString();

function database() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function setting(db, key, value) {
    await db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).bind(key, value, NOW_ISO).run();
}

async function configure(db, provider) {
    for (const [key, value] of Object.entries({
        [`${provider}_oauth_enabled`]: "true",
        [`${provider}_oauth_client_id`]: `${provider}-client`,
        [`${provider}_oauth_redirect_url`]: `https://api.example/api/v1/auth/oauth/${provider}/callback`,
        [`${provider}_oauth_frontend_redirect_url`]: "/auth/oauth/callback",
        invitation_code_enabled: "false",
        backend_mode_enabled: "false",
        registration_enabled: "true"
    })) await setting(db, key, value);
}

function env(db, provider) {
    const upper = provider.toUpperCase();
    return {
        DB: db,
        JWT_SECRET: "email-oauth-route-secret-that-is-at-least-32-bytes",
        [`${upper}_OAUTH_CLIENT_SECRET`]: `${provider}-secret`,
        [`${upper}_OAUTH_AUTHORIZE_URL`]: `https://${provider}.example/authorize`,
        [`${upper}_OAUTH_TOKEN_URL`]: `https://${provider}.example/token`,
        [`${upper}_OAUTH_USERINFO_URL`]: `https://${provider}.example/user`,
        ...(provider === "github" ? { GITHUB_OAUTH_EMAILS_URL: "https://github.example/emails" } : {})
    };
}

function cookieHeader(response) {
    return response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
}

function providerFetch(provider, email = `${provider}@example.com`) {
    return async (input) => {
        const url = String(input);
        if (url.endsWith("/token")) return new Response(JSON.stringify({ access_token: `${provider}-access` }));
        if (url.endsWith("/emails")) return new Response(JSON.stringify([
            { email, verified: true, primary: true }
        ]));
        return new Response(JSON.stringify(provider === "github" ? {
            id: 42, login: "octocat", name: "Octo Cat", avatar_url: "https://cdn.example/octo.png"
        } : {
            sub: "google-sub", email, email_verified: true, given_name: "Google", name: "Google Member",
            picture: "https://cdn.example/google.png"
        }));
    };
}

test("GitHub and Google callback create provider-bound password-registration pending sessions", async () => {
    for (const provider of ["github", "google"]) {
        const db = database();
        await configure(db, provider);
        const opaque = ["a".repeat(64), "b".repeat(64), "c".repeat(48)];
        const dependencies = {
            clock: () => NOW,
            opaqueTokenFactory: () => opaque.shift(),
            fetchImplementation: providerFetch(provider)
        };
        const paths = provider === "github"
            ? { start: STAGED_EMAIL_OAUTH_PATHS.githubStart, callback: STAGED_EMAIL_OAUTH_PATHS.githubCallback }
            : { start: STAGED_EMAIL_OAUTH_PATHS.googleStart, callback: STAGED_EMAIL_OAUTH_PATHS.googleCallback };
        const start = await routeStagedEmailOAuth(new Request(
            `https://api.example${paths.start}?redirect=%2Fbilling&promo_code=PROMO&aff_code=AFF`
        ), env(db, provider), dependencies);
        assert.equal(new URL(start.headers.get("location")).searchParams.get("state"), "a".repeat(64));
        const callback = await routeStagedEmailOAuth(new Request(
            `https://api.example${paths.callback}?code=code&state=${"a".repeat(64)}`,
            { headers: { cookie: cookieHeader(start) } }
        ), env(db, provider), dependencies);
        assert.equal(callback.headers.get("location"), "https://api.example/auth/oauth/callback");
        const pending = await db.prepare(`
            SELECT provider_type AS providerType, provider_key AS providerKey,
                resolved_email AS email, local_flow_state AS flow, consumed_at AS consumedAt
            FROM pending_auth_sessions
        `).first();
        assert.equal(pending.providerType, provider);
        assert.equal(pending.providerKey, provider);
        assert.equal(pending.email, `${provider}@example.com`);
        const flow = JSON.parse(pending.flow);
        assert.equal(flow.promo_code, "PROMO");
        assert.equal(flow.affiliate_code, "AFF");
        assert.equal(flow.completion_response.error, "registration_completion_required");
        assert.equal(pending.consumedAt, null);
    }
});

test("verified Google email owner is atomically bound and logged in by pending exchange", async () => {
    const db = database();
    await configure(db, "google");
    const created = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, signup_source, token_version
        ) VALUES (?, ?, 'owner@example.com', 'owner-hash', 'user', 'active', 'Owner', 'email', 0)
    `).bind(NOW_ISO, NOW_ISO).run();
    const opaque = ["d".repeat(64), "e".repeat(64), "f".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: providerFetch("google", "owner@example.com")
    };
    const start = await routeStagedEmailOAuth(
        new Request(`https://api.example${STAGED_EMAIL_OAUTH_PATHS.googleStart}`),
        env(db, "google"), dependencies
    );
    const callback = await routeStagedEmailOAuth(new Request(
        `https://api.example${STAGED_EMAIL_OAUTH_PATHS.googleCallback}?code=code&state=${"d".repeat(64)}`,
        { headers: { cookie: cookieHeader(start) } }
    ), env(db, "google"), dependencies);
    const exchanged = await routeStagedPendingOAuth(new Request(
        `https://api.example${STAGED_PENDING_OAUTH_PATHS.exchange}`,
        { method: "POST", headers: { "content-type": "application/json", cookie: cookieHeader(callback) }, body: "{}" }
    ), env(db, "google"), { clock: () => NOW, nonceFactory: () => "google-exchange" });
    const body = await exchanged.json();
    assert.equal(body.code, 0, JSON.stringify(body));
    assert.ok(body.data.access_token);
    const identity = await db.prepare(`
        SELECT user_id AS userId, provider_type AS providerType FROM auth_identities
    `).first();
    assert.equal(identity.userId, created.meta.last_row_id);
    assert.equal(identity.providerType, "google");
    assert.ok((await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first()).consumedAt);
});

test("email OAuth callback rejects wrong browser state before provider exchange", async () => {
    const db = database();
    await configure(db, "github");
    const opaque = ["g".repeat(64), "h".repeat(64)];
    let fetched = false;
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: async () => { fetched = true; return new Response("{}"); }
    };
    const start = await routeStagedEmailOAuth(
        new Request(`https://api.example${STAGED_EMAIL_OAUTH_PATHS.githubStart}`),
        env(db, "github"), dependencies
    );
    const callback = await routeStagedEmailOAuth(new Request(
        `https://api.example${STAGED_EMAIL_OAUTH_PATHS.githubCallback}?code=code&state=${"x".repeat(64)}`,
        { headers: { cookie: cookieHeader(start) } }
    ), env(db, "github"), dependencies);
    assert.match(new URL(callback.headers.get("location")).hash, /invalid_state/u);
    assert.equal(fetched, false);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM pending_auth_sessions`).first()).count, 0);
});
