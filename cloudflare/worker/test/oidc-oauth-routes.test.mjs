import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    routeStagedOIDCOAuth,
    STAGED_OIDC_OAUTH_PATHS
} from "../src/router/staged-oidc-oauth.ts";
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
const NOW = Date.parse("2026-07-16T09:00:00.000Z");

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

async function configure(db) {
    for (const [key, value] of Object.entries({
        oidc_connect_enabled: "true",
        oidc_connect_provider_name: "Example OIDC",
        oidc_connect_client_id: "oidc-client",
        oidc_connect_issuer_url: "https://issuer.example",
        oidc_connect_redirect_url: "https://api.example/api/v1/auth/oauth/oidc/callback",
        oidc_connect_use_pkce: "true",
        oidc_connect_validate_id_token: "true",
        oidc_connect_allowed_signing_algs: "RS256",
        oidc_connect_require_email_verified: "true",
        registration_enabled: "false",
        email_verify_enabled: "false",
        force_email_on_third_party_signup: "false"
    })) await setting(db, key, value);
}

function env(db) {
    return {
        DB: db,
        JWT_SECRET: "oidc-route-secret-that-is-at-least-32-bytes",
        OIDC_CLIENT_SECRET: "oidc-secret",
        OIDC_AUTHORIZE_URL: "https://issuer.example/authorize",
        OIDC_TOKEN_URL: "https://issuer.example/token",
        OIDC_USERINFO_URL: "https://issuer.example/userinfo",
        OIDC_JWKS_URL: "https://issuer.example/jwks",
        OIDC_FRONTEND_REDIRECT_URL: "/auth/oidc/callback"
    };
}

function cookies(response) {
    return response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
}

test("OIDC start and callback validate ID token then create a browser-bound D1 pending choice", async () => {
    const db = createDatabase();
    await configure(db);
    const signing = await signingFixture();
    const opaque = ["a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(64), "e".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: async (input) => {
            const url = String(input);
            if (url.endsWith("/token")) {
                return new Response(JSON.stringify({
                    access_token: "provider-access",
                    token_type: "Bearer",
                    id_token: await signing.token("d".repeat(64))
                }));
            }
            if (url.endsWith("/jwks")) return new Response(JSON.stringify({ keys: [signing.jwk] }));
            return new Response(JSON.stringify({
                sub: "subject-42",
                email: "member@example.com",
                email_verified: true,
                preferred_username: "member",
                name: "Member Name",
                picture: "https://cdn.example/member.png"
            }));
        }
    };
    const start = await routeStagedOIDCOAuth(new Request(
        `https://api.example${STAGED_OIDC_OAUTH_PATHS.start}?redirect=%2Fprofile&promo_code=PROMO`
    ), env(db), dependencies);
    assert.equal(start.status, 302);
    const authorize = new URL(start.headers.get("location"));
    assert.equal(authorize.searchParams.get("state"), "a".repeat(64));
    assert.equal(authorize.searchParams.get("nonce"), "d".repeat(64));
    assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");

    const callback = await routeStagedOIDCOAuth(new Request(
        `https://api.example${STAGED_OIDC_OAUTH_PATHS.callback}?code=provider-code&state=${"a".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "https://api.example/auth/oidc/callback");
    assert.match(cookies(callback), /oauth_pending_session=e{48}/u);
    const pending = await db.prepare(`
        SELECT session_token AS sessionToken, provider_type AS providerType,
            provider_key AS providerKey, provider_subject AS providerSubject,
            resolved_email AS resolvedEmail, local_flow_state AS localFlowState
        FROM pending_auth_sessions
    `).first();
    assert.equal(pending.sessionToken, createHash("sha256").update("e".repeat(48)).digest("hex"));
    assert.equal(pending.providerType, "oidc");
    assert.equal(pending.providerKey, "https://issuer.example");
    assert.equal(pending.providerSubject, "subject-42");
    assert.match(pending.resolvedEmail, /^oidc-[a-f0-9]{32}@oidc-connect\.invalid$/u);
    const flow = JSON.parse(pending.localFlowState);
    assert.equal(flow.promo_code, "PROMO");
    assert.equal(flow.completion_response.step, "choose_account_action_required");
    assert.equal(flow.completion_response.suggested_display_name, "Member Name");

    const replay = await routeStagedOIDCOAuth(new Request(
        `https://api.example${STAGED_OIDC_OAUTH_PATHS.callback}?code=x&state=${"a".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.match(new URL(replay.headers.get("location")).hash, /invalid_state/u);
});

test("OIDC callback rejects a signed token with the wrong nonce before pending creation", async () => {
    const db = createDatabase();
    await configure(db);
    const signing = await signingFixture();
    const opaque = ["1".repeat(64), "2".repeat(64), "3".repeat(64), "4".repeat(64)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        fetchImplementation: async (input) => {
            const url = String(input);
            if (url.endsWith("/token")) {
                return new Response(JSON.stringify({
                    access_token: "provider-access",
                    id_token: await signing.token("wrong-nonce")
                }));
            }
            if (url.endsWith("/jwks")) return new Response(JSON.stringify({ keys: [signing.jwk] }));
            throw new Error("userinfo must not be requested");
        }
    };
    const start = await routeStagedOIDCOAuth(
        new Request(`https://api.example${STAGED_OIDC_OAUTH_PATHS.start}`),
        env(db),
        dependencies
    );
    const callback = await routeStagedOIDCOAuth(new Request(
        `https://api.example${STAGED_OIDC_OAUTH_PATHS.callback}?code=x&state=${"1".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);
    assert.match(new URL(callback.headers.get("location")).hash, /invalid_id_token/u);
    assert.equal((await db.prepare(`SELECT COUNT(*) AS count FROM pending_auth_sessions`).first()).count, 0);
});

test("OIDC bind-start authenticates the handoff token and stores the D1 target user", async () => {
    const db = createDatabase();
    await configure(db);
    const created = await db.prepare(`
        INSERT INTO users (
            created_at, updated_at, email, password_hash, role, status,
            username, signup_source, token_version
        ) VALUES (?, ?, 'bind@example.com', 'bind-password-hash', 'user', 'active', '', 'email', 0)
    `).bind(new Date(NOW).toISOString(), new Date(NOW).toISOString()).run();
    const userId = created.meta.last_row_id;
    const tokenVersion = await legacyTokenVersion("bind@example.com", "bind-password-hash", 0n);
    const access = await new Hs256JwtSigner(env(db).JWT_SECRET, 3600, () => NOW).sign({
        id: userId,
        email: "bind@example.com",
        role: "user",
        tokenVersion
    });
    const opaque = ["k".repeat(64), "l".repeat(64), "m".repeat(64), "n".repeat(64)];
    const response = await routeStagedOIDCOAuth(new Request(
        `https://api.example${STAGED_OIDC_OAUTH_PATHS.bindStart}`,
        { headers: { cookie: `oauth_bind_access_token=${access.token}` } }
    ), env(db), { clock: () => NOW, opaqueTokenFactory: () => opaque.shift() });

    assert.equal(response.status, 302);
    assert.equal(new URL(response.headers.get("location")).searchParams.get("state"), "k".repeat(64));
    const stored = await db.prepare(`SELECT value_json AS value FROM runtime_expiring_values`).first();
    const state = JSON.parse(stored.value);
    assert.equal(state.intent, "bind_current_user");
    assert.equal(state.bindUserId, userId);
    assert.ok(response.headers.getSetCookie().some((value) => value.startsWith("oauth_bind_access_token=;")));
});

test("OIDC verified email fast path atomically creates, binds, consumes, and redirects with tokens", async () => {
    const db = createDatabase();
    await configure(db);
    await setting(db, "registration_enabled", "true");
    const signing = await signingFixture();
    const opaque = ["f".repeat(64), "g".repeat(64), "h".repeat(64), "i".repeat(64), "j".repeat(48)];
    const dependencies = {
        clock: () => NOW,
        opaqueTokenFactory: () => opaque.shift(),
        nonceFactory: () => "fast-path-finalization",
        passwordHasher: { async hash() { return "$2b$10$fast-path-test-hash"; } },
        fetchImplementation: async (input) => {
            const url = String(input);
            if (url.endsWith("/token")) {
                return new Response(JSON.stringify({
                    access_token: "provider-access",
                    token_type: "Bearer",
                    id_token: await signing.token("i".repeat(64))
                }));
            }
            if (url.endsWith("/jwks")) return new Response(JSON.stringify({ keys: [signing.jwk] }));
            return new Response(JSON.stringify({
                sub: "subject-42",
                email: "Member@Example.com",
                email_verified: true,
                preferred_username: "member",
                name: "Member Name",
                picture: "https://cdn.example/member.png"
            }));
        }
    };
    const start = await routeStagedOIDCOAuth(
        new Request(`https://api.example${STAGED_OIDC_OAUTH_PATHS.start}?redirect=%2Fprofile`),
        env(db),
        dependencies
    );
    const callback = await routeStagedOIDCOAuth(new Request(
        `https://api.example${STAGED_OIDC_OAUTH_PATHS.callback}?code=x&state=${"f".repeat(64)}`,
        { headers: { cookie: cookies(start) } }
    ), env(db), dependencies);

    assert.equal(callback.status, 302);
    const redirected = new URL(callback.headers.get("location"));
    const fragment = new URLSearchParams(redirected.hash.slice(1));
    assert.equal(fragment.get("redirect"), "/profile");
    assert.ok(fragment.get("access_token"));
    assert.ok(fragment.get("refresh_token"));
    assert.equal(fragment.get("token_type"), "Bearer");
    const user = await db.prepare(`
        SELECT id, email, username, signup_source AS signupSource FROM users
    `).first();
    assert.equal(user.email, "member@example.com");
    assert.equal(user.username, "Member Name");
    assert.equal(user.signupSource, "oidc");
    const identity = await db.prepare(`
        SELECT provider_type AS providerType, provider_key AS providerKey,
            provider_subject AS providerSubject, metadata
        FROM auth_identities
    `).first();
    assert.equal(identity.providerType, "oidc");
    assert.equal(identity.providerKey, "https://issuer.example");
    assert.equal(identity.providerSubject, "subject-42");
    const identityMetadata = JSON.parse(identity.metadata);
    assert.equal(identityMetadata.email, "member@example.com");
    assert.match(identityMetadata.synthetic_email, /^oidc-[a-f0-9]{32}@oidc-connect\.invalid$/u);
    const pending = await db.prepare(`SELECT consumed_at AS consumedAt FROM pending_auth_sessions`).first();
    assert.ok(pending.consumedAt);
    assert.match(cookies(callback), /oauth_pending_session=/u);
});

async function signingFixture() {
    const pair = await crypto.subtle.generateKey({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    }, true, ["sign", "verify"]);
    const jwk = {
        ...await crypto.subtle.exportKey("jwk", pair.publicKey),
        kid: "route-key",
        use: "sig",
        alg: "RS256"
    };
    return {
        jwk,
        async token(nonce) {
            const now = Math.floor(NOW / 1000);
            const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "route-key" }));
            const claims = base64Url(JSON.stringify({
                iss: "https://issuer.example",
                sub: "subject-42",
                aud: "oidc-client",
                exp: now + 600,
                iat: now,
                nonce,
                email: "member@example.com",
                email_verified: true
            }));
            const input = new TextEncoder().encode(`${header}.${claims}`);
            const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, input);
            return `${header}.${claims}.${base64Url(new Uint8Array(signature))}`;
        }
    };
}

function base64Url(value) {
    return Buffer.from(value).toString("base64url");
}
