import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import {
    D1OIDCOAuthStateService,
    OIDCOAuthClient,
    OIDCOAuthError,
    resolveOIDCOAuthConfig,
    validateOIDCIDToken
} from "../src/services/oidc-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const runtimeMigration = await readFile(
    new URL("../../d1/migrations/0004_runtime_state.sql", import.meta.url),
    "utf8"
);
const NOW = Date.parse("2026-07-16T08:00:00.000Z");

function config(overrides = {}) {
    return {
        enabled: true,
        providerName: "Example OIDC",
        clientId: "oidc-client",
        clientSecret: "oidc-secret",
        issuerUrl: "https://issuer.example",
        discoveryUrl: "https://issuer.example/.well-known/openid-configuration",
        authorizeUrl: "https://issuer.example/authorize",
        tokenUrl: "https://issuer.example/token",
        userInfoUrl: "https://issuer.example/userinfo",
        jwksUrl: "https://issuer.example/jwks",
        scopes: "openid email profile",
        redirectUrl: "https://api.example/api/v1/auth/oauth/oidc/callback",
        frontendRedirectUrl: "/auth/oidc/callback",
        tokenAuthMethod: "client_secret_post",
        usePkce: true,
        validateIdToken: true,
        allowedSigningAlgs: ["RS256"],
        clockSkewSeconds: 120,
        requireEmailVerified: true,
        userInfoEmailPath: "",
        userInfoIdPath: "",
        userInfoUsernamePath: "",
        ...overrides
    };
}

test("OIDC state stores PKCE and nonce in D1 and consumes exactly once", async () => {
    const db = new SQLiteD1Database();
    db.exec(runtimeMigration);
    const values = ["a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(64)];
    const service = new D1OIDCOAuthStateService(
        new D1ExpiringStateRepository(db, { clock: () => NOW }),
        () => values.shift()
    );
    const started = await service.create(config(), {
        redirectTo: "/profile",
        intent: "bind_current_user",
        bindUserId: 11,
        promoCode: "PROMO"
    });
    const authorize = new URL(started.authorizeUrl);
    assert.equal(authorize.searchParams.get("state"), "a".repeat(64));
    assert.equal(authorize.searchParams.get("nonce"), "d".repeat(64));
    assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
    const row = await db.prepare(`SELECT state_key AS stateKey, value_json AS valueJson FROM runtime_expiring_values`).first();
    assert.equal(row.stateKey.includes("a".repeat(64)), false);
    assert.equal(JSON.parse(row.valueJson).codeVerifier, "c".repeat(64));
    await assert.rejects(() => service.consume(started.state, "f".repeat(64)), OIDCOAuthError);
    const consumed = await service.consume(started.state, started.browserSessionKey);
    assert.equal(consumed.nonce, "d".repeat(64));
    assert.equal(consumed.bindUserId, 11);
    await assert.rejects(() => service.consume(started.state, started.browserSessionKey), OIDCOAuthError);
});

test("OIDC discovery resolves endpoints and rejects issuer substitution", async () => {
    const settings = {
        oidc_connect_enabled: "true",
        oidc_connect_client_id: "oidc-client",
        oidc_connect_issuer_url: "https://issuer.example",
        oidc_connect_redirect_url: "https://api.example/callback"
    };
    const resolved = await resolveOIDCOAuthConfig(settings, { OIDC_CLIENT_SECRET: "secret" }, async () =>
        new Response(JSON.stringify({
            issuer: "https://issuer.example",
            authorization_endpoint: "https://issuer.example/authorize",
            token_endpoint: "https://issuer.example/token",
            userinfo_endpoint: "https://issuer.example/userinfo",
            jwks_uri: "https://issuer.example/jwks"
        }))
    );
    assert.equal(resolved.authorizeUrl, "https://issuer.example/authorize");
    assert.equal(resolved.usePkce, true);
    assert.equal(resolved.validateIdToken, true);
    await assert.rejects(
        () => resolveOIDCOAuthConfig(settings, { OIDC_CLIENT_SECRET: "secret" }, async () =>
            new Response(JSON.stringify({
                issuer: "https://attacker.example",
                authorization_endpoint: "https://attacker.example/authorize",
                token_endpoint: "https://attacker.example/token",
                jwks_uri: "https://attacker.example/jwks"
            }))
        ),
        (error) => error instanceof OIDCOAuthError && error.code === "oauth_config_invalid"
    );
});

test("OIDC client validates RS256 signature, claims, nonce, and userinfo subject", async () => {
    const signing = await signingFixture();
    const nonce = "n".repeat(64);
    const idToken = await signing.token({ nonce });
    const calls = [];
    const client = new OIDCOAuthClient(async (input, init = {}) => {
        const url = String(input);
        calls.push({ url, init });
        if (url.endsWith("/token")) {
            return new Response(JSON.stringify({
                access_token: "provider-access",
                token_type: "Bearer",
                id_token: idToken
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
    }, () => NOW);
    const user = await client.fetchUser(config(), "authorization-code", {
        codeVerifier: "v".repeat(64),
        nonce
    });
    assert.equal(user.subject, "subject-42");
    assert.equal(user.issuer, "https://issuer.example");
    assert.equal(user.compatEmail, "member@example.com");
    assert.match(user.syntheticEmail, /^oidc-[a-f0-9]{32}@oidc-connect\.invalid$/u);
    assert.match(String(calls[0].init.body), /code_verifier=v{64}/u);
    assert.equal(new Headers(calls[2].init.headers).get("authorization"), "Bearer provider-access");
});

test("OIDC ID token validation fails closed on nonce, audience, signature, and ambiguous keys", async () => {
    const signing = await signingFixture();
    const valid = await signing.token({ nonce: "expected" });
    const fetchJwks = async () => new Response(JSON.stringify({ keys: [signing.jwk] }));
    await assert.rejects(
        () => validateOIDCIDToken(valid, config(), "wrong", fetchJwks, NOW),
        (error) => error instanceof OIDCOAuthError && /nonce/u.test(error.message)
    );
    const wrongAudience = await signing.token({ nonce: "expected", aud: "other-client" });
    await assert.rejects(() => validateOIDCIDToken(wrongAudience, config(), "expected", fetchJwks, NOW), OIDCOAuthError);
    const [header, claims, encodedSignature] = valid.split(".");
    const changedSignature = Buffer.from(encodedSignature, "base64url");
    changedSignature[0] ^= 1;
    const tampered = `${header}.${claims}.${changedSignature.toString("base64url")}`;
    await assert.rejects(() => validateOIDCIDToken(tampered, config(), "expected", fetchJwks, NOW), OIDCOAuthError);
    const noKeyId = await signing.token({ nonce: "expected", kid: undefined });
    await assert.rejects(
        () => validateOIDCIDToken(
            noKeyId,
            config(),
            "expected",
            async () => new Response(JSON.stringify({ keys: [signing.jwk, { ...signing.jwk, kid: "second" }] })),
            NOW
        ),
        OIDCOAuthError
    );
});

test("OIDC ID token validation supports configured PS256 and ES256 keys", async () => {
    for (const algorithm of ["PS256", "ES256"]) {
        const fixture = await algorithmFixture(algorithm);
        const configured = { ...config(), allowedSigningAlgs: [algorithm] };
        const claims = await validateOIDCIDToken(
            fixture.token,
            configured,
            "algorithm-nonce",
            async () => new Response(JSON.stringify({ keys: [fixture.jwk] })),
            NOW
        );
        assert.equal(claims.sub, `${algorithm.toLowerCase()}-subject`);
    }
});

async function algorithmFixture(algorithm) {
    const keyAlgorithm = algorithm === "ES256"
        ? { name: "ECDSA", namedCurve: "P-256" }
        : {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        };
    const pair = await crypto.subtle.generateKey(keyAlgorithm, true, ["sign", "verify"]);
    const jwk = {
        ...await crypto.subtle.exportKey("jwk", pair.publicKey),
        kid: `${algorithm.toLowerCase()}-key`,
        use: "sig",
        alg: algorithm
    };
    const now = Math.floor(NOW / 1000);
    const header = base64Url(JSON.stringify({ alg: algorithm, typ: "JWT", kid: jwk.kid }));
    const claims = base64Url(JSON.stringify({
        iss: "https://issuer.example",
        sub: `${algorithm.toLowerCase()}-subject`,
        aud: "oidc-client",
        exp: now + 600,
        iat: now,
        nonce: "algorithm-nonce"
    }));
    const signAlgorithm = algorithm === "ES256"
        ? { name: "ECDSA", hash: "SHA-256" }
        : { name: "RSA-PSS", saltLength: 32 };
    const signature = await crypto.subtle.sign(
        signAlgorithm,
        pair.privateKey,
        new TextEncoder().encode(`${header}.${claims}`)
    );
    return { jwk, token: `${header}.${claims}.${base64Url(new Uint8Array(signature))}` };
}

async function signingFixture() {
    const pair = await crypto.subtle.generateKey({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    }, true, ["sign", "verify"]);
    const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const jwk = { ...exported, kid: "test-key", use: "sig", alg: "RS256" };
    return {
        jwk,
        async token(overrides = {}) {
            const header = { alg: "RS256", typ: "JWT", kid: "test-key", ...("kid" in overrides ? { kid: overrides.kid } : {}) };
            const now = Math.floor(NOW / 1000);
            const claims = {
                iss: "https://issuer.example",
                sub: "subject-42",
                aud: "oidc-client",
                exp: now + 600,
                iat: now,
                email: "member@example.com",
                email_verified: true,
                ...overrides
            };
            delete claims.kid;
            const encodedHeader = base64Url(JSON.stringify(header));
            const encodedClaims = base64Url(JSON.stringify(claims));
            const input = new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`);
            const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, input));
            return `${encodedHeader}.${encodedClaims}.${base64Url(signature)}`;
        }
    };
}

function base64Url(value) {
    const buffer = typeof value === "string" ? Buffer.from(value) : Buffer.from(value);
    return buffer.toString("base64url");
}
