import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import {
    D1EmailOAuthStateService,
    EmailOAuthClient,
    EmailOAuthError,
    resolveEmailOAuthConfig
} from "../src/services/email-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migration = await readFile(new URL("../../d1/migrations/0004_runtime_state.sql", import.meta.url), "utf8");
const NOW = Date.parse("2026-07-16T14:00:00.000Z");

function config(provider) {
    return resolveEmailOAuthConfig(provider, {
        [`${provider}_oauth_enabled`]: "true",
        [`${provider}_oauth_client_id`]: `${provider}-client`,
        [`${provider}_oauth_redirect_url`]: `https://api.example/api/v1/auth/oauth/${provider}/callback`
    }, { [`${provider.toUpperCase()}_OAUTH_CLIENT_SECRET`]: `${provider}-secret` });
}

test("email OAuth state is provider- and browser-bound in one-time D1 storage", async () => {
    const db = new SQLiteD1Database();
    db.exec(migration);
    const opaque = ["a".repeat(64), "b".repeat(64)];
    const state = new D1EmailOAuthStateService(
        new D1ExpiringStateRepository(db, { clock: () => NOW }),
        () => opaque.shift()
    );
    const started = await state.create(config("github"), {
        redirectTo: "/billing",
        promoCode: "PROMO",
        affiliateCode: "AFF"
    });
    assert.equal(new URL(started.authorizeUrl).searchParams.get("state"), "a".repeat(64));
    await assert.rejects(() => state.consume("github", started.state, "c".repeat(64)), EmailOAuthError);
    const consumed = await state.consume("github", started.state, started.browserSessionKey);
    assert.equal(consumed.promoCode, "PROMO");
    await assert.rejects(() => state.consume("github", started.state, started.browserSessionKey), EmailOAuthError);
});

test("GitHub profile requires the verified email endpoint and prefers primary email", async () => {
    const calls = [];
    const client = new EmailOAuthClient(async (input, init) => {
        calls.push({ url: String(input), init });
        if (String(input).includes("access_token")) return new Response(JSON.stringify({ access_token: "token" }));
        if (String(input).endsWith("/user")) return new Response(JSON.stringify({
            id: 42, login: "octo", name: "Octo Cat", avatar_url: "https://cdn.example/octo.png"
        }));
        return new Response(JSON.stringify([
            { email: "fallback@example.com", verified: true, primary: false },
            { email: "Primary@Example.com", verified: true, primary: true }
        ]));
    });
    const profile = await client.fetchProfile(config("github"), "code");
    assert.equal(profile.subject, "42");
    assert.equal(profile.email, "primary@example.com");
    assert.equal(new Headers(calls[1].init.headers).get("authorization"), "Bearer token");
});

test("Google profile requires a verified email", async () => {
    let verified = false;
    const client = new EmailOAuthClient(async (input) => String(input).includes("token")
        ? new Response(JSON.stringify({ access_token: "token" }))
        : new Response(JSON.stringify({ sub: "google-sub", email: "member@example.com", email_verified: verified })));
    await assert.rejects(() => client.fetchProfile(config("google"), "code"), EmailOAuthError);
    verified = true;
    const profile = await client.fetchProfile(config("google"), "code");
    assert.equal(profile.email, "member@example.com");
});
