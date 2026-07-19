import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import {
    D1LinuxDoOAuthStateService,
    LinuxDoOAuthClient,
    LinuxDoOAuthError,
    resolveLinuxDoOAuthConfig
} from "../src/services/linuxdo-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const runtimeMigration = await readFile(
    new URL("../../d1/migrations/0004_runtime_state.sql", import.meta.url),
    "utf8"
);
const FIXED_NOW = Date.parse("2026-07-16T00:00:00.000Z");

function config(overrides = {}) {
    return {
        enabled: true,
        clientId: "linuxdo-client",
        clientSecret: "linuxdo-secret",
        authorizeUrl: "https://connect.example/oauth2/authorize",
        tokenUrl: "https://connect.example/oauth2/token",
        userInfoUrl: "https://connect.example/api/user",
        scopes: "user",
        redirectUrl: "https://api.example/api/v1/auth/oauth/linuxdo/callback",
        frontendRedirectUrl: "/auth/linuxdo/callback",
        tokenAuthMethod: "client_secret_post",
        usePkce: true,
        userInfoEmailPath: "",
        userInfoIdPath: "",
        userInfoUsernamePath: "",
        ...overrides
    };
}

test("LinuxDo state is D1-backed, PKCE protected, and one-time", async () => {
    const db = new SQLiteD1Database();
    db.exec(runtimeMigration);
    const tokens = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
    const service = new D1LinuxDoOAuthStateService(
        new D1ExpiringStateRepository(db, { clock: () => FIXED_NOW }),
        () => tokens.shift()
    );

    const started = await service.create(config(), {
        redirectTo: "/profile/security",
        intent: "bind_current_user",
        bindUserId: 17,
        promoCode: "PROMO"
    });
    const authorize = new URL(started.authorizeUrl);
    assert.equal(authorize.searchParams.get("state"), "a".repeat(64));
    assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
    assert.notEqual(authorize.searchParams.get("code_challenge"), "c".repeat(64));

    const row = await db.prepare(`
        SELECT state_key AS stateKey, value_json AS valueJson FROM runtime_expiring_values
    `).first();
    assert.equal(row.stateKey.includes("a".repeat(64)), false);
    assert.equal(row.valueJson.includes("c".repeat(64)), true);

    await assert.rejects(
        () => service.consume(started.state, "f".repeat(64)),
        LinuxDoOAuthError
    );
    const consumed = await service.consume(started.state, started.browserSessionKey);
    assert.equal(consumed.browserSessionKey, "b".repeat(64));
    assert.equal(consumed.codeVerifier, "c".repeat(64));
    assert.equal(consumed.bindUserId, 17);
    await assert.rejects(
        () => service.consume(started.state, started.browserSessionKey),
        LinuxDoOAuthError
    );
});

test("LinuxDo client supports form token responses and stable synthetic identity email", async () => {
    const calls = [];
    const client = new LinuxDoOAuthClient(async (input, init = {}) => {
        calls.push({ url: String(input), init });
        if (calls.length === 1) {
            return new Response("access_token=provider-token&token_type=Bearer", { status: 200 });
        }
        return new Response(JSON.stringify({
            id: "member_42",
            email: "member@example.com",
            username: "member",
            name: "Member Name",
            avatar_url: "https://cdn.example/member.png"
        }), { status: 200 });
    });

    const user = await client.fetchUser(config(), "authorization-code", "pkce-verifier");
    assert.equal(user.subject, "member_42");
    assert.equal(user.email, "linuxdo-member_42@linuxdo-connect.invalid");
    assert.equal(user.compatEmail, "member@example.com");
    assert.equal(user.displayName, "Member Name");
    assert.match(String(calls[0].init.body), /client_secret=linuxdo-secret/u);
    assert.match(String(calls[0].init.body), /code_verifier=pkce-verifier/u);
    assert.equal(new Headers(calls[1].init.headers).get("authorization"), "Bearer provider-token");
});

test("LinuxDo client rejects unsafe provider subjects", async () => {
    const client = new LinuxDoOAuthClient(async (input) => String(input).includes("token")
        ? new Response(JSON.stringify({ access_token: "provider-token" }))
        : new Response(JSON.stringify({ id: "../../admin" }))
    );
    await assert.rejects(
        () => client.fetchUser(config(), "authorization-code"),
        (error) => error instanceof LinuxDoOAuthError && error.code === "userinfo_failed"
    );
});

test("LinuxDo config resolves Cloudflare env fallbacks and validates token auth method", () => {
    const resolved = resolveLinuxDoOAuthConfig({
        linuxdo_connect_enabled: "true",
        linuxdo_connect_client_id: "db-client",
        linuxdo_connect_redirect_url: "https://api.example/callback"
    }, {
        LINUXDO_CLIENT_SECRET: "worker-secret"
    });
    assert.equal(resolved.clientId, "db-client");
    assert.equal(resolved.clientSecret, "worker-secret");
    assert.equal(resolved.tokenUrl, "https://connect.linux.do/oauth2/token");
    assert.throws(() => resolveLinuxDoOAuthConfig({}, {
        LINUXDO_TOKEN_AUTH_METHOD: "private_key_jwt"
    }), LinuxDoOAuthError);
});
