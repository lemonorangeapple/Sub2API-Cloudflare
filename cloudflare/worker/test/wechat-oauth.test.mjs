import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import {
    D1WeChatOAuthStateService,
    WeChatOAuthClient,
    WeChatOAuthError,
    resolveWeChatMode,
    resolveWeChatOAuthConfig
} from "../src/services/wechat-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migration = await readFile(new URL("../../d1/migrations/0004_runtime_state.sql", import.meta.url), "utf8");
const NOW = Date.parse("2026-07-16T16:00:00.000Z");

function config(mode = "open", both = false) {
    return resolveWeChatOAuthConfig(mode, {
        wechat_connect_enabled: "true",
        wechat_connect_open_enabled: "true",
        wechat_connect_open_app_id: "open-app",
        wechat_connect_mp_enabled: both ? "true" : "false",
        wechat_connect_mp_app_id: "mp-app",
        wechat_connect_redirect_url: "https://api.example/api/v1/auth/oauth/wechat/callback"
    }, {
        WECHAT_CONNECT_OPEN_APP_SECRET: "open-secret",
        WECHAT_CONNECT_MP_APP_SECRET: "mp-secret",
        WECHAT_CONNECT_OPEN_AUTHORIZE_URL: "https://wechat.example/open-authorize",
        WECHAT_CONNECT_MP_AUTHORIZE_URL: "https://wechat.example/mp-authorize",
        WECHAT_CONNECT_TOKEN_URL: "https://wechat.example/token",
        WECHAT_CONNECT_USERINFO_URL: "https://wechat.example/userinfo"
    });
}

test("WeChat mode follows explicit input and MicroMessenger user agent", () => {
    assert.equal(resolveWeChatMode(null, "Mozilla MicroMessenger"), "mp");
    assert.equal(resolveWeChatMode(null, "Mozilla"), "open");
    assert.equal(resolveWeChatMode("mp", "Mozilla"), "mp");
    assert.throws(() => resolveWeChatMode("mobile"), WeChatOAuthError);
});

test("WeChat D1 state binds mode, intent, target, and browser exactly once", async () => {
    const db = new SQLiteD1Database();
    db.exec(migration);
    const opaque = ["a".repeat(64), "b".repeat(64)];
    const state = new D1WeChatOAuthStateService(
        new D1ExpiringStateRepository(db, { clock: () => NOW }),
        () => opaque.shift()
    );
    const started = await state.create(config(), {
        intent: "bind_current_user",
        bindUserId: 42,
        redirectTo: "/profile",
        promoCode: "PROMO"
    });
    const authorize = new URL(started.authorizeUrl);
    assert.equal(authorize.searchParams.get("appid"), "open-app");
    assert.equal(authorize.hash, "#wechat_redirect");
    const consumed = await state.consume(started.state, started.browserSessionKey);
    assert.equal(consumed.bindUserId, 42);
    await assert.rejects(() => state.consume(started.state, started.browserSessionKey), WeChatOAuthError);
});

test("WeChat identity uses unionid across enabled channels and stable synthetic email", async () => {
    const calls = [];
    const client = new WeChatOAuthClient(async (input) => {
        calls.push(String(input));
        return calls.length === 1
            ? new Response(JSON.stringify({ access_token: "access", openid: "open-1", unionid: "union-1" }))
            : new Response(JSON.stringify({ openid: "open-1", unionid: "union-1", nickname: "微信用户", headimgurl: "https://cdn.example/wx.png" }));
    });
    const identity = await client.fetchIdentity(config("open", true), "code");
    assert.equal(identity.subject, "union-1");
    assert.equal(identity.syntheticEmail, "wechat-union-1@wechat-connect.invalid");
    assert.equal(identity.displayName, "微信用户");
    assert.match(calls[0], /secret=open-secret/u);
});

test("WeChat requires unionid when open and mp channels are both enabled", async () => {
    const client = new WeChatOAuthClient(async (input) => String(input).includes("/token")
        ? new Response(JSON.stringify({ access_token: "access", openid: "channel-openid" }))
        : new Response(JSON.stringify({ openid: "channel-openid" })));
    await assert.rejects(
        () => client.fetchIdentity(config("open", true), "code"),
        (error) => error instanceof WeChatOAuthError && error.code === "wechat_missing_unionid"
    );
    const identity = await client.fetchIdentity(config("open", false), "code");
    assert.equal(identity.subject, "channel-openid");
});
