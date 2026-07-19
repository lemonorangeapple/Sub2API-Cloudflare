import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import {
    D1DingTalkOAuthStateService,
    DingTalkOAuthClient,
    DingTalkOAuthError,
    resolveDingTalkOAuthConfig
} from "../src/services/dingtalk-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migration = await readFile(new URL("../../d1/migrations/0004_runtime_state.sql", import.meta.url), "utf8");
const NOW = Date.parse("2026-07-16T20:00:00.000Z");

function config(policy = "internal_only") {
    return resolveDingTalkOAuthConfig({
        dingtalk_connect_enabled: "true",
        dingtalk_connect_client_id: "ding-client",
        dingtalk_connect_redirect_url: "https://api.example/api/v1/auth/oauth/dingtalk/callback",
        dingtalk_connect_corp_restriction_policy: policy
    }, {
        DINGTALK_CLIENT_SECRET: "ding-secret",
        DINGTALK_AUTHORIZE_URL: "https://ding.example/authorize",
        DINGTALK_TOKEN_URL: "https://ding.example/user-token",
        DINGTALK_USERINFO_URL: "https://ding.example/me",
        DINGTALK_APP_TOKEN_URL: "https://ding.example/app-token",
        DINGTALK_USER_BY_UNIONID_URL: "https://ding.example/by-union",
        DINGTALK_STAFF_INFO_URL: "https://ding.example/staff"
    });
}

test("DingTalk authorization state is browser-bound and consumed once from D1", async () => {
    const db = new SQLiteD1Database();
    db.exec(migration);
    const opaque = ["a".repeat(64), "b".repeat(64)];
    const service = new D1DingTalkOAuthStateService(
        new D1ExpiringStateRepository(db, { clock: () => NOW }),
        () => opaque.shift()
    );
    const started = await service.create(config(), {
        intent: "bind_current_user",
        bindUserId: 42,
        redirectTo: "/profile",
        promoCode: "PROMO"
    });
    const authorize = new URL(started.authorizeUrl);
    assert.equal(authorize.searchParams.get("prompt"), "consent");
    assert.equal(authorize.searchParams.get("client_id"), "ding-client");
    const state = await service.consume(started.state, started.browserSessionKey);
    assert.equal(state.bindUserId, 42);
    await assert.rejects(() => service.consume(started.state, started.browserSessionKey), DingTalkOAuthError);
});

test("DingTalk four-step internal flow resolves unionId, corporate email, and staff profile", async () => {
    const calls = [];
    const client = new DingTalkOAuthClient(async (input, init = {}) => {
        const url = String(input);
        calls.push({ url, init });
        if (url.endsWith("/user-token")) return json({ accessToken: "user-access", corpId: "ding-corp" });
        if (url.endsWith("/me")) return json({ unionId: "union_abcdef123", nick: "个人昵称" });
        if (url.endsWith("/app-token")) return json({ accessToken: "app-access", expireIn: 7200 });
        if (url.includes("/by-union")) return json({ errcode: 0, result: { userid: "staff-1" } });
        return json({
            errcode: 0,
            result: {
                userid: "staff-1",
                name: "企业姓名",
                org_email: "Member@Corp.Example",
                dept_id_list: [42, 99]
            }
        });
    });
    const identity = await client.fetchIdentity(config(), "provider-code");
    assert.equal(identity.subject, "union_abcdef123");
    assert.equal(identity.syntheticEmail, "dingtalk-union_abcdef123@dingtalk-connect.invalid");
    assert.equal(identity.email, "member@corp.example");
    assert.equal(identity.displayName, "个人昵称");
    assert.equal(identity.primaryDeptId, 42);
    assert.equal(calls[1].init.headers["x-acs-dingtalk-access-token"], "user-access");
    assert.match(calls[3].url, /access_token=app-access/u);
});

test("DingTalk public policy falls back to unionId identity when corporate directory lookup rejects", async () => {
    let count = 0;
    const client = new DingTalkOAuthClient(async () => {
        count += 1;
        if (count === 1) return json({ accessToken: "user-access" });
        if (count === 2) return json({ unionId: "cross_org_union", nick: "Cross User" });
        if (count === 3) return json({ accessToken: "app-access" });
        return new Response(JSON.stringify({ errcode: 60011, errmsg: "not in directory" }), { status: 403 });
    });
    const identity = await client.fetchIdentity(config("none"), "provider-code");
    assert.equal(identity.subject, "cross_org_union");
    assert.equal(identity.email, "");
    assert.equal(identity.displayName, "Cross User");
    count = 0;
    await assert.rejects(
        () => client.fetchIdentity(config("internal_only"), "provider-code"),
        DingTalkOAuthError
    );
});

function json(value) {
    return new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
}
