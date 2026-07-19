import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import {
    D1WeChatPaymentOAuthStateService,
    WeChatPaymentOAuthError,
    WeChatPaymentResumeService,
    normalizePaymentRedirect,
    resolvePaymentResumeKeys
} from "../src/services/wechat-payment-oauth.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migration = await readFile(new URL("../../d1/migrations/0004_runtime_state.sql", import.meta.url), "utf8");
const NOW = Date.parse("2026-07-16T19:00:00.000Z");

test("WeChat payment state is browser-bound, one-time, and replaces plaintext context cookies", async () => {
    const db = new SQLiteD1Database();
    db.exec(migration);
    const opaque = ["a".repeat(64), "b".repeat(64)];
    const service = new D1WeChatPaymentOAuthStateService(
        new D1ExpiringStateRepository(db, { clock: () => NOW }),
        () => opaque.shift()
    );
    const started = await service.create({
        paymentType: "wxpay_direct",
        amount: "12.5",
        orderType: "subscription",
        planId: 7,
        redirectTo: "/purchase?tab=plans",
        scope: "snsapi_base"
    });
    await assert.rejects(() => service.consume(started.state, "c".repeat(64)), WeChatPaymentOAuthError);
    const consumed = await service.consume(started.state, started.browserSessionKey);
    assert.equal(consumed.planId, 7);
    assert.equal(consumed.paymentType, "wxpay_direct");
    await assert.rejects(() => service.consume(started.state, started.browserSessionKey), WeChatPaymentOAuthError);
});

test("Worker resume tokens are byte-compatible HMAC-SHA256 tokens with a 15 minute expiry", async () => {
    const key = new TextEncoder().encode("explicit-payment-resume-signing-key");
    const service = new WeChatPaymentResumeService(key, [], () => NOW);
    const token = await service.create({
        openId: "payment-openid",
        paymentType: "wxpay_direct",
        amount: "12.5",
        orderType: "subscription",
        planId: 7,
        redirectTo: "/payment?tab=plans",
        scope: "snsapi_base"
    });
    const [payload, signature] = token.split(".");
    assert.equal(signature, createHmac("sha256", key).update(payload).digest("base64url"));
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    assert.deepEqual(claims, {
        tk: "wechat_payment_resume",
        openid: "payment-openid",
        pt: "wxpay",
        amt: "12.5",
        ot: "subscription",
        pid: 7,
        rd: "/purchase?tab=plans",
        scp: "snsapi_base",
        iat: Math.floor(NOW / 1000),
        exp: Math.floor(NOW / 1000) + 900
    });
    assert.deepEqual(await service.parse(token), claims);
    await assert.rejects(
        () => new WeChatPaymentResumeService(key, [], () => NOW + 901_000).parse(token),
        WeChatPaymentOAuthError
    );
});

test("explicit payment signing keys verify legacy TOTP-key tokens during migration", async () => {
    const legacyHex = "0123456789abcdef".repeat(4);
    const legacyKeys = resolvePaymentResumeKeys({ TOTP_ENCRYPTION_KEY: legacyHex });
    const legacy = new WeChatPaymentResumeService(legacyKeys.signingKey, [], () => NOW);
    const token = await legacy.create({
        openId: "legacy-openid",
        paymentType: "wxpay",
        amount: "",
        orderType: "balance",
        planId: 0,
        redirectTo: "/purchase",
        scope: "snsapi_base"
    });
    const migratedKeys = resolvePaymentResumeKeys({
        PAYMENT_RESUME_SIGNING_KEY: "new-explicit-key",
        TOTP_ENCRYPTION_KEY: legacyHex
    });
    const migrated = new WeChatPaymentResumeService(
        migratedKeys.signingKey,
        migratedKeys.verifyFallbacks,
        () => NOW
    );
    assert.equal((await migrated.parse(token)).openid, "legacy-openid");
    assert.equal(normalizePaymentRedirect("//evil.example"), "/purchase");
});
