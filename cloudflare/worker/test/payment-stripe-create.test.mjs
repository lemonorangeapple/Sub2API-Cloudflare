import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import { D1PaymentUserService } from "../src/services/payment-user.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all(["0001_ent_core.sql", "0002_business_supplemental.sql", "0004_runtime_state.sql", "0005_auth_sessions.sql"].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

test("Stripe order creation creates a PaymentIntent with idempotency and order metadata", async (t) => {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    const now = new Date().toISOString();
    await db.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('payment_enabled', 'true', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(now).run();
    const user = await db.prepare("INSERT INTO users (created_at, updated_at, email, password_hash, role, status, username, totp_enabled, signup_source, token_version) VALUES (?, ?, 'stripe@example.com', 'hash', 'user', 'active', 'stripe', 0, 'email', 0)").bind(now, now).run();
    const userId = Number(user.meta.last_row_id);
    await db.prepare("INSERT INTO payment_provider_instances (provider_key, name, config, supported_types, enabled, payment_mode, sort_order, limits, refund_enabled, allow_user_refund, created_at, updated_at) VALUES ('stripe', 'Stripe', ?, 'card', 1, '', 0, '', 0, 0, ?, ?)").bind(JSON.stringify({ secretKey: "sk_test_123", currency: "USD" }), now, now).run();
    const originalFetch = globalThis.fetch;
    let captured;
    globalThis.fetch = async (url, init) => {
        captured = { url: String(url), init, body: await new Response(init.body).text() };
        return new Response(JSON.stringify({ id: "pi_test", client_secret: "pi_test_secret" }), { status: 200, headers: { "content-type": "application/json" } });
    };
    t.after(() => { globalThis.fetch = originalFetch; });
    const result = await new D1PaymentUserService(db).createOrder({ userId, userEmail: "stripe@example.com", userName: "stripe", amount: 12.34, paymentType: "stripe", orderType: "balance", clientIp: "127.0.0.1", srcHost: "edge.example" });
    assert.equal(result.client_secret, "pi_test_secret");
    assert.equal(result.intent_id, "pi_test");
    assert.equal(captured.url, "https://api.stripe.com/v1/payment_intents");
    assert.equal(captured.init.headers["idempotency-key"].startsWith("payment-"), true);
    const body = new URLSearchParams(captured.body);
    assert.equal(body.get("amount"), "1259");
    assert.equal(body.get("metadata[order_id]"), result.out_trade_no);
});
