import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all(["0001_ent_core.sql", "0002_business_supplemental.sql", "0004_runtime_state.sql", "0005_auth_sessions.sql"].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));
const secret = "whsec_test_secret";

async function fixture(providerKey = "stripe") {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    const now = new Date().toISOString();
    const user = await db.prepare(`INSERT INTO users (created_at, updated_at, email, password_hash, role, status, username, totp_enabled, signup_source, token_version, balance) VALUES (?, ?, ?, ?, 'user', 'active', 'buyer', 0, 'email', 0, 0)`).bind(now, now, "buyer@example.com", "hash").run();
    const userId = Number(user.meta.last_row_id);
    await db.prepare(`INSERT INTO payment_provider_instances (provider_key, name, config, supported_types, enabled, payment_mode, sort_order, limits, refund_enabled, allow_user_refund, created_at, updated_at) VALUES (?, ?, ?, 'card', 1, '', 0, '', 0, 0, ?, ?)`).bind(providerKey, providerKey, JSON.stringify({ webhookSecret: secret }), now, now).run();
    const order = await db.prepare(`INSERT INTO payment_orders (user_id, user_email, user_name, amount, pay_amount, recharge_code, out_trade_no, payment_type, payment_trade_no, order_type, status, client_ip, src_host, expires_at, created_at, updated_at) VALUES (?, ?, ?, 10, 10.2, '', 'ORDER_WEBHOOK_1', 'stripe', '', 'balance', 'PENDING', '', '', ?, ?, ?)`).bind(userId, "buyer@example.com", "buyer", new Date(Date.now() + 3600000).toISOString(), now, now).run();
    return { db, userId, orderId: Number(order.meta.last_row_id) };
}

function signed(body, timestamp = Math.floor(Date.now() / 1000)) {
    const signature = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
    return `t=${timestamp},v1=${signature}`;
}

function payload(amount = 1020) {
    return JSON.stringify({ id: "evt_1", type: "payment_intent.succeeded", data: { object: { id: "pi_1", amount_received: amount, metadata: { order_id: "ORDER_WEBHOOK_1" } } } });
}

test("Stripe webhook verifies signature, amount, credits balance, and is idempotent", async () => {
    const { db, userId } = await fixture();
    const body = payload();
    const request = () => new Request("https://edge.example/api/v1/payment/webhook/stripe", { method: "POST", headers: { "stripe-signature": signed(body), "content-type": "application/json" }, body });
    const first = await routeRequest(request(), { DB: db });
    assert.equal(first.status, 200);
    const firstJson = await first.json();
    assert.equal(firstJson.data.duplicate, undefined);
    const second = await routeRequest(request(), { DB: db });
    assert.equal(second.status, 200);
    assert.equal((await second.json()).data.duplicate, true);
    const user = await db.prepare("SELECT balance FROM users WHERE id = ?").bind(userId).first();
    assert.equal(user.balance, 10);
    const order = await db.prepare("SELECT status, payment_trade_no FROM payment_orders WHERE out_trade_no = 'ORDER_WEBHOOK_1'").first();
    assert.equal(order.status, "PAID");
    assert.equal(order.payment_trade_no, "pi_1");
});

test("Stripe webhook rejects invalid signature and amount mismatch", async () => {
    const { db } = await fixture();
    const body = payload();
    const invalid = await routeRequest(new Request("https://edge.example/api/v1/payment/webhook/stripe", { method: "POST", headers: { "stripe-signature": "1.bad" }, body }), { DB: db });
    assert.equal(invalid.status, 400);
    const mismatchBody = payload(999);
    const mismatch = await routeRequest(new Request("https://edge.example/api/v1/payment/webhook/stripe", { method: "POST", headers: { "stripe-signature": signed(mismatchBody) }, body: mismatchBody }), { DB: db });
    assert.equal(mismatch.status, 400);
    const order = await db.prepare("SELECT status FROM payment_orders WHERE out_trade_no = 'ORDER_WEBHOOK_1'").first();
    assert.equal(order.status, "PENDING");
});

test("Airwallex webhook verifies timestamp HMAC and credits once", async () => {
    const { db, userId } = await fixture("airwallex");
    const timestamp = String(Date.now());
    const body = JSON.stringify({ name: "payment_intent.succeeded", id: "evt_aw_1", data: { object: { id: "pi_aw_1", amount: 10.2, merchant_order_id: "ORDER_WEBHOOK_1", status: "SUCCEEDED" } } });
    const signature = createHmac("sha256", secret).update(`${timestamp}${body}`).digest("hex");
    const response = await routeRequest(new Request("https://edge.example/api/v1/payment/webhook/airwallex", { method: "POST", headers: { "x-timestamp": timestamp, "x-signature": signature }, body }), { DB: db });
    assert.equal(response.status, 200);
    const user = await db.prepare("SELECT balance FROM users WHERE id = ?").bind(userId).first();
    assert.equal(user.balance, 10);
});
