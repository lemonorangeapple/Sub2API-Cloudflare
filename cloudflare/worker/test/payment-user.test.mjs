import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { legacyTokenVersion } from "../src/utils/crypto.ts";
import { Hs256JwtSigner } from "../src/services/jwt.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql", "0002_business_supplemental.sql", "0004_runtime_state.sql", "0005_auth_sessions.sql"
].map((n) => readFile(new URL(`../../d1/migrations/${n}`, import.meta.url), "utf8")));

const JWT_SECRET = "payment-user-test-secret-that-is-at-least-32-bytes-long!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind(
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z",
        overrides.email ?? "user@x.com", PASSWORD_HASH,
        overrides.role ?? "user", overrides.status ?? "active",
        overrides.username ?? "testuser", 0
    ).run();
    return Number(r.meta.last_row_id);
}

async function insGroup(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO groups (name, platform, rate_multiplier, status, supported_model_scopes, messages_dispatch_model_config, models_list_config, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(
        overrides.name ?? "Standard", overrides.platform ?? "openai", overrides.rate_multiplier ?? 1,
        "active", "[]", "{}", "[]", "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"
    ).run();
    return Number(r.meta.last_row_id);
}

async function insPlan(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO subscription_plans (group_id, name, description, price, original_price, validity_days, validity_unit, features, product_name, for_sale, sort_order, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.group_id ?? 1, overrides.name ?? "Basic Plan", overrides.description ?? "",
        overrides.price ?? 9.99, overrides.original_price ?? null,
        overrides.validity_days ?? 30, "day", overrides.features ?? "",
        overrides.product_name ?? "basic", overrides.for_sale ?? 1, overrides.sort_order ?? 0,
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"
    ).run();
    return Number(r.meta.last_row_id);
}

async function insProvider(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO payment_provider_instances (provider_key, name, config, supported_types, enabled, payment_mode, sort_order, limits, refund_enabled, allow_user_refund, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.provider_key ?? "alipay", overrides.name ?? "Alipay",
        overrides.config ?? JSON.stringify({ app_id: "test", private_key: "test" }),
        overrides.supported_types ?? "alipay", overrides.enabled ?? 1,
        overrides.payment_mode ?? "redirect", overrides.sort_order ?? 0,
        overrides.limits ?? JSON.stringify({ daily_limit: 50000, single_min: 1, single_max: 50000 }),
        overrides.refund_enabled ?? 0, overrides.allow_user_refund ?? 0,
        "2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"
    ).run();
    return Number(r.meta.last_row_id);
}

async function insOrder(d, overrides = {}) {
    const cols = ["user_id","user_email","user_name","amount","pay_amount","recharge_code","out_trade_no","payment_type","payment_trade_no","order_type","status","client_ip","src_host","expires_at","created_at","updated_at"];
    const vals = [
        overrides.user_id ?? 1, overrides.user_email ?? "user@x.com", overrides.user_name ?? "Test User",
        overrides.amount ?? 29.99, overrides.pay_amount ?? 29.99, overrides.recharge_code ?? "",
        overrides.out_trade_no ?? `ORD${Date.now()}_${Math.random()}`, overrides.payment_type ?? "wxpay",
        overrides.payment_trade_no ?? "", overrides.order_type ?? "balance",
        overrides.status ?? "PENDING", overrides.client_ip ?? "127.0.0.1",
        overrides.src_host ?? "example.com",
        overrides.expires_at ?? "2026-08-01T00:00:00.000Z",
        overrides.created_at ?? "2026-07-01T00:00:00.000Z",
        overrides.updated_at ?? "2026-07-01T00:00:00.000Z"
    ];
    if (overrides.provider_instance_id !== undefined) {
        cols.push("provider_instance_id");
        vals.push(overrides.provider_instance_id);
    }
    if (overrides.plan_id !== undefined) {
        cols.push("plan_id");
        vals.push(overrides.plan_id);
    }
    const ph = cols.map(() => "?").join(",");
    const r = await d.prepare(`INSERT INTO payment_orders (${cols.join(",")}) VALUES(${ph})`).bind(...vals).run();
    return Number(r.meta.last_row_id);
}

function token(d, uid, email, role) {
    return async () => {
        const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
        const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
        const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
        return s.token;
    };
}

test("user-facing payment routes", async (t) => {
    await t.test("GET /payment/config returns config", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/config`), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.enabled, "boolean");
        assert.equal(typeof j.data.min_amount, "number");
        assert.equal(typeof j.data.stripe_publishable_key, "string");
    });

    await t.test("GET /payment/plans returns plans for sale", async () => {
        const d = db();
        const gid = await insGroup(d);
        await insPlan(d, { group_id: gid, price: 9.99, name: "Basic" });
        await insPlan(d, { group_id: gid, price: 19.99, name: "Pro", for_sale: 0 });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/plans`), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.length, 1);
        assert.equal(j.data[0].name, "Basic");
        assert.equal(j.data[0].groupPlatform, "openai");
    });

    await t.test("GET /payment/limits returns limits", async () => {
        const d = db();
        await insProvider(d);
        await insProvider(d, { provider_key: "wxpay", supported_types: "wxpay", limits: JSON.stringify({ daily_limit: 30000, single_min: 1, single_max: 30000 }) });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/limits`), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.methods, "object");
        assert.ok(j.data.methods.alipay);
        assert.ok(j.data.methods.wxpay);
        assert.equal(j.data.methods.alipay.currency, "CNY");
    });

    await t.test("GET /payment/checkout-info returns checkout info", async () => {
        const d = db();
        const gid = await insGroup(d);
        await insPlan(d, { group_id: gid, price: 9.99, name: "Basic" });
        await insProvider(d);
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/checkout-info`), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data.plans));
        assert.equal(typeof j.data.methods, "object");
        assert.equal(typeof j.data.globalMin, "number");
    });

    await t.test("POST /payment/orders creates order", async () => {
        const d = db();
        await d.prepare(`INSERT INTO settings (key, value, updated_at) VALUES('payment_enabled','true','2026-07-01T00:00:00.000Z') ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run();
        await d.prepare(`INSERT INTO settings (key, value, updated_at) VALUES('payment_min_amount','1','2026-07-01T00:00:00.000Z') ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run();
        await d.prepare(`INSERT INTO settings (key, value, updated_at) VALUES('payment_max_amount','10000','2026-07-01T00:00:00.000Z') ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run();
        await d.prepare(`INSERT INTO settings (key, value, updated_at) VALUES('payment_max_pending_orders','10','2026-07-01T00:00:00.000Z') ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        await insProvider(d, { provider_key: "alipay", supported_types: "alipay" });

        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ amount: 100, payment_type: "alipay", order_type: "balance" }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200, `expected 200 got ${r.status}: ${JSON.stringify(j)}`);
        assert.equal(j.code, 0);
        assert.equal(j.data.status, "PENDING");
        assert.equal(j.data.payment_type, "alipay");
        assert.equal(j.data.order_type, "balance");
        assert.ok(j.data.out_trade_no);
        assert.ok(j.data.order_id);
    });

    await t.test("GET /payment/orders/my lists user orders", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        await insOrder(d, { user_id: uid, out_trade_no: "UMY1", status: "PENDING" });
        await insOrder(d, { user_id: uid, out_trade_no: "UMY2", status: "PAID" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/my`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.total, 2);
        assert.equal(j.data.items.length, 2);
    });

    await t.test("GET /payment/orders/:id returns order", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const oid = await insOrder(d, { user_id: uid, out_trade_no: "UMYD1" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/${oid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.id, oid);
        assert.equal(j.data.status, "PENDING");
    });

    await t.test("POST /payment/orders/:id/cancel cancels pending order", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const oid = await insOrder(d, { user_id: uid, out_trade_no: "CAN1" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/${oid}/cancel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.message, "cancelled");
    });

    await t.test("POST /payment/orders/verify verifies by out_trade_no", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const otn = `VER_${Date.now()}`;
        await insOrder(d, { user_id: uid, out_trade_no: otn, status: "PAID" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/verify`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ out_trade_no: otn }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.outTradeNo, otn);
        assert.equal(j.data.status, "PAID");
    });

    await t.test("POST /payment/orders/:id/refund-request requests refund", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const pid = await insProvider(d, { refund_enabled: 1, allow_user_refund: 1 });
        const oid = await insOrder(d, { user_id: uid, out_trade_no: "REFREQ1", status: "COMPLETED", provider_instance_id: String(pid) });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/${oid}/refund-request`, {
            method: "POST",
            headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ reason: "Not satisfied" }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.message, "refund requested");
    });

    await t.test("GET /payment/orders/refund-eligible-providers returns eligible", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        await insProvider(d, { refund_enabled: 1, allow_user_refund: 1 });
        await insProvider(d, { provider_key: "wxpay", supported_types: "wxpay", refund_enabled: 0, allow_user_refund: 0 });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/refund-eligible-providers`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.provider_instance_ids.length, 1);
    });

    await t.test("unauthenticated requests get 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/my`), env(d));
        assert.equal(r.status, 401);
    });

    await t.test("other user's order returns 403", async () => {
        const d = db();
        const uid1 = await insUser(d, { email: "user1@x.com", username: "user1" });
        const uid2 = await insUser(d, { email: "user2@x.com", username: "user2" });
        const tk = await token(d, uid2, "user2@x.com", "user")();
        const oid = await insOrder(d, { user_id: uid1, out_trade_no: "OTH1" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/${oid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 403);
    });

    await t.test("POST /payment/public/orders/verify returns public order status", async () => {
        const d = db();
        const uid = await insUser(d);
        const otn = `PUB_${Date.now()}`;
        await insOrder(d, { user_id: uid, out_trade_no: otn, status: "COMPLETED" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/public/orders/verify`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ out_trade_no: otn }),
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.out_trade_no, otn);
        assert.equal(j.data.paid, true);
    });

    await t.test("cannot cancel non-pending order", async () => {
        const d = db();
        const uid = await insUser(d);
        const tk = await token(d, uid, "user@x.com", "user")();
        const oid = await insOrder(d, { user_id: uid, out_trade_no: "CANT1", status: "PAID" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/payment/orders/${oid}/cancel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 400);
    });
});
