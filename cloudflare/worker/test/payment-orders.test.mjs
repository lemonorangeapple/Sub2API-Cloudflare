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

const JWT_SECRET = "payment-orders-test-secret-that-is-at-least-32-bytes-long!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", overrides.email ?? "user@x.com", PASSWORD_HASH, "user", "active", overrides.username ?? "testuser", 0).run();
    return Number(r.meta.last_row_id);
}

async function insOrder(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO payment_orders (user_id,user_email,user_name,amount,pay_amount,recharge_code,out_trade_no,payment_type,payment_trade_no,order_type,status,client_ip,src_host,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.user_id ?? 1, overrides.user_email ?? "user@x.com", overrides.user_name ?? "Test User",
        overrides.amount ?? 29.99, overrides.pay_amount ?? 29.99, overrides.recharge_code ?? "",
        overrides.out_trade_no ?? `ORDER${Date.now()}`, overrides.payment_type ?? "wxpay",
        overrides.payment_trade_no ?? "", overrides.order_type ?? "balance",
        overrides.status ?? "PENDING", overrides.client_ip ?? "127.0.0.1",
        overrides.src_host ?? "example.com",
        overrides.expires_at ?? "2026-08-01T00:00:00.000Z",
        overrides.created_at ?? "2026-07-01T00:00:00.000Z",
        overrides.updated_at ?? "2026-07-01T00:00:00.000Z"
    ).run();
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

test("admin payment orders", async (t) => {
    await t.test("GET /admin/payment/orders returns empty list", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(j.data.items.length, 0);
        assert.equal(j.data.total, 0);
    });

    await t.test("GET /admin/payment/orders lists orders", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        await insOrder(d, { user_id: uid, out_trade_no: "ORD001", status: "PENDING" });
        await insOrder(d, { user_id: uid, out_trade_no: "ORD002", status: "PAID" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.total, 2);
        assert.equal(j.data.items.length, 2);
    });

    await t.test("GET /admin/payment/orders filters by status", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        await insOrder(d, { user_id: uid, out_trade_no: "ORD003", status: "PENDING" });
        await insOrder(d, { user_id: uid, out_trade_no: "ORD004", status: "PAID" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders?status=PAID`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.data.total, 1);
        assert.equal(j.data.items[0].status, "PAID");
    });

    await t.test("GET /admin/payment/orders/:id returns order detail", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const oid = await insOrder(d, { user_id: uid, out_trade_no: "ORD005" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders/${oid}`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.order.id, oid);
        assert.equal(j.data.order.outTradeNo, "ORD005");
        assert.equal(Array.isArray(j.data.auditLogs), true);
    });

    await t.test("GET /admin/payment/orders/:id returns 404 for non-existent", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders/99999`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        assert.equal(r.status, 404);
    });

    await t.test("POST /admin/payment/orders/:id/cancel cancels pending order", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const oid = await insOrder(d, { user_id: uid, status: "PENDING" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders/${oid}/cancel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.message, "Order cancelled successfully");
    });

    await t.test("POST /admin/payment/orders/:id/cancel fails for non-pending order", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const oid = await insOrder(d, { user_id: uid, status: "PAID" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders/${oid}/cancel`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("POST /admin/payment/orders/:id/retry retries paid order", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const oid = await insOrder(d, { user_id: uid, status: "PAID" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders/${oid}/retry`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.message, "fulfillment retried");
    });

    await t.test("POST /admin/payment/orders/:id/retry fails for non-paid order", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const uid = await insUser(d);
        const oid = await insOrder(d, { user_id: uid, status: "PENDING" });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders/${oid}/retry`, {
            method: "POST", headers: { authorization: `Bearer ${tk}` }
        }), env(d));
        assert.equal(r.status, 400);
    });

    await t.test("returns 401 without auth", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/orders`), env(d));
        assert.equal(r.status, 401);
    });
});
