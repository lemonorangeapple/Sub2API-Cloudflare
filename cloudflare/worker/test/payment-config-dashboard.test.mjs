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

const JWT_SECRET = "payment-cfg-dash-test-secret-that-is-at-least-32-bytes!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insAdmin(d) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,totp_enabled,totp_secret_encrypted,signup_source,token_version) VALUES(?,?,?,?,?,?,?,?,?,?,0)`).bind("2026-07-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "admin@x.com", PASSWORD_HASH, "admin", "active", "admin", 0, null, "email").run();
    return Number(r.meta?.last_row_id);
}

let orderCounter = 0;
async function insOrder(d, overrides = {}) {
    orderCounter++;
    const on = `ORD${Date.now()}_${orderCounter}`;
    await d.prepare(`INSERT INTO payment_orders (user_id,user_email,user_name,amount,pay_amount,recharge_code,out_trade_no,payment_type,payment_trade_no,order_type,status,client_ip,src_host,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.user_id ?? 1, overrides.user_email ?? "user@x.com", overrides.user_name ?? "Test User",
        overrides.amount ?? 29.99, overrides.pay_amount ?? 29.99, overrides.recharge_code ?? "",
        on, overrides.payment_type ?? "wxpay",
        overrides.payment_trade_no ?? "", overrides.order_type ?? "balance",
        overrides.status ?? "PAID", overrides.client_ip ?? "127.0.0.1",
        overrides.src_host ?? "example.com",
        overrides.expires_at ?? "2026-08-01T00:00:00.000Z",
        overrides.created_at ?? new Date().toISOString(),
        overrides.updated_at ?? new Date().toISOString()
    ).run();
}

function token(d, uid, email, role) {
    return async () => {
        const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
        const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
        const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
        return s.token;
    };
}

test("admin payment config and dashboard", async (t) => {
    await t.test("GET /admin/payment/config returns default config", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/config`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.equal(typeof j.data.enabled, "boolean");
        assert.equal(typeof j.data.minAmount, "number");
    });

    await t.test("PUT /admin/payment/config updates config", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/config`, {
            method: "PUT", headers: { authorization: `Bearer ${tk}`, "content-type": "application/json" },
            body: JSON.stringify({ enabled: true, min_amount: 10, max_amount: 10000 })
        }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);

        const r2 = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/config`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j2 = await r2.json();
        assert.equal(j2.data.enabled, true);
        assert.equal(j2.data.minAmount, 10);
    });

    await t.test("GET /admin/payment/dashboard returns stats", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insOrder(d, { user_id: 1, status: "PAID", pay_amount: 100 });
        await insOrder(d, { user_id: 1, status: "PAID", pay_amount: 50 });
        await insOrder(d, { user_id: 1, status: "PENDING", pay_amount: 30 });

        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/dashboard`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.totalOrders, 3);
        assert.equal(j.data.totalRevenue, 150);
        assert.equal(j.data.pendingOrders, 1);
        assert.equal(j.data.paidOrders, 2);
    });

    await t.test("GET /admin/payment/dashboard respects days param", async () => {
        const d = db(); const aid = await insAdmin(d); const tk = await token(d, aid, "admin@x.com", "admin")();
        await insOrder(d, { user_id: 1, status: "PAID", pay_amount: 10 });
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/dashboard?days=7`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(j.code, 0);
        assert.equal(j.data.periodDays, 7);
    });

    await t.test("returns 401 without auth", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/admin/payment/config`), env(d));
        assert.equal(r.status, 401);
    });
});
