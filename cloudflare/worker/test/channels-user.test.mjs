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

const JWT_SECRET = "ch-user-test-secret-at-least-32-bytes!!";
const PASSWORD_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const BASE = "https://edge.example";
const NOW = "2026-07-15T12:00:00.000Z";

function db() { const d = new SQLiteD1Database(); for (const m of migrations) d.exec(m); return d; }
function env(d) { return { DB: d, JWT_SECRET, JWT_ACCESS_TOKEN_EXPIRES_SECONDS: "3600", JWT_REFRESH_TOKEN_EXPIRE_DAYS: "30" }; }

async function insUser(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO users (created_at,updated_at,email,password_hash,role,status,username,token_version) VALUES(?,?,?,?,?,?,?,?)`).bind(
        NOW, NOW,
        overrides.email ?? "user@x.com", PASSWORD_HASH,
        "user", "active", overrides.username ?? "testuser", 0
    ).run();
    return Number(r.meta.last_row_id);
}

async function insGroup(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO groups (name, platform, rate_multiplier, status, supported_model_scopes, messages_dispatch_model_config, models_list_config, created_at, updated_at, is_exclusive, subscription_type) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.name ?? "Standard", overrides.platform ?? "openai", overrides.rate_multiplier ?? 1,
        "active", "[]", "{}", "[]", NOW, NOW,
        overrides.is_exclusive ?? 0, overrides.subscription_type ?? "standard"
    ).run();
    return Number(r.meta.last_row_id);
}

async function insChannel(d, overrides = {}) {
    const r = await d.prepare(`INSERT INTO channels (name, description, status, model_mapping, billing_model_source, restrict_models, features, features_config, apply_pricing_to_account_stats, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        overrides.name ?? "Test Channel", overrides.description ?? "A test channel",
        overrides.status ?? "active", overrides.model_mapping ?? "{}",
        "channel_mapped", 0, "", "{}", 0, NOW, NOW
    ).run();
    return Number(r.meta.last_row_id);
}

async function insChannelGroup(d, channelId, groupId) {
    await d.prepare(`INSERT INTO channel_groups (channel_id, group_id) VALUES(?,?)`).bind(channelId, groupId).run();
}

function token(d, uid, email, role) {
    return async () => {
        const signer = new Hs256JwtSigner(JWT_SECRET, 604800);
        const tv = await legacyTokenVersion(email, PASSWORD_HASH, 0n);
        const s = await signer.sign({ id: uid, email, role, tokenVersion: tv });
        return s.token;
    };
}

test("user-facing channels available route", async (t) => {
    await t.test("GET /channels/available returns available channels", async () => {
        const d = db();
        const uid = await insUser(d);
        const gid = await insGroup(d, { name: "Pro", platform: "openai" });
        const cid = await insChannel(d, { name: "GPT-4 Channel" });
        await insChannelGroup(d, cid, gid);
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/channels/available`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.code, 0);
        assert.ok(Array.isArray(j.data));
        assert.equal(j.data.length, 1);
        assert.equal(j.data[0].name, "GPT-4 Channel");
        assert.ok(Array.isArray(j.data[0].platforms));
        assert.equal(j.data[0].platforms.length, 1);
        assert.equal(j.data[0].platforms[0].platform, "openai");
    });

    await t.test("GET /channels/available excludes inactive channels", async () => {
        const d = db();
        const uid = await insUser(d);
        const gid1 = await insGroup(d, { name: "Group A" });
        const gid2 = await insGroup(d, { name: "Group B" });
        const cid1 = await insChannel(d, { name: "Active", status: "active" });
        const cid2 = await insChannel(d, { name: "Inactive", status: "disabled" });
        await insChannelGroup(d, cid1, gid1);
        await insChannelGroup(d, cid2, gid2);
        const tk = await token(d, uid, "user@x.com", "user")();
        const r = await routeRequest(new Request(`${BASE}/api/v1/channels/available`, { headers: { authorization: `Bearer ${tk}` } }), env(d));
        const j = await r.json();
        assert.equal(r.status, 200);
        assert.equal(j.data.length, 1);
        assert.equal(j.data[0].name, "Active");
    });

    await t.test("unauthenticated requests get 401", async () => {
        const d = db();
        const r = await routeRequest(new Request(`${BASE}/api/v1/channels/available`), env(d));
        assert.equal(r.status, 401);
    });
});
