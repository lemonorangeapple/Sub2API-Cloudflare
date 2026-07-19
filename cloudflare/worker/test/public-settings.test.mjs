import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const coreMigration = await readFile(
    new URL("../../d1/migrations/0001_ent_core.sql", import.meta.url),
    "utf8"
);
const legacySettingsDTO = await readFile(
    new URL("../../../legacy/backend/internal/handler/dto/settings.go", import.meta.url),
    "utf8"
);
const legacyPublicSettingsBlock = legacySettingsDTO.match(/type PublicSettings struct \{([\s\S]*?)\n\}/u)?.[1];
assert.ok(legacyPublicSettingsBlock, "legacy PublicSettings DTO was not found");
const legacyPublicSettingsFields = [...legacyPublicSettingsBlock.matchAll(/json:"([a-z0-9_]+)"/gu)]
    .map((match) => match[1])
    .sort();

async function createDatabase(settings = {}) {
    const db = new SQLiteD1Database();
    db.exec(coreMigration);
    const insert = db.prepare(`
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
    `);
    for (const [key, value] of Object.entries(settings)) {
        await insert.bind(key, value, "2026-07-15T00:00:00Z").run();
    }
    return db;
}

test("GET public settings executes natively through Worker service and D1 repository", async () => {
    const db = await createDatabase({
        registration_enabled: "true",
        email_verify_enabled: "true",
        password_reset_enabled: "true",
        force_email_on_third_party_signup: "true",
        registration_email_suffix_whitelist: JSON.stringify([
            "Example.COM",
            "@example.com",
            "*.Company.COM",
            "bad_domain"
        ]),
        promo_code_enabled: "false",
        login_agreement_enabled: "true",
        login_agreement_mode: "checkbox",
        login_agreement_updated_at: "2026-07-01",
        login_agreement_documents: JSON.stringify([
            { id: " Terms ", title: " Terms ", content_md: " body " },
            { id: "terms", title: "Second", content_md: "more" },
            { title: "Generated", content_md: "generated body" }
        ]),
        site_name: " Native Site ",
        site_subtitle: "",
        table_default_page_size: "5000",
        table_page_size_options: "[100,20,20,4,1001]",
        custom_menu_items: JSON.stringify([
            { id: "user", label: "User", icon_svg: "", url: "/user", visibility: "user", sort_order: 2 },
            { id: "admin", label: "Admin", icon_svg: "", url: "/admin", visibility: "admin", sort_order: 1 }
        ]),
        custom_endpoints: JSON.stringify([
            { name: "OpenAI", endpoint: "/v1", description: "compat" }
        ]),
        github_oauth_enabled: "true",
        github_oauth_client_id: "github-client",
        github_oauth_client_secret: "github-secret",
        google_oauth_enabled: "true",
        google_oauth_client_id: "google-client",
        google_oauth_client_secret: "",
        wechat_connect_enabled: "true",
        wechat_connect_open_enabled: "true",
        wechat_connect_open_app_id: "wx-open",
        wechat_connect_open_app_secret: "wx-secret",
        wechat_connect_mp_enabled: "false",
        wechat_connect_mobile_enabled: "true",
        wechat_connect_mobile_app_id: "wx-mobile",
        wechat_connect_mobile_app_secret: "wx-mobile-secret",
        payment_enabled: "true",
        channel_monitor_enabled: "true",
        channel_monitor_default_interval_seconds: "3",
        balance_low_notify_threshold: "12.5",
        available_channels_enabled: "true",
        affiliate_enabled: "true",
        risk_control_enabled: "true",
        allow_user_view_error_requests: "true"
    });
    let backendCalled = false;

    const response = await routeRequest(
        new Request("https://edge.example/api/v1/settings/public?cache_bust=1"),
        {
            DB: db,
            APP_VERSION: "worker-test",
            SERVER_TIMEZONE: "Asia/Singapore",
            SERVER_UTC_OFFSET: "+08:00",
            BACKEND: {
                async fetch() {
                    backendCalled = true;
                    return new Response("unexpected");
                }
            }
        }
    );

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("x-sub2api-router"), "sub2api-router");
    assert.equal(backendCalled, false);

    const body = await response.json();
    assert.equal(body.code, 0);
    assert.equal(body.message, "success");
    assert.equal(body.data.registration_enabled, true);
    assert.equal(body.data.password_reset_enabled, true);
    assert.equal(body.data.force_email_on_third_party_signup, true);
    assert.deepEqual(body.data.registration_email_suffix_whitelist, ["@example.com", "*.company.com"]);
    assert.equal(body.data.promo_code_enabled, false);
    assert.equal(body.data.login_agreement_enabled, true);
    assert.equal(body.data.login_agreement_mode, "checkbox");
    assert.equal(body.data.login_agreement_documents[0].id, "terms");
    assert.equal(body.data.login_agreement_documents[1].id, "terms-2");
    assert.equal(body.data.login_agreement_documents[2].id.length, 12);
    assert.match(body.data.login_agreement_revision, /^[a-f0-9]{16}$/u);
    assert.equal(body.data.site_name, " Native Site ");
    assert.equal(body.data.site_subtitle, "Subscription to API Conversion Platform");
    assert.equal(body.data.table_default_page_size, 20);
    assert.deepEqual(body.data.table_page_size_options, [20, 100]);
    assert.deepEqual(body.data.custom_menu_items.map((item) => item.id), ["user"]);
    assert.deepEqual(body.data.custom_endpoints, [{ name: "OpenAI", endpoint: "/v1", description: "compat" }]);
    assert.equal(body.data.github_oauth_enabled, true);
    assert.equal(body.data.google_oauth_enabled, false);
    assert.equal(body.data.wechat_oauth_enabled, true);
    assert.equal(body.data.wechat_oauth_open_enabled, true);
    assert.equal(body.data.wechat_oauth_mobile_enabled, true);
    assert.equal(body.data.payment_enabled, true);
    assert.equal(body.data.channel_monitor_default_interval_seconds, 15);
    assert.equal(body.data.balance_low_notify_threshold, 12.5);
    assert.equal(body.data.version, "worker-test");
    assert.equal(body.data.server_timezone, "Asia/Singapore");
    assert.equal(body.data.server_utc_offset, "+08:00");
    assert.equal(JSON.stringify(body.data).includes("github-secret"), false);
    assert.equal(JSON.stringify(body.data).includes("wx-secret"), false);
    db.close();
});

test("public settings preserve legacy defaults for an empty settings table", async () => {
    const db = await createDatabase();
    const response = await routeRequest(new Request("https://edge.example/api/v1/settings/public"), { DB: db });
    const { data } = await response.json();

    assert.deepEqual(Object.keys(data).sort(), legacyPublicSettingsFields);
    assert.equal(data.registration_enabled, false);
    assert.equal(data.promo_code_enabled, true);
    assert.equal(data.password_reset_enabled, false);
    assert.equal(data.site_name, "Sub2API");
    assert.equal(data.login_agreement_mode, "modal");
    assert.equal(data.login_agreement_updated_at, "2026-03-31");
    assert.equal(data.login_agreement_documents.length, 4);
    assert.deepEqual(data.table_page_size_options, [10, 20, 50]);
    assert.equal(data.channel_monitor_enabled, true);
    assert.equal(data.channel_monitor_default_interval_seconds, 60);
    assert.deepEqual(data.custom_menu_items, []);
    assert.deepEqual(data.custom_endpoints, []);
    assert.equal(data.version, "dev");
    assert.equal(data.server_timezone, "UTC");
    assert.equal(data.server_utc_offset, "+00:00");
    db.close();
});

test("public settings path does not fall back to BACKEND on method or configuration errors", async () => {
    let backendCalls = 0;
    const backend = {
        async fetch() {
            backendCalls += 1;
            return new Response("unexpected");
        }
    };

    const methodResponse = await routeRequest(new Request("https://edge.example/api/v1/settings/public", {
        method: "POST"
    }), { BACKEND: backend });
    assert.equal(methodResponse.status, 405);
    assert.equal(methodResponse.headers.get("allow"), "GET");

    const missingDatabase = await routeRequest(
        new Request("https://edge.example/api/v1/settings/public"),
        { BACKEND: backend }
    );
    assert.equal(missingDatabase.status, 503);
    assert.equal((await missingDatabase.json()).error.code, "database_not_configured");
    assert.equal(backendCalls, 0);
});
