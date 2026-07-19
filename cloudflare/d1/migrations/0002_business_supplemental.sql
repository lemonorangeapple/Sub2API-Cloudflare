-- D1/SQLite baseline for selected raw-SQL business tables.
-- Requires 0001_ent_core.sql. Historical PostgreSQL backfills are intentionally excluded.

PRAGMA foreign_keys = ON;

-- Compatibility patches for raw columns/indexes that are absent from Ent's 0001 descriptor.
ALTER TABLE "usage_logs" ADD COLUMN "account_stats_cost" REAL;

CREATE UNIQUE INDEX IF NOT EXISTS "idx_usage_logs_request_id_api_key_unique"
    ON "usage_logs" ("request_id", "api_key_id");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_payment_audit_logs_order_action_uniq"
    ON "payment_audit_logs" ("order_id", "action");

CREATE TABLE IF NOT EXISTS "auth_identity_migration_reports" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "report_type" TEXT NOT NULL,
    "report_key" TEXT NOT NULL,
    "details" TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid("details") AND json_type("details") = 'object'),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "resolved_at" TEXT,
    "resolved_by_user_id" INTEGER,
    "resolution_note" TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS "auth_identity_migration_reports_type_idx"
    ON "auth_identity_migration_reports" ("report_type");
CREATE UNIQUE INDEX IF NOT EXISTS "auth_identity_migration_reports_type_key"
    ON "auth_identity_migration_reports" ("report_type", "report_key");
CREATE INDEX IF NOT EXISTS "idx_auth_identity_migration_reports_resolved_at"
    ON "auth_identity_migration_reports" ("resolved_at");

CREATE TABLE IF NOT EXISTS "billing_usage_entries" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "usage_log_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "api_key_id" INTEGER NOT NULL,
    "subscription_id" INTEGER,
    "billing_type" INTEGER NOT NULL,
    "applied" INTEGER NOT NULL DEFAULT 1 CHECK ("applied" IN (0, 1)),
    "delta_usd" REAL NOT NULL DEFAULT 0,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "billing_usage_entries_usage_log_fk"
        FOREIGN KEY ("usage_log_id") REFERENCES "usage_logs" ("id") ON DELETE CASCADE,
    CONSTRAINT "billing_usage_entries_user_fk"
        FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE,
    CONSTRAINT "billing_usage_entries_api_key_fk"
        FOREIGN KEY ("api_key_id") REFERENCES "api_keys" ("id") ON DELETE CASCADE,
    CONSTRAINT "billing_usage_entries_subscription_fk"
        FOREIGN KEY ("subscription_id") REFERENCES "user_subscriptions" ("id") ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS "billing_usage_entries_usage_log_id_unique"
    ON "billing_usage_entries" ("usage_log_id");
CREATE INDEX IF NOT EXISTS "idx_billing_usage_entries_user_time"
    ON "billing_usage_entries" ("user_id", "created_at");
CREATE INDEX IF NOT EXISTS "idx_billing_usage_entries_created_at"
    ON "billing_usage_entries" ("created_at");

CREATE TABLE IF NOT EXISTS "channels" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "description" TEXT DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'active',
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "model_mapping" TEXT DEFAULT '{}'
        CHECK ("model_mapping" IS NULL OR json_valid("model_mapping")),
    "billing_model_source" TEXT DEFAULT 'channel_mapped',
    "restrict_models" INTEGER DEFAULT 0
        CHECK ("restrict_models" IS NULL OR "restrict_models" IN (0, 1)),
    "features" TEXT NOT NULL DEFAULT '',
    "apply_pricing_to_account_stats" INTEGER NOT NULL DEFAULT 0
        CHECK ("apply_pricing_to_account_stats" IN (0, 1)),
    "features_config" TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid("features_config"))
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_channels_name" ON "channels" ("name");
CREATE INDEX IF NOT EXISTS "idx_channels_status" ON "channels" ("status");

CREATE TABLE IF NOT EXISTS "channel_groups" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "channel_id" INTEGER NOT NULL,
    "group_id" INTEGER NOT NULL,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "channel_groups_channel_fk"
        FOREIGN KEY ("channel_id") REFERENCES "channels" ("id") ON DELETE CASCADE,
    CONSTRAINT "channel_groups_group_fk"
        FOREIGN KEY ("group_id") REFERENCES "groups" ("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_channel_groups_group_id"
    ON "channel_groups" ("group_id");
CREATE INDEX IF NOT EXISTS "idx_channel_groups_channel_id"
    ON "channel_groups" ("channel_id");

CREATE TABLE IF NOT EXISTS "channel_model_pricing" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "channel_id" INTEGER NOT NULL,
    "models" TEXT NOT NULL DEFAULT '[]' CHECK (json_valid("models")),
    "input_price" REAL,
    "output_price" REAL,
    "cache_write_price" REAL,
    "cache_read_price" REAL,
    "image_output_price" REAL,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "billing_mode" TEXT NOT NULL DEFAULT 'token',
    "per_request_price" REAL,
    "platform" TEXT NOT NULL DEFAULT 'anthropic',
    CONSTRAINT "channel_model_pricing_channel_fk"
        FOREIGN KEY ("channel_id") REFERENCES "channels" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_channel_model_pricing_channel_id"
    ON "channel_model_pricing" ("channel_id");
CREATE INDEX IF NOT EXISTS "idx_channel_model_pricing_platform"
    ON "channel_model_pricing" ("platform");

CREATE TABLE IF NOT EXISTS "channel_pricing_intervals" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "pricing_id" INTEGER NOT NULL,
    "min_tokens" INTEGER NOT NULL DEFAULT 0,
    "max_tokens" INTEGER,
    "tier_label" TEXT,
    "input_price" REAL,
    "output_price" REAL,
    "cache_write_price" REAL,
    "cache_read_price" REAL,
    "per_request_price" REAL,
    "sort_order" INTEGER NOT NULL DEFAULT 0,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "channel_pricing_intervals_pricing_fk"
        FOREIGN KEY ("pricing_id") REFERENCES "channel_model_pricing" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_channel_pricing_intervals_pricing_id"
    ON "channel_pricing_intervals" ("pricing_id");

CREATE TABLE IF NOT EXISTS "channel_account_stats_pricing_rules" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "channel_id" INTEGER NOT NULL,
    "name" TEXT NOT NULL DEFAULT '',
    "group_ids" TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid("group_ids") AND json_type("group_ids") = 'array'),
    "account_ids" TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid("account_ids") AND json_type("account_ids") = 'array'),
    "sort_order" INTEGER NOT NULL DEFAULT 0,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "channel_account_stats_pricing_rules_channel_fk"
        FOREIGN KEY ("channel_id") REFERENCES "channels" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_cas_pricing_rules_channel_id"
    ON "channel_account_stats_pricing_rules" ("channel_id");

CREATE TABLE IF NOT EXISTS "channel_account_stats_model_pricing" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "rule_id" INTEGER NOT NULL,
    "platform" TEXT NOT NULL DEFAULT '',
    "models" TEXT NOT NULL DEFAULT '[]' CHECK (json_valid("models")),
    "billing_mode" TEXT NOT NULL DEFAULT 'token',
    "input_price" REAL,
    "output_price" REAL,
    "cache_write_price" REAL,
    "cache_read_price" REAL,
    "image_output_price" REAL,
    "per_request_price" REAL,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "channel_account_stats_model_pricing_rule_fk"
        FOREIGN KEY ("rule_id") REFERENCES "channel_account_stats_pricing_rules" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_cas_model_pricing_rule_id"
    ON "channel_account_stats_model_pricing" ("rule_id");

CREATE TABLE IF NOT EXISTS "channel_account_stats_pricing_intervals" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "pricing_id" INTEGER NOT NULL,
    "min_tokens" INTEGER NOT NULL DEFAULT 0,
    "max_tokens" INTEGER,
    "tier_label" TEXT,
    "input_price" REAL,
    "output_price" REAL,
    "cache_write_price" REAL,
    "cache_read_price" REAL,
    "per_request_price" REAL,
    "sort_order" INTEGER NOT NULL DEFAULT 0,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "channel_account_stats_pricing_intervals_pricing_fk"
        FOREIGN KEY ("pricing_id") REFERENCES "channel_account_stats_model_pricing" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_account_stats_pricing_intervals_pricing_id"
    ON "channel_account_stats_pricing_intervals" ("pricing_id");

CREATE TABLE IF NOT EXISTS "channel_monitor_aggregation_watermark" (
    "id" INTEGER NOT NULL PRIMARY KEY DEFAULT 1,
    "last_aggregated_date" TEXT,
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "channel_monitor_aggregation_watermark_singleton" CHECK ("id" = 1)
);

CREATE TABLE IF NOT EXISTS "content_moderation_logs" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "request_id" TEXT NOT NULL DEFAULT '',
    "user_id" INTEGER,
    "user_email" TEXT NOT NULL DEFAULT '',
    "api_key_id" INTEGER,
    "api_key_name" TEXT NOT NULL DEFAULT '',
    "group_id" INTEGER,
    "group_name" TEXT NOT NULL DEFAULT '',
    "endpoint" TEXT NOT NULL DEFAULT '',
    "provider" TEXT NOT NULL DEFAULT '',
    "model" TEXT NOT NULL DEFAULT '',
    "mode" TEXT NOT NULL DEFAULT '',
    "action" TEXT NOT NULL DEFAULT '',
    "flagged" INTEGER NOT NULL DEFAULT 0 CHECK ("flagged" IN (0, 1)),
    "highest_category" TEXT NOT NULL DEFAULT '',
    "highest_score" REAL NOT NULL DEFAULT 0,
    "category_scores" TEXT NOT NULL DEFAULT '{}' CHECK (json_valid("category_scores")),
    "threshold_snapshot" TEXT NOT NULL DEFAULT '{}' CHECK (json_valid("threshold_snapshot")),
    "input_excerpt" TEXT NOT NULL DEFAULT '',
    "upstream_latency_ms" INTEGER,
    "error" TEXT NOT NULL DEFAULT '',
    "violation_count" INTEGER NOT NULL DEFAULT 0,
    "auto_banned" INTEGER NOT NULL DEFAULT 0 CHECK ("auto_banned" IN (0, 1)),
    "email_sent" INTEGER NOT NULL DEFAULT 0 CHECK ("email_sent" IN (0, 1)),
    "queue_delay_ms" INTEGER,
    "matched_keyword" TEXT NOT NULL DEFAULT '',
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "content_moderation_logs_user_fk"
        FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE SET NULL,
    CONSTRAINT "content_moderation_logs_api_key_fk"
        FOREIGN KEY ("api_key_id") REFERENCES "api_keys" ("id") ON DELETE SET NULL,
    CONSTRAINT "content_moderation_logs_group_fk"
        FOREIGN KEY ("group_id") REFERENCES "groups" ("id") ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS "idx_content_moderation_logs_created_at"
    ON "content_moderation_logs" ("created_at" DESC);
CREATE INDEX IF NOT EXISTS "idx_content_moderation_logs_group_created_at"
    ON "content_moderation_logs" ("group_id", "created_at" DESC);
CREATE INDEX IF NOT EXISTS "idx_content_moderation_logs_flagged_created_at"
    ON "content_moderation_logs" ("flagged", "created_at" DESC);
CREATE INDEX IF NOT EXISTS "idx_content_moderation_logs_user_created_at"
    ON "content_moderation_logs" ("user_id", "created_at" DESC);
CREATE INDEX IF NOT EXISTS "idx_content_moderation_logs_api_key_created_at"
    ON "content_moderation_logs" ("api_key_id", "created_at" DESC);
CREATE INDEX IF NOT EXISTS "idx_content_moderation_logs_endpoint_created_at"
    ON "content_moderation_logs" ("endpoint", "created_at" DESC);

CREATE TABLE IF NOT EXISTS "deleted_api_key_audits" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "key" TEXT NOT NULL,
    "api_key_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "key_name" TEXT NOT NULL DEFAULT '',
    "deleted_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS "deletedapikeyaudit_key" ON "deleted_api_key_audits" ("key");
CREATE INDEX IF NOT EXISTS "deletedapikeyaudit_user_id" ON "deleted_api_key_audits" ("user_id");

CREATE TABLE IF NOT EXISTS "user_affiliates" (
    "user_id" INTEGER NOT NULL PRIMARY KEY,
    "aff_code" TEXT NOT NULL UNIQUE,
    "inviter_id" INTEGER,
    "aff_count" INTEGER NOT NULL DEFAULT 0,
    "aff_quota" REAL NOT NULL DEFAULT 0,
    "aff_history_quota" REAL NOT NULL DEFAULT 0,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "aff_rebate_rate_percent" REAL,
    "aff_code_custom" INTEGER NOT NULL DEFAULT 0 CHECK ("aff_code_custom" IN (0, 1)),
    "aff_frozen_quota" REAL NOT NULL DEFAULT 0,
    CONSTRAINT "user_affiliates_user_fk"
        FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE,
    CONSTRAINT "user_affiliates_inviter_fk"
        FOREIGN KEY ("inviter_id") REFERENCES "users" ("id") ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS "idx_user_affiliates_inviter_id"
    ON "user_affiliates" ("inviter_id");
CREATE INDEX IF NOT EXISTS "idx_user_affiliates_aff_quota"
    ON "user_affiliates" ("aff_quota");
CREATE INDEX IF NOT EXISTS "idx_user_affiliates_admin_settings"
    ON "user_affiliates" ("updated_at")
    WHERE "aff_code_custom" = 1 OR "aff_rebate_rate_percent" IS NOT NULL;

CREATE TABLE IF NOT EXISTS "user_affiliate_ledger" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "action" TEXT NOT NULL,
    "amount" REAL NOT NULL,
    "source_user_id" INTEGER,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "frozen_until" TEXT,
    "source_order_id" INTEGER,
    "balance_after" REAL,
    "aff_quota_after" REAL,
    "aff_frozen_quota_after" REAL,
    "aff_history_quota_after" REAL,
    CONSTRAINT "user_affiliate_ledger_user_fk"
        FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE,
    CONSTRAINT "user_affiliate_ledger_source_user_fk"
        FOREIGN KEY ("source_user_id") REFERENCES "users" ("id") ON DELETE SET NULL,
    CONSTRAINT "user_affiliate_ledger_source_order_fk"
        FOREIGN KEY ("source_order_id") REFERENCES "payment_orders" ("id") ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS "idx_user_affiliate_ledger_user_id"
    ON "user_affiliate_ledger" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_user_affiliate_ledger_action"
    ON "user_affiliate_ledger" ("action");
CREATE INDEX IF NOT EXISTS "idx_ual_frozen_thaw"
    ON "user_affiliate_ledger" ("user_id", "frozen_until")
    WHERE "frozen_until" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "idx_user_affiliate_ledger_source_order_id"
    ON "user_affiliate_ledger" ("source_order_id")
    WHERE "source_order_id" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "idx_user_affiliate_ledger_rebate_lookup"
    ON "user_affiliate_ledger" ("action", "source_order_id", "user_id", "source_user_id", "created_at")
    WHERE "action" = 'accrue';

CREATE TABLE IF NOT EXISTS "user_avatars" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "storage_provider" TEXT NOT NULL DEFAULT 'database',
    "storage_key" TEXT NOT NULL DEFAULT '',
    "url" TEXT NOT NULL DEFAULT '',
    "content_type" TEXT NOT NULL DEFAULT '',
    "byte_size" INTEGER NOT NULL DEFAULT 0,
    "sha256" TEXT NOT NULL DEFAULT '',
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "user_avatars_user_fk"
        FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "user_avatars_user_id_key" ON "user_avatars" ("user_id");

CREATE TABLE IF NOT EXISTS "user_group_rate_multipliers" (
    "user_id" INTEGER NOT NULL,
    "group_id" INTEGER NOT NULL,
    "rate_multiplier" REAL,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "rpm_override" INTEGER,
    PRIMARY KEY ("user_id", "group_id"),
    CONSTRAINT "user_group_rate_multipliers_user_fk"
        FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE,
    CONSTRAINT "user_group_rate_multipliers_group_fk"
        FOREIGN KEY ("group_id") REFERENCES "groups" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_user_group_rate_multipliers_group_id"
    ON "user_group_rate_multipliers" ("group_id");

CREATE TABLE IF NOT EXISTS "user_provider_default_grants" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "provider_type" TEXT NOT NULL,
    "grant_reason" TEXT NOT NULL DEFAULT 'first_bind',
    "granted_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "user_provider_default_grants_provider_type_check"
        CHECK ("provider_type" IN ('email', 'linuxdo', 'wechat', 'oidc', 'github', 'google', 'dingtalk')),
    CONSTRAINT "user_provider_default_grants_reason_check"
        CHECK ("grant_reason" IN ('signup', 'first_bind')),
    CONSTRAINT "user_provider_default_grants_user_fk"
        FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "user_provider_default_grants_user_provider_reason_key"
    ON "user_provider_default_grants" ("user_id", "provider_type", "grant_reason");
CREATE INDEX IF NOT EXISTS "user_provider_default_grants_user_id_idx"
    ON "user_provider_default_grants" ("user_id");

-- Idempotent bootstrap rows directly owned by this supplemental feature set.
INSERT INTO "channel_monitor_aggregation_watermark" ("id", "last_aggregated_date", "updated_at")
VALUES (1, NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT ("id") DO NOTHING;

INSERT INTO "settings" ("key", "value", "updated_at") VALUES
    ('risk_control_enabled', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_email_balance', '0', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_email_concurrency', '5', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_email_subscriptions', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_email_grant_on_signup', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_email_grant_on_first_bind', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_linuxdo_balance', '0', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_linuxdo_concurrency', '5', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_linuxdo_subscriptions', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_linuxdo_grant_on_signup', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_linuxdo_grant_on_first_bind', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_oidc_balance', '0', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_oidc_concurrency', '5', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_oidc_subscriptions', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_oidc_grant_on_signup', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_oidc_grant_on_first_bind', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_wechat_balance', '0', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_wechat_concurrency', '5', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_wechat_subscriptions', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_wechat_grant_on_signup', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('auth_source_default_wechat_grant_on_first_bind', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('force_email_on_third_party_signup', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT ("key") DO NOTHING;
