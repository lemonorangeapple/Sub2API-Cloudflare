-- D1 final-state schema for Ops, scheduled tests, scheduler outbox, and usage aggregates.
-- Sources: legacy/backend/migrations/013 through 175a, with all later ALTER/DROP events folded in.
-- PostgreSQL-only indexes and data rewrites are documented in ../ops-usage-porting-notes.md.
-- Timestamps are UTC RFC 3339 text; JSONB and booleans use checked SQLite values.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS "orphan_allowed_groups_audit" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "group_id" INTEGER NOT NULL,
    "recorded_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE ("user_id", "group_id")
);

CREATE INDEX IF NOT EXISTS "idx_orphan_allowed_groups_audit_user_id"
    ON "orphan_allowed_groups_audit" ("user_id");

CREATE TABLE IF NOT EXISTS "ops_error_logs" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "request_id" TEXT,
    "client_request_id" TEXT,
    "user_id" INTEGER,
    "api_key_id" INTEGER,
    "account_id" INTEGER,
    "group_id" INTEGER,
    "client_ip" TEXT,
    "platform" TEXT,
    "model" TEXT,
    "request_path" TEXT,
    "stream" INTEGER NOT NULL DEFAULT 0 CHECK ("stream" IN (0, 1)),
    "user_agent" TEXT,
    "error_phase" TEXT NOT NULL,
    "error_type" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'P2',
    "status_code" INTEGER,
    "is_business_limited" INTEGER NOT NULL DEFAULT 0 CHECK ("is_business_limited" IN (0, 1)),
    "error_message" TEXT,
    "error_body" TEXT,
    "error_source" TEXT,
    "error_owner" TEXT,
    "account_status" TEXT,
    "upstream_status_code" INTEGER,
    "upstream_error_message" TEXT,
    "upstream_error_detail" TEXT,
    "provider_error_code" TEXT,
    "provider_error_type" TEXT,
    "network_error_type" TEXT,
    "retry_after_seconds" INTEGER,
    "duration_ms" INTEGER,
    "time_to_first_token_ms" INTEGER,
    "auth_latency_ms" INTEGER,
    "routing_latency_ms" INTEGER,
    "upstream_latency_ms" INTEGER,
    "response_latency_ms" INTEGER,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "upstream_errors" TEXT CHECK ("upstream_errors" IS NULL OR json_valid("upstream_errors")),
    "is_count_tokens" INTEGER NOT NULL DEFAULT 0 CHECK ("is_count_tokens" IN (0, 1)),
    "resolved" INTEGER NOT NULL DEFAULT 0 CHECK ("resolved" IN (0, 1)),
    "resolved_at" TEXT,
    "resolved_by_user_id" INTEGER,
    "inbound_endpoint" TEXT,
    "upstream_endpoint" TEXT,
    "requested_model" TEXT,
    "upstream_model" TEXT,
    "request_type" INTEGER,
    "attempted_key_prefix" TEXT,
    "deleted_key_owner_user_id" INTEGER,
    "deleted_key_name" TEXT,
    "api_key_prefix" TEXT
);

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_created_at"
    ON "ops_error_logs" ("created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_platform_time"
    ON "ops_error_logs" ("platform", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_group_time"
    ON "ops_error_logs" ("group_id", "created_at" DESC)
    WHERE "group_id" IS NOT NULL;

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_account_time"
    ON "ops_error_logs" ("account_id", "created_at" DESC)
    WHERE "account_id" IS NOT NULL;

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_status_time"
    ON "ops_error_logs" ("status_code", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_phase_time"
    ON "ops_error_logs" ("error_phase", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_type_time"
    ON "ops_error_logs" ("error_type", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_request_id"
    ON "ops_error_logs" ("request_id");

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_client_request_id"
    ON "ops_error_logs" ("client_request_id");

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_is_count_tokens"
    ON "ops_error_logs" ("is_count_tokens")
    WHERE "is_count_tokens" = 1;

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_resolved_time"
    ON "ops_error_logs" ("resolved", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_unresolved_time"
    ON "ops_error_logs" ("created_at" DESC)
    WHERE "resolved" = 0;

CREATE INDEX IF NOT EXISTS "idx_ops_error_logs_user_time"
    ON "ops_error_logs" ("user_id", "created_at" DESC)
    WHERE "user_id" IS NOT NULL;

CREATE TABLE IF NOT EXISTS "ops_system_metrics" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "window_minutes" INTEGER NOT NULL DEFAULT 1,
    "platform" TEXT,
    "group_id" INTEGER,
    "success_count" INTEGER NOT NULL DEFAULT 0,
    "error_count_total" INTEGER NOT NULL DEFAULT 0,
    "business_limited_count" INTEGER NOT NULL DEFAULT 0,
    "error_count_sla" INTEGER NOT NULL DEFAULT 0,
    "upstream_error_count_excl_429_529" INTEGER NOT NULL DEFAULT 0,
    "upstream_429_count" INTEGER NOT NULL DEFAULT 0,
    "upstream_529_count" INTEGER NOT NULL DEFAULT 0,
    "token_consumed" INTEGER NOT NULL DEFAULT 0,
    "qps" REAL,
    "tps" REAL,
    "duration_p50_ms" INTEGER,
    "duration_p90_ms" INTEGER,
    "duration_p95_ms" INTEGER,
    "duration_p99_ms" INTEGER,
    "duration_avg_ms" REAL,
    "duration_max_ms" INTEGER,
    "ttft_p50_ms" INTEGER,
    "ttft_p90_ms" INTEGER,
    "ttft_p95_ms" INTEGER,
    "ttft_p99_ms" INTEGER,
    "ttft_avg_ms" REAL,
    "ttft_max_ms" INTEGER,
    "cpu_usage_percent" REAL,
    "memory_used_mb" INTEGER,
    "memory_total_mb" INTEGER,
    "memory_usage_percent" REAL,
    "db_ok" INTEGER CHECK ("db_ok" IS NULL OR "db_ok" IN (0, 1)),
    "redis_ok" INTEGER CHECK ("redis_ok" IS NULL OR "redis_ok" IN (0, 1)),
    "db_conn_active" INTEGER,
    "db_conn_idle" INTEGER,
    "db_conn_waiting" INTEGER,
    "goroutine_count" INTEGER,
    "concurrency_queue_depth" INTEGER,
    "redis_conn_total" INTEGER,
    "redis_conn_idle" INTEGER,
    "account_switch_count" INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS "idx_ops_system_metrics_created_at"
    ON "ops_system_metrics" ("created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_metrics_window_time"
    ON "ops_system_metrics" ("window_minutes", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_metrics_platform_time"
    ON "ops_system_metrics" ("platform", "created_at" DESC)
    WHERE "platform" IS NOT NULL AND "platform" <> '' AND "group_id" IS NULL;

CREATE INDEX IF NOT EXISTS "idx_ops_system_metrics_group_time"
    ON "ops_system_metrics" ("group_id", "created_at" DESC)
    WHERE "group_id" IS NOT NULL;

CREATE TABLE IF NOT EXISTS "ops_job_heartbeats" (
    "job_name" TEXT NOT NULL PRIMARY KEY,
    "last_run_at" TEXT,
    "last_success_at" TEXT,
    "last_error_at" TEXT,
    "last_error" TEXT,
    "last_duration_ms" INTEGER,
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "last_result" TEXT
);

CREATE TABLE IF NOT EXISTS "ops_alert_rules" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "enabled" INTEGER NOT NULL DEFAULT 1 CHECK ("enabled" IN (0, 1)),
    "severity" TEXT NOT NULL DEFAULT 'warning',
    "metric_type" TEXT NOT NULL,
    "operator" TEXT NOT NULL,
    "threshold" REAL NOT NULL,
    "window_minutes" INTEGER NOT NULL DEFAULT 5,
    "sustained_minutes" INTEGER NOT NULL DEFAULT 5,
    "cooldown_minutes" INTEGER NOT NULL DEFAULT 10,
    "filters" TEXT CHECK ("filters" IS NULL OR json_valid("filters")),
    "last_triggered_at" TEXT,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "notify_email" INTEGER NOT NULL DEFAULT 1 CHECK ("notify_email" IN (0, 1))
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_ops_alert_rules_name_unique"
    ON "ops_alert_rules" ("name");

CREATE INDEX IF NOT EXISTS "idx_ops_alert_rules_enabled"
    ON "ops_alert_rules" ("enabled");

CREATE TABLE IF NOT EXISTS "ops_alert_events" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "rule_id" INTEGER,
    "severity" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'firing',
    "title" TEXT,
    "description" TEXT,
    "metric_value" REAL,
    "threshold_value" REAL,
    "dimensions" TEXT CHECK ("dimensions" IS NULL OR json_valid("dimensions")),
    "fired_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "resolved_at" TEXT,
    "email_sent" INTEGER NOT NULL DEFAULT 0 CHECK ("email_sent" IN (0, 1)),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS "idx_ops_alert_events_rule_status"
    ON "ops_alert_events" ("rule_id", "status");

CREATE INDEX IF NOT EXISTS "idx_ops_alert_events_fired_at"
    ON "ops_alert_events" ("fired_at" DESC);

CREATE TABLE IF NOT EXISTS "ops_metrics_hourly" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "bucket_start" TEXT NOT NULL,
    "platform" TEXT,
    "group_id" INTEGER,
    "success_count" INTEGER NOT NULL DEFAULT 0,
    "error_count_total" INTEGER NOT NULL DEFAULT 0,
    "business_limited_count" INTEGER NOT NULL DEFAULT 0,
    "error_count_sla" INTEGER NOT NULL DEFAULT 0,
    "upstream_error_count_excl_429_529" INTEGER NOT NULL DEFAULT 0,
    "upstream_429_count" INTEGER NOT NULL DEFAULT 0,
    "upstream_529_count" INTEGER NOT NULL DEFAULT 0,
    "token_consumed" INTEGER NOT NULL DEFAULT 0,
    "duration_p50_ms" INTEGER,
    "duration_p90_ms" INTEGER,
    "duration_p95_ms" INTEGER,
    "duration_p99_ms" INTEGER,
    "ttft_p50_ms" INTEGER,
    "ttft_p90_ms" INTEGER,
    "ttft_p95_ms" INTEGER,
    "ttft_p99_ms" INTEGER,
    "computed_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "duration_avg_ms" REAL,
    "duration_max_ms" INTEGER,
    "ttft_avg_ms" REAL,
    "ttft_max_ms" INTEGER,
    "ttft_sample_count" INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_ops_metrics_hourly_unique_dim"
    ON "ops_metrics_hourly" (
        "bucket_start",
        COALESCE("platform", ''),
        COALESCE("group_id", 0)
    );

CREATE INDEX IF NOT EXISTS "idx_ops_metrics_hourly_bucket"
    ON "ops_metrics_hourly" ("bucket_start" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_metrics_hourly_platform_bucket"
    ON "ops_metrics_hourly" ("platform", "bucket_start" DESC)
    WHERE "platform" IS NOT NULL AND "platform" <> '' AND "group_id" IS NULL;

CREATE INDEX IF NOT EXISTS "idx_ops_metrics_hourly_group_bucket"
    ON "ops_metrics_hourly" ("group_id", "bucket_start" DESC)
    WHERE "group_id" IS NOT NULL AND "group_id" <> 0;

CREATE TABLE IF NOT EXISTS "ops_metrics_daily" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "bucket_date" TEXT NOT NULL,
    "platform" TEXT,
    "group_id" INTEGER,
    "success_count" INTEGER NOT NULL DEFAULT 0,
    "error_count_total" INTEGER NOT NULL DEFAULT 0,
    "business_limited_count" INTEGER NOT NULL DEFAULT 0,
    "error_count_sla" INTEGER NOT NULL DEFAULT 0,
    "upstream_error_count_excl_429_529" INTEGER NOT NULL DEFAULT 0,
    "upstream_429_count" INTEGER NOT NULL DEFAULT 0,
    "upstream_529_count" INTEGER NOT NULL DEFAULT 0,
    "token_consumed" INTEGER NOT NULL DEFAULT 0,
    "duration_p50_ms" INTEGER,
    "duration_p90_ms" INTEGER,
    "duration_p95_ms" INTEGER,
    "duration_p99_ms" INTEGER,
    "ttft_p50_ms" INTEGER,
    "ttft_p90_ms" INTEGER,
    "ttft_p95_ms" INTEGER,
    "ttft_p99_ms" INTEGER,
    "computed_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "duration_avg_ms" REAL,
    "duration_max_ms" INTEGER,
    "ttft_avg_ms" REAL,
    "ttft_max_ms" INTEGER,
    "ttft_sample_count" INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_ops_metrics_daily_unique_dim"
    ON "ops_metrics_daily" (
        "bucket_date",
        COALESCE("platform", ''),
        COALESCE("group_id", 0)
    );

CREATE INDEX IF NOT EXISTS "idx_ops_metrics_daily_bucket"
    ON "ops_metrics_daily" ("bucket_date" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_metrics_daily_platform_bucket"
    ON "ops_metrics_daily" ("platform", "bucket_date" DESC)
    WHERE "platform" IS NOT NULL AND "platform" <> '' AND "group_id" IS NULL;

CREATE INDEX IF NOT EXISTS "idx_ops_metrics_daily_group_bucket"
    ON "ops_metrics_daily" ("group_id", "bucket_date" DESC)
    WHERE "group_id" IS NOT NULL AND "group_id" <> 0;

CREATE TABLE IF NOT EXISTS "ops_alert_silences" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "rule_id" INTEGER NOT NULL,
    "platform" TEXT NOT NULL,
    "group_id" INTEGER,
    "region" TEXT,
    "until" TEXT NOT NULL,
    "reason" TEXT,
    "created_by" INTEGER,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS "idx_ops_alert_silences_lookup"
    ON "ops_alert_silences" ("rule_id", "platform", "group_id", "region", "until");

CREATE TABLE IF NOT EXISTS "ops_system_logs" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "level" TEXT NOT NULL,
    "component" TEXT NOT NULL DEFAULT '',
    "message" TEXT NOT NULL,
    "request_id" TEXT,
    "client_request_id" TEXT,
    "user_id" INTEGER,
    "account_id" INTEGER,
    "platform" TEXT,
    "model" TEXT,
    "extra" TEXT NOT NULL DEFAULT '{}' CHECK (json_valid("extra")),
    "api_key_id" INTEGER,
    "host" TEXT
);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_created_at_id"
    ON "ops_system_logs" ("created_at" DESC, "id" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_level_created_at"
    ON "ops_system_logs" ("level", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_component_created_at"
    ON "ops_system_logs" ("component", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_request_id"
    ON "ops_system_logs" ("request_id");

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_client_request_id"
    ON "ops_system_logs" ("client_request_id");

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_user_id_created_at"
    ON "ops_system_logs" ("user_id", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_account_id_created_at"
    ON "ops_system_logs" ("account_id", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_platform_model_created_at"
    ON "ops_system_logs" ("platform", "model", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_api_key_id_created_at"
    ON "ops_system_logs" ("api_key_id", "created_at" DESC);

CREATE INDEX IF NOT EXISTS "idx_ops_system_logs_host_created_at"
    ON "ops_system_logs" ("host", "created_at" DESC);

CREATE TABLE IF NOT EXISTS "ops_system_log_cleanup_audits" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "operator_id" INTEGER NOT NULL,
    "conditions" TEXT NOT NULL DEFAULT '{}' CHECK (json_valid("conditions")),
    "deleted_rows" INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS "idx_ops_system_log_cleanup_audits_created_at"
    ON "ops_system_log_cleanup_audits" ("created_at" DESC, "id" DESC);

CREATE TABLE IF NOT EXISTS "scheduled_test_plans" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "account_id" INTEGER NOT NULL,
    "model_id" TEXT NOT NULL DEFAULT '',
    "cron_expression" TEXT NOT NULL DEFAULT '*/30 * * * *',
    "enabled" INTEGER NOT NULL DEFAULT 1 CHECK ("enabled" IN (0, 1)),
    "max_results" INTEGER NOT NULL DEFAULT 50,
    "last_run_at" TEXT,
    "next_run_at" TEXT,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "auto_recover" INTEGER NOT NULL DEFAULT 0 CHECK ("auto_recover" IN (0, 1)),
    CONSTRAINT "scheduled_test_plans_accounts_account"
        FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_stp_account_id"
    ON "scheduled_test_plans" ("account_id");

CREATE INDEX IF NOT EXISTS "idx_stp_enabled_next_run"
    ON "scheduled_test_plans" ("enabled", "next_run_at")
    WHERE "enabled" = 1;

CREATE TABLE IF NOT EXISTS "scheduled_test_results" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "plan_id" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'success',
    "response_text" TEXT NOT NULL DEFAULT '',
    "error_message" TEXT NOT NULL DEFAULT '',
    "latency_ms" INTEGER NOT NULL DEFAULT 0,
    "started_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "finished_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CONSTRAINT "scheduled_test_results_plans_plan"
        FOREIGN KEY ("plan_id") REFERENCES "scheduled_test_plans" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_str_plan_created"
    ON "scheduled_test_results" ("plan_id", "created_at" DESC);

CREATE TABLE IF NOT EXISTS "scheduler_outbox" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "event_type" TEXT NOT NULL,
    "account_id" INTEGER,
    "group_id" INTEGER,
    "payload" TEXT CHECK ("payload" IS NULL OR json_valid("payload")),
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "dedup_key" TEXT
);

CREATE INDEX IF NOT EXISTS "idx_scheduler_outbox_created_at"
    ON "scheduler_outbox" ("created_at");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_scheduler_outbox_pending_dedup_key"
    ON "scheduler_outbox" ("dedup_key")
    WHERE "dedup_key" IS NOT NULL;

CREATE TABLE IF NOT EXISTS "usage_billing_dedup" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "request_id" TEXT NOT NULL,
    "api_key_id" INTEGER NOT NULL,
    "request_fingerprint" TEXT NOT NULL,
    "created_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_usage_billing_dedup_request_api_key"
    ON "usage_billing_dedup" ("request_id", "api_key_id");

-- D1 has no BRIN access method; retain the PostgreSQL index name with a B-tree index.
CREATE INDEX IF NOT EXISTS "idx_usage_billing_dedup_created_at_brin"
    ON "usage_billing_dedup" ("created_at");

CREATE TABLE IF NOT EXISTS "usage_billing_dedup_archive" (
    "request_id" TEXT NOT NULL,
    "api_key_id" INTEGER NOT NULL,
    "request_fingerprint" TEXT NOT NULL,
    "created_at" TEXT NOT NULL,
    "archived_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY ("request_id", "api_key_id")
);

CREATE TABLE IF NOT EXISTS "usage_dashboard_hourly" (
    "bucket_start" TEXT NOT NULL PRIMARY KEY,
    "total_requests" INTEGER NOT NULL DEFAULT 0,
    "input_tokens" INTEGER NOT NULL DEFAULT 0,
    "output_tokens" INTEGER NOT NULL DEFAULT 0,
    "cache_creation_tokens" INTEGER NOT NULL DEFAULT 0,
    "cache_read_tokens" INTEGER NOT NULL DEFAULT 0,
    "total_cost" REAL NOT NULL DEFAULT 0,
    "actual_cost" REAL NOT NULL DEFAULT 0,
    "total_duration_ms" INTEGER NOT NULL DEFAULT 0,
    "active_users" INTEGER NOT NULL DEFAULT 0,
    "computed_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "account_cost" REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS "idx_usage_dashboard_hourly_bucket_start"
    ON "usage_dashboard_hourly" ("bucket_start" DESC);

CREATE TABLE IF NOT EXISTS "usage_dashboard_daily" (
    "bucket_date" TEXT NOT NULL PRIMARY KEY,
    "total_requests" INTEGER NOT NULL DEFAULT 0,
    "input_tokens" INTEGER NOT NULL DEFAULT 0,
    "output_tokens" INTEGER NOT NULL DEFAULT 0,
    "cache_creation_tokens" INTEGER NOT NULL DEFAULT 0,
    "cache_read_tokens" INTEGER NOT NULL DEFAULT 0,
    "total_cost" REAL NOT NULL DEFAULT 0,
    "actual_cost" REAL NOT NULL DEFAULT 0,
    "total_duration_ms" INTEGER NOT NULL DEFAULT 0,
    "active_users" INTEGER NOT NULL DEFAULT 0,
    "computed_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    "account_cost" REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS "idx_usage_dashboard_daily_bucket_date"
    ON "usage_dashboard_daily" ("bucket_date" DESC);

CREATE TABLE IF NOT EXISTS "usage_dashboard_hourly_users" (
    "bucket_start" TEXT NOT NULL,
    "user_id" INTEGER NOT NULL,
    PRIMARY KEY ("bucket_start", "user_id")
);

CREATE INDEX IF NOT EXISTS "idx_usage_dashboard_hourly_users_bucket_start"
    ON "usage_dashboard_hourly_users" ("bucket_start");

CREATE TABLE IF NOT EXISTS "usage_dashboard_daily_users" (
    "bucket_date" TEXT NOT NULL,
    "user_id" INTEGER NOT NULL,
    PRIMARY KEY ("bucket_date", "user_id")
);

CREATE INDEX IF NOT EXISTS "idx_usage_dashboard_daily_users_bucket_date"
    ON "usage_dashboard_daily_users" ("bucket_date");

CREATE TABLE IF NOT EXISTS "usage_dashboard_aggregation_watermark" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "last_aggregated_at" TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z',
    "updated_at" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO "usage_dashboard_aggregation_watermark" ("id")
VALUES (1)
ON CONFLICT ("id") DO NOTHING;

INSERT INTO "ops_alert_rules" (
    "name", "description", "enabled", "metric_type", "operator", "threshold",
    "window_minutes", "sustained_minutes", "severity", "notify_email", "cooldown_minutes"
) VALUES
    ('错误率过高', '当错误率超过 5% 且持续 5 分钟时触发告警', 1, 'error_rate', '>', 5.0, 5, 5, 'P1', 1, 20),
    ('成功率过低', '当成功率低于 95% 且持续 5 分钟时触发告警（服务可用性下降）', 1, 'success_rate', '<', 95.0, 5, 5, 'P0', 1, 15),
    ('P99延迟过高', '当 P99 延迟超过 3000ms 且持续 10 分钟时触发告警', 1, 'p99_latency_ms', '>', 3000.0, 5, 10, 'P2', 1, 30),
    ('P95延迟过高', '当 P95 延迟超过 2000ms 且持续 10 分钟时触发告警', 1, 'p95_latency_ms', '>', 2000.0, 5, 10, 'P2', 1, 30),
    ('CPU使用率过高', '当 CPU 使用率超过 85% 且持续 10 分钟时触发告警', 1, 'cpu_usage_percent', '>', 85.0, 5, 10, 'P2', 1, 30),
    ('内存使用率过高', '当内存使用率超过 90% 且持续 10 分钟时触发告警（可能导致 OOM）', 1, 'memory_usage_percent', '>', 90.0, 5, 10, 'P1', 1, 20),
    ('并发队列积压', '当并发队列深度超过 100 且持续 5 分钟时触发告警（系统处理能力不足）', 1, 'concurrency_queue_depth', '>', 100.0, 5, 5, 'P1', 1, 20),
    ('错误率极高', '当错误率超过 20% 且持续 1 分钟时触发告警（服务严重异常）', 1, 'error_rate', '>', 20.0, 1, 1, 'P0', 1, 15)
ON CONFLICT ("name") DO NOTHING;
