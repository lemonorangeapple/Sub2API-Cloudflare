-- D1-only runtime coordination, expiring state, and task claim primitives.
-- Epoch millisecond integers are used so Worker comparisons stay deterministic.

CREATE TABLE IF NOT EXISTS "runtime_leases" (
    "lease_key" TEXT NOT NULL PRIMARY KEY,
    "owner" TEXT NOT NULL,
    "acquire_nonce" TEXT NOT NULL,
    "fencing_token" INTEGER NOT NULL DEFAULT 1 CHECK ("fencing_token" > 0),
    "expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0),
    "created_at" INTEGER NOT NULL CHECK ("created_at" >= 0),
    "updated_at" INTEGER NOT NULL CHECK ("updated_at" >= 0)
);

CREATE INDEX IF NOT EXISTS "runtime_leases_expires_at"
    ON "runtime_leases" ("expires_at");

CREATE TABLE IF NOT EXISTS "runtime_fixed_windows" (
    "counter_key" TEXT NOT NULL PRIMARY KEY,
    "window_start" INTEGER NOT NULL CHECK ("window_start" >= 0),
    "window_ms" INTEGER NOT NULL CHECK ("window_ms" > 0),
    "count" INTEGER NOT NULL CHECK ("count" >= 0),
    "reset_at" INTEGER NOT NULL CHECK ("reset_at" >= 0),
    "updated_at" INTEGER NOT NULL CHECK ("updated_at" >= 0)
);

CREATE INDEX IF NOT EXISTS "runtime_fixed_windows_reset_at"
    ON "runtime_fixed_windows" ("reset_at");

CREATE TABLE IF NOT EXISTS "runtime_reservations" (
    "reservation_key" TEXT NOT NULL PRIMARY KEY,
    "reservation_id" TEXT NOT NULL,
    "reservation_nonce" TEXT NOT NULL,
    "expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0),
    "created_at" INTEGER NOT NULL CHECK ("created_at" >= 0),
    "updated_at" INTEGER NOT NULL CHECK ("updated_at" >= 0)
);

CREATE INDEX IF NOT EXISTS "runtime_reservations_expires_at"
    ON "runtime_reservations" ("expires_at");

CREATE TABLE IF NOT EXISTS "runtime_expiring_values" (
    "state_key" TEXT NOT NULL PRIMARY KEY,
    "value_json" TEXT NOT NULL CHECK (json_valid("value_json")),
    "expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0),
    "created_at" INTEGER NOT NULL CHECK ("created_at" >= 0),
    "updated_at" INTEGER NOT NULL CHECK ("updated_at" >= 0)
);

CREATE INDEX IF NOT EXISTS "runtime_expiring_values_expires_at"
    ON "runtime_expiring_values" ("expires_at");

CREATE TABLE IF NOT EXISTS "runtime_tasks" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "queue_name" TEXT NOT NULL,
    "idempotency_key" TEXT,
    "payload_json" TEXT NOT NULL CHECK (json_valid("payload_json")),
    "result_json" TEXT CHECK ("result_json" IS NULL OR json_valid("result_json")),
    "status" TEXT NOT NULL CHECK ("status" IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    "priority" INTEGER NOT NULL DEFAULT 0,
    "available_at" INTEGER NOT NULL CHECK ("available_at" >= 0),
    "claim_owner" TEXT,
    "claim_token" TEXT,
    "claim_expires_at" INTEGER CHECK ("claim_expires_at" IS NULL OR "claim_expires_at" >= 0),
    "attempts" INTEGER NOT NULL DEFAULT 0 CHECK ("attempts" >= 0),
    "max_attempts" INTEGER NOT NULL DEFAULT 3 CHECK ("max_attempts" > 0),
    "last_error" TEXT,
    "created_at" INTEGER NOT NULL CHECK ("created_at" >= 0),
    "updated_at" INTEGER NOT NULL CHECK ("updated_at" >= 0),
    "completed_at" INTEGER CHECK ("completed_at" IS NULL OR "completed_at" >= 0),
    CHECK (
        ("status" = 'running' AND "claim_owner" IS NOT NULL AND "claim_token" IS NOT NULL AND "claim_expires_at" IS NOT NULL)
        OR
        ("status" <> 'running' AND "claim_owner" IS NULL AND "claim_token" IS NULL AND "claim_expires_at" IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS "runtime_tasks_queue_idempotency"
    ON "runtime_tasks" ("queue_name", "idempotency_key")
    WHERE "idempotency_key" IS NOT NULL;

CREATE INDEX IF NOT EXISTS "runtime_tasks_claimable"
    ON "runtime_tasks" ("queue_name", "status", "available_at", "priority" DESC, "id");

CREATE INDEX IF NOT EXISTS "runtime_tasks_claim_expires_at"
    ON "runtime_tasks" ("claim_expires_at")
    WHERE "claim_expires_at" IS NOT NULL;
