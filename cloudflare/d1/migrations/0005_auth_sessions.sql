-- D1-native authentication state.
--
-- token_version is persisted for future Worker-native password changes and
-- session revocation. Imported legacy users start at zero; until explicitly
-- changed, access-token compatibility uses the same email/password fingerprint
-- fallback as the legacy Go service.
ALTER TABLE "users" ADD COLUMN "token_version" INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS "auth_refresh_sessions" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "token_hash" TEXT NOT NULL UNIQUE,
    "user_id" INTEGER NOT NULL,
    "token_version" TEXT NOT NULL,
    "family_id" TEXT NOT NULL,
    "created_at" INTEGER NOT NULL,
    "expires_at" INTEGER NOT NULL,
    "rotated_at" INTEGER,
    "revoked_at" INTEGER,
    "replaced_by_hash" TEXT,
    CONSTRAINT "auth_refresh_sessions_users_session" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "auth_refresh_sessions_user_id_expires_at"
    ON "auth_refresh_sessions" ("user_id", "expires_at");
CREATE INDEX IF NOT EXISTS "auth_refresh_sessions_family_id"
    ON "auth_refresh_sessions" ("family_id");
CREATE INDEX IF NOT EXISTS "auth_refresh_sessions_expires_at"
    ON "auth_refresh_sessions" ("expires_at");
CREATE INDEX IF NOT EXISTS "auth_refresh_sessions_active_token"
    ON "auth_refresh_sessions" ("token_hash", "expires_at")
    WHERE "revoked_at" IS NULL AND "rotated_at" IS NULL;
