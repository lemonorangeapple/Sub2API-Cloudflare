-- D1-only user write integrity.
-- Active users must not share the same normalized email. Soft-deleted users do
-- not block reuse, matching the legacy active-user lookup contract.

CREATE UNIQUE INDEX IF NOT EXISTS "users_active_email_normalized_unique"
    ON "users" (lower(trim("email")))
    WHERE "deleted_at" IS NULL;
