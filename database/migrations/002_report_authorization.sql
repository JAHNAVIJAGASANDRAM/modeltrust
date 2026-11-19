-- Apply manually after backing up database/modeltrust.db.
-- Existing artifacts have no authenticated owner and remain administrator-only
-- until an administrator grants a report permission.
ALTER TABLE artifacts ADD COLUMN auth_user_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_artifacts_auth_user_id ON artifacts (auth_user_id);
