-- 0004_user_token_version.up.sql — per-user session-revocation watermark.
--
-- Session tokens embed the value current at mint time (the "tv" claim); the
-- auth gate (resolveVerified) rejects any token whose tv != users.token_version.
-- The column is bumped on password change and logout-everywhere, invalidating
-- every previously minted token for that user.
--
-- DEFAULT 0 keeps existing sessions valid across the rollout: tokens minted
-- before this change carry no "tv" claim and decode to 0, which matches the
-- default for users that have never revoked.

ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
