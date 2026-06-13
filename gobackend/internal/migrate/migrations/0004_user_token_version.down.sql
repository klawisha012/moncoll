-- 0004_user_token_version.down.sql
ALTER TABLE users DROP COLUMN IF EXISTS token_version;
