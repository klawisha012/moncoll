-- 0001_init.down.sql
-- Reverses the baseline schema: drops all tables and enum types.
-- WARNING: this destroys all data. Only use in development.

DROP TABLE IF EXISTS connections CASCADE;
DROP TABLE IF EXISTS email_verifications CASCADE;
DROP TABLE IF EXISTS oauth_accounts CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;

DROP TYPE IF EXISTS modsec_state CASCADE;
DROP TYPE IF EXISTS connection_status CASCADE;
DROP TYPE IF EXISTS origin_tls_mode CASCADE;
DROP TYPE IF EXISTS email_verification_purpose CASCADE;
DROP TYPE IF EXISTS oauth_provider CASCADE;
DROP TYPE IF EXISTS tenant_role CASCADE;
DROP TYPE IF EXISTS platform_role CASCADE;
