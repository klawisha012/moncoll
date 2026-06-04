-- 0001_init.up.sql
-- Go-owned baseline schema for the WAF platform.
--
-- This is a single greenfield baseline representing the net result of all 8
-- alembic migrations (0001_initial → 0008_connection_crowdsec). We are NOT
-- replaying alembic's incremental steps — this is the final schema as of
-- migration 0008. All DDL is idempotent (IF NOT EXISTS / exception guards) so
-- running this against an already-alembic-migrated production DB is a safe
-- no-op.
--
-- Column types match what alembic actually emitted:
--   - Timestamps: TIMESTAMPTZ (DateTime(timezone=True))
--   - JSON arrays (origin_hosts, geoip_denied_countries): JSON (not JSONB —
--     alembic used sa.JSON() which maps to json in PostgreSQL)
--   - ARRAY(String): TEXT[] (recovery_codes_hash)
--   - Enums: named PostgreSQL enums (platform_role, tenant_role, oauth_provider,
--     email_verification_purpose, origin_tls_mode, connection_status, modsec_state)

-- ── Enum types ────────────────────────────────────────────────────────────────

DO $$ BEGIN
    CREATE TYPE platform_role AS ENUM ('admin', 'client');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE tenant_role AS ENUM ('owner', 'member');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE oauth_provider AS ENUM ('google', 'github');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE email_verification_purpose AS ENUM ('verify_email', 'reset_password');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE origin_tls_mode AS ENUM ('strict', 'lenient');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE connection_status AS ENUM (
        'pending_verification',
        'pending_dns',
        'provisioning_cert',
        'active',
        'error'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE modsec_state AS ENUM ('off', 'detection_only', 'blocking');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── tenants ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
    id           SERIAL       PRIMARY KEY,
    name         VARCHAR(32)  NOT NULL UNIQUE,
    display_name VARCHAR(64)  NOT NULL,
    suspended_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_tenants_name ON tenants (name);

-- ── users ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id                  SERIAL       PRIMARY KEY,
    email               VARCHAR(254) NOT NULL UNIQUE,
    display_name        VARCHAR(64)  NOT NULL DEFAULT '',
    password_hash       VARCHAR(255),
    platform_role       platform_role NOT NULL,
    tenant_id           INTEGER      REFERENCES tenants(id) ON DELETE CASCADE,
    tenant_role         tenant_role,
    email_verified_at   TIMESTAMPTZ,
    totp_secret         VARCHAR(64),
    totp_enabled_at     TIMESTAMPTZ,
    recovery_codes_hash VARCHAR(64)[],
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT users_platform_tenant_consistency CHECK (
        (platform_role = 'admin'  AND tenant_id IS NULL     AND tenant_role IS NULL) OR
        (platform_role = 'client' AND tenant_id IS NOT NULL AND tenant_role IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_users_email     ON users (email);
CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON users (tenant_id);

-- ── oauth_accounts ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS oauth_accounts (
    id                  SERIAL       PRIMARY KEY,
    user_id             INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            oauth_provider NOT NULL,
    provider_account_id VARCHAR(128) NOT NULL,
    email_at_provider   VARCHAR(254) NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_oauth_provider_account UNIQUE (provider, provider_account_id)
);

CREATE INDEX IF NOT EXISTS ix_oauth_accounts_user_id ON oauth_accounts (user_id);

-- ── email_verifications ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_verifications (
    id         SERIAL                     PRIMARY KEY,
    user_id    INTEGER                    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    email_verification_purpose NOT NULL,
    token_hash VARCHAR(64)                NOT NULL,
    expires_at TIMESTAMPTZ                NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ                NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_email_verifications_user_id    ON email_verifications (user_id);
CREATE INDEX IF NOT EXISTS ix_email_verifications_token_hash ON email_verifications (token_hash);

-- ── connections ───────────────────────────────────────────────────────────────
-- 26 columns matching the Go store's connFullColumns SELECT and INSERT exactly.
-- origin_hosts / geoip_denied_countries are JSON (not JSONB) — matching alembic's
-- sa.JSON() which emits the plain json type in PostgreSQL.

CREATE TABLE IF NOT EXISTS connections (
    id                    SERIAL           PRIMARY KEY,
    tenant_id             INTEGER          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                  VARCHAR(128)     NOT NULL,
    domain                VARCHAR(253)     NOT NULL UNIQUE,
    origin_hosts          JSON             NOT NULL DEFAULT '[]',
    origin_port           INTEGER          NOT NULL DEFAULT 443,
    origin_tls_mode       origin_tls_mode  NOT NULL DEFAULT 'strict',
    verify_token          VARCHAR(64)      NOT NULL DEFAULT '',
    verified_at           TIMESTAMPTZ,
    status                connection_status NOT NULL DEFAULT 'pending_verification',
    status_detail         TEXT,
    acme_retry_count      INTEGER          NOT NULL DEFAULT 0,
    acme_next_retry_at    TIMESTAMPTZ,
    next_poll_at          TIMESTAMPTZ,
    dns_ttl_seconds       INTEGER          NOT NULL DEFAULT 60,
    last_checked_at       TIMESTAMPTZ,
    http_versions         VARCHAR(32)      NOT NULL DEFAULT 'h1,h2',
    compression_algo      VARCHAR(16)      NOT NULL DEFAULT 'auto',
    enabled               BOOLEAN          NOT NULL DEFAULT TRUE,
    modsec_state          modsec_state     NOT NULL DEFAULT 'detection_only',
    geoip_denied_countries JSON            NOT NULL DEFAULT '[]',
    crowdsec_active       BOOLEAN          NOT NULL DEFAULT TRUE,
    ssl_cert_path         VARCHAR(512),
    ssl_key_path          VARCHAR(512),
    created_at            TIMESTAMPTZ      NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ      NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_connections_domain ON connections (domain);
CREATE        INDEX IF NOT EXISTS ix_connections_tenant_id ON connections (tenant_id);
