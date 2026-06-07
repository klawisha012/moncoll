-- 0003_invitations.up.sql — team invitations by email (token + TTL).

DO $$ BEGIN
    CREATE TYPE invitation_status AS ENUM ('pending', 'accepted', 'revoked', 'expired');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS invitations (
    id                 SERIAL            PRIMARY KEY,
    tenant_id          INTEGER           NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email              VARCHAR(254)      NOT NULL,
    role               membership_role   NOT NULL,
    token_hash         VARCHAR(64)       NOT NULL,
    invited_by_user_id INTEGER           NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status             invitation_status NOT NULL DEFAULT 'pending',
    expires_at         TIMESTAMPTZ       NOT NULL,
    accepted_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ       NOT NULL DEFAULT now(),
    CONSTRAINT invitations_role_not_owner CHECK (role IN ('admin', 'member'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_invitations_pending
    ON invitations(tenant_id, email) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS ix_invitations_email_pending
    ON invitations(email) WHERE status = 'pending';
