-- 0002_memberships.up.sql — many-to-many team membership.
-- The existing tenant_role enum is ('owner','member'); teams add an 'admin'
-- tier, so a dedicated enum is used rather than altering tenant_role.

DO $$ BEGIN
    CREATE TYPE membership_role AS ENUM ('owner', 'admin', 'member');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS memberships (
    id         SERIAL          PRIMARY KEY,
    tenant_id  INTEGER         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    INTEGER         NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    role       membership_role NOT NULL,
    created_at TIMESTAMPTZ     NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS memberships_user_id_idx ON memberships(user_id);

INSERT INTO memberships (tenant_id, user_id, role)
SELECT tenant_id, id, COALESCE(tenant_role::text, 'owner')::membership_role
FROM users
WHERE tenant_id IS NOT NULL
ON CONFLICT (tenant_id, user_id) DO NOTHING;
