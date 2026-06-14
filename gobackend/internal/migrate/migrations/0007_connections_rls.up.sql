-- 0007_connections_rls.up.sql — Row-Level Security on connections as
-- defense-in-depth beneath the app-level WHERE tenant_id filters.
--
-- Tenant-isolation inventory (audit)
-- ----------------------------------
-- tenant-scoped, single-tenant ownership:
--   connections  → RLS target below. Every client method scopes by tenant_id
--                  (ListConnectionsFull / GetConnectionFull / GetConnectionForTenant
--                  / UpdateConnection / DeleteConnection / UpdateSecurity /
--                  UpdateProbeState / TenantHasVerifiedZone). System/admin methods
--                  (ListConnections, GetConnectionInternal, ListConnectionsForPoll,
--                  UpdatePollerState) are intentionally cross-tenant.
-- tenant-scoped but cross-tenant access patterns (app-level isolation only):
--   memberships  → queried by user_id (a user's tenants span tenants) and by
--                  tenant_id (members list). Not a clean single-tenant RLS target.
--   invitations  → looked up by token_hash (pre-membership accept) and email.
-- global (correctly not tenant-scoped):
--   tenants, users (login by email; admins have NULL tenant_id), oauth_accounts
--   (by user_id), email_verifications (by user_id / token_hash).
--
-- Policy semantics
-- ----------------
-- Permissive backstop: with NO tenant context set (system / admin / poller
-- queries, and any superuser connection), all rows are visible — existing
-- behaviour is preserved. When the app sets app.tenant_id (client request paths,
-- via Store.runInTenantTx → SET LOCAL), only that tenant's rows are visible /
-- writable, even if a query forgets its WHERE tenant_id.
--
-- Activation note: a Postgres SUPERUSER (and BYPASSRLS roles) ALWAYS bypass RLS,
-- regardless of FORCE. To make this policy actually enforce in production, the
-- application must connect as a non-superuser, non-BYPASSRLS role, e.g.:
--     CREATE ROLE waf_app LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;
--     GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO waf_app;
--     GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO waf_app;
-- and point WAF_POSTGRES_DSN at it. The policy + SET LOCAL mechanism land here;
-- the role switch is the ops activation step.

ALTER TABLE connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE connections FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS connections_tenant_isolation ON connections;
CREATE POLICY connections_tenant_isolation ON connections
    USING (
        NULLIF(current_setting('app.tenant_id', true), '') IS NULL
        OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::integer
    )
    WITH CHECK (
        NULLIF(current_setting('app.tenant_id', true), '') IS NULL
        OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::integer
    );
