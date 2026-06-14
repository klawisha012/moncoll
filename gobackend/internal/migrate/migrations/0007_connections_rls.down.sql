-- 0007_connections_rls.down.sql — remove RLS from connections.
DROP POLICY IF EXISTS connections_tenant_isolation ON connections;
ALTER TABLE connections NO FORCE ROW LEVEL SECURITY;
ALTER TABLE connections DISABLE ROW LEVEL SECURITY;
