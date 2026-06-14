-- 0006_perf_indexes.down.sql — drop the performance indexes.
DROP INDEX IF EXISTS ix_connections_poll;
DROP INDEX IF EXISTS ix_invitations_token_hash;
