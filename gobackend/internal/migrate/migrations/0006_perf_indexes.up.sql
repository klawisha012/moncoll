-- 0006_perf_indexes.up.sql — measurement-driven indexes for two hot queries
-- that currently sequential-scan.
--
-- The "obvious" lookup columns (users.email, *.tenant_id, *.user_id FKs,
-- email_verifications.token_hash, connections.domain) are ALREADY indexed by
-- 0001–0003, so they are intentionally NOT repeated here (no speculative
-- indexes). These two are the genuine gaps:
--
-- 1. invitations.token_hash — GetInvitationByToken (accept-invite flow) runs
--      WHERE token_hash = $1 AND status = 'pending' AND expires_at > now()
--    with no supporting index. A partial index over only pending invitations
--    matches the predicate and stays tiny (accepted/expired rows are excluded).
--
-- 2. connections poller — ListConnectionsForPoll runs every poll interval:
--      WHERE enabled AND status IN (<active set>)
--        AND (next_poll_at IS NULL OR next_poll_at <= now())
--    A partial index on next_poll_at over only the pollable rows keeps the
--    poller cheap as the table fills with 'active' connections (which drop out
--    of the active set and out of the index).
--
-- Both tables are small and the DDL is additive (CREATE INDEX IF NOT EXISTS),
-- so no CONCURRENTLY build is needed (and CONCURRENTLY cannot run inside the
-- migration transaction anyway). Confirm impact with EXPLAIN ANALYZE on
-- production-shaped data.

CREATE INDEX IF NOT EXISTS ix_invitations_token_hash
    ON invitations (token_hash)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS ix_connections_poll
    ON connections (next_poll_at)
    WHERE enabled = true
      AND status IN ('pending_verification', 'pending_dns', 'provisioning_cert', 'error');
