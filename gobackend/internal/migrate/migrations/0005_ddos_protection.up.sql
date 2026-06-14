-- Per-connection anti-DDoS toggle. When true, Angie enforces limit_req/limit_conn
-- for the connection. Idempotent (IF NOT EXISTS) to match the 0001 baseline style
-- so it is safe on both fresh and already-provisioned databases.
ALTER TABLE connections
    ADD COLUMN IF NOT EXISTS ddos_protection boolean NOT NULL DEFAULT false;
