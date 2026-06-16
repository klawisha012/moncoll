-- 0009_origin_tls_off.up.sql — allow proxying to plain-HTTP origins.
-- Adds 'off' to the origin_tls_mode enum: the connection generator emits
-- proxy_pass http:// (no TLS to origin) for this value. Used by the WAF
-- self-connection, whose origin (the frontend) speaks plain HTTP on :3000.
ALTER TYPE origin_tls_mode ADD VALUE IF NOT EXISTS 'off';
