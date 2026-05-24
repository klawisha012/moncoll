#!/bin/bash
# Generates .env with random secrets. Re-running OVERWRITES .env — back up
# first if you've already rotated passwords by hand.
#
# Why this script exists: docker-compose.yml requires POSTGRES_PASSWORD
# and CENTRIFUGO secrets via the `:?...` syntax. Without them the stack
# refuses to boot — intentional, so we never ship weak fallbacks.
# See .gstack/security-reports/.

set -euo pipefail

CLICKHOUSE_USER="user_$(openssl rand -hex 4)"
CLICKHOUSE_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
# JWT signing key for backend session cookies. Stored in .env so it survives
# backend restarts — otherwise security.py falls back to an ephemeral secret
# and every restart invalidates all active sessions, forcing re-login.
WAF_JWT_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)
WAF_PASETO_KEY=$(openssl rand -hex 32)
# CrowdSec bouncer API key. Pre-generated here (instead of letting
# `cscli bouncers add` allocate one) so the value lives only in .env
# (gitignored, mode 0600) and is injected at bouncer registration via
# `cscli bouncers add --key`. The Angie bouncer config is rendered from
# crowdsec-nginx-bouncer.conf.template at the end of this script.
CROWDSEC_BOUNCER_KEY=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 48)
# Centrifugo secrets: token_hmac_secret signs short-lived client JWTs
# (backend → centrifuge-js); api_key authenticates server-side HTTP
# publish calls (backend → Centrifugo /api/publish).
CENTRIFUGO_TOKEN_HMAC_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)
CENTRIFUGO_API_KEY=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 48)
# Host docker group GID — backend container joins this group at runtime
# to access /var/run/docker.sock without running as root. Falls back to
# 999 (most Linux distros) when getent isn't available (eg. macOS hosts).
DOCKER_GID="$(getent group docker 2>/dev/null | cut -d: -f3 || echo 999)"

cat > .env << EOF
# Angie
ANGIE_BINARY=angie
ANGIE_CONFIG_TEMPLATE=/etc/angie/angie.conf.t
ANGIE_ERROR_LOG_SEVERITY=notice
ANGIE_FEATURE_RELOAD=on
ANGIE_FEATURE_TEMPLATE=on
ANGIE_LOAD_MODULES="modsecurity,geoip2"
ANGIE_LOAD_MODSECURITY=on
ANGIE_LOAD_GEOIP2=on
ANGIE_PID_FILE=/run/angie/angie.pid
ANGIE_WORKER_CONNECTIONS=65536
ANGIE_WORKER_RLIMIT_NOFILE=65536

# Vector
VECTOR_CONFIG=/etc/vector/vector.yaml
VECTOR_LOG=info
VECTOR_LOG_FORMAT=text
VECTOR_COLOR=auto
VECTOR_WATCH_CONFIG=false
VECTOR_REQUIRE_HEALTHY=false
VECTOR_GRACEFUL_SHUTDOWN_LIMIT_SECS=60
VECTOR_INTERNAL_LOG_RATE_LIMIT=10
VECTOR_WATCH_CONFIG_METHOD=recommended
VECTOR_WATCH_CONFIG_POLL_INTERVAL_SECONDS=60
VECTOR_STRICT_ENV_VARS=true
VECTOR_ALLOW_EMPTY_CONFIG=false
VECTOR_OPENSSL_NO_PROBE=false

# ClickHouse
CLICKHOUSE_ENDPOINT=http://clickhouse:8123
CLICKHOUSE_USER=$CLICKHOUSE_USER
CLICKHOUSE_PASSWORD=$CLICKHOUSE_PASSWORD
CLICKHOUSE_DB=logs

# PostgreSQL (backend metadata: users, connections)
POSTGRES_USER=waf
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=waf

# Docker GID - backend container joins this host group to use docker.sock
# without running as root.
DOCKER_GID=$DOCKER_GID

# Backend JWT signing key (HS256). Stable across restarts so sessions survive.
WAF_JWT_SECRET=$WAF_JWT_SECRET

# Email registered with Let's Encrypt for ACME account + expiry notifications.
# Override on regeneration if running under a different operator.
ACME_EMAIL=zwarder.main@gmail.com

# CrowdSec bouncer API key — consumed by scripts/init-crowdsec.sh
# (cscli bouncers add --key) and by the Angie bouncer config
# rendered below from crowdsec-nginx-bouncer.conf.template.
CROWDSEC_BOUNCER_KEY=$CROWDSEC_BOUNCER_KEY

# Centrifugo — real-time fan-out for dashboard live updates.
# token_hmac_secret: backend signs short-lived JWTs that centrifuge-js
#   sends on connect; Centrifugo verifies signature with the same secret.
# api_key: protects Centrifugo's server HTTP API. Backend sends
#   `Authorization: apikey <KEY>` when publishing aggregated deltas.
CENTRIFUGO_TOKEN_HMAC_SECRET=$CENTRIFUGO_TOKEN_HMAC_SECRET
CENTRIFUGO_API_KEY=$CENTRIFUGO_API_KEY
CENTRIFUGO_API_URL=http://centrifugo:8000/api

# Redis URL used by backend's realtime consumer (Vector pushes raw geoip
# events to channel `attacks:raw`, consumer aggregates 500ms batches and
# publishes deltas to Centrifugo). Same Redis as Centrifugo engine.
REDIS_URL=redis://redis:6379/0

# ── SaaS auth ─────────────────────────────────────────────────────────────
# PASETO session signing key (required). Generated fresh by generate-env.sh.
WAF_PASETO_KEY=$WAF_PASETO_KEY

# Public base URL of this WAF instance (required for OAuth redirect URIs and
# email links). Change to your real domain before going to production.
WAF_PUBLIC_BASE_URL=https://CHANGEME

# Set to true in production (HTTPS). Dev stack runs on HTTP so leave false.
WAF_COOKIE_SECURE=false

# ── Cloudflare Turnstile (optional — anti-bot on signup/login) ─────────────
# Leave blank to run without captcha (dev mode).
# Get keys at: https://dash.cloudflare.com/?to=/:account/turnstile
WAF_TURNSTILE_SITE_KEY=
WAF_TURNSTILE_SECRET_KEY=

# ── SMTP email transport (optional) ───────────────────────────────────────
# Without SMTP, verification/reset emails are logged to backend stdout.
WAF_SMTP_HOST=
WAF_SMTP_PORT=587
WAF_SMTP_USERNAME=
WAF_SMTP_PASSWORD=
WAF_SMTP_FROM_EMAIL=
WAF_SMTP_FROM_NAME=WAF Platform

# ── Google OAuth (optional) ────────────────────────────────────────────────
# Create credentials at: https://console.cloud.google.com/apis/credentials
# Redirect URI: \${WAF_PUBLIC_BASE_URL}/api/auth/oauth/google/callback
WAF_OAUTH_GOOGLE_CLIENT_ID=
WAF_OAUTH_GOOGLE_CLIENT_SECRET=
WAF_OAUTH_GOOGLE_REDIRECT_URI=

# ── GitHub OAuth (optional) ────────────────────────────────────────────────
# Create credentials at: https://github.com/settings/developers
# Redirect URI: \${WAF_PUBLIC_BASE_URL}/api/auth/oauth/github/callback
WAF_OAUTH_GITHUB_CLIENT_ID=
WAF_OAUTH_GITHUB_CLIENT_SECRET=
WAF_OAUTH_GITHUB_REDIRECT_URI=

EOF

# 0600 so other users on the host can't read the secrets.
chmod 600 .env

# Re-stamp configs/clickhouse/users.d/default-user.xml so the <user_*> tag
# matches the freshly-rolled $CLICKHOUSE_USER. This file replaces the one
# that clickhouse/clickhouse-server's entrypoint would normally auto-write
# (we set CLICKHOUSE_SKIP_USER_SETUP=1 in docker-compose.yml so entrypoint
# leaves ours alone).
mkdir -p configs/clickhouse/users.d
cat > configs/clickhouse/users.d/default-user.xml << EOF
<!--
  AUTO-GENERATED by scripts/generate-env.sh. Do not hand-edit; the
  <user_*> tag and <password> must match .env. Re-run generate-env.sh
  to regenerate after rolling credentials.
-->
<clickhouse>
  <users>
    <default remove="remove"></default>

    <$CLICKHOUSE_USER>
      <profile>default</profile>
      <networks>
        <ip>::/0</ip>
      </networks>
      <password><![CDATA[$CLICKHOUSE_PASSWORD]]></password>
      <quota>default</quota>
      <grants>
        <query>GRANT ALL ON *.*</query>
      </grants>
    </$CLICKHOUSE_USER>
  </users>
</clickhouse>
EOF

echo "Generated .env file (mode 0600)"
echo "  CLICKHOUSE_USER=$CLICKHOUSE_USER"
echo "  (POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD, CROWDSEC_BOUNCER_KEY, WAF_PASETO_KEY - see .env)"
echo "  DOCKER_GID=$DOCKER_GID"
echo "  Wrote configs/clickhouse/users.d/default-user.xml for $CLICKHOUSE_USER"
echo "  WAF_PUBLIC_BASE_URL=https://CHANGEME  ← edit this in .env before production"

# Render CrowdSec bouncer config from template. The .conf is gitignored;
# the .template is the canonical, key-free version that lives in git.
# Run scripts/init-crowdsec.sh after `docker compose up` to register
# the bouncer with this key inside the running CrowdSec container.
BOUNCER_TEMPLATE="configs/angie/bouncers/crowdsec-nginx-bouncer.conf.template"
BOUNCER_OUT="configs/angie/bouncers/crowdsec-nginx-bouncer.conf"
if [ -f "$BOUNCER_TEMPLATE" ]; then
  sed "s|__CROWDSEC_BOUNCER_KEY__|$CROWDSEC_BOUNCER_KEY|g" "$BOUNCER_TEMPLATE" > "$BOUNCER_OUT"
  chmod 600 "$BOUNCER_OUT"
  echo "  Wrote $BOUNCER_OUT from template (mode 0600)"
else
  echo "  WARNING: $BOUNCER_TEMPLATE missing — bouncer config not regenerated"
fi
