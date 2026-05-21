#!/bin/bash
# Register the Angie bouncer with CrowdSec using the pre-generated API key
# from .env (CROWDSEC_BOUNCER_KEY, written by scripts/generate-env.sh).
#
# Idempotent: re-running deletes any prior bouncer of the same name and
# re-registers with the current .env key, so a key rotation flow is
# simply `bash scripts/generate-env.sh && bash scripts/init-crowdsec.sh
# && docker compose restart angie`.

set -euo pipefail

if [ ! -f .env ]; then
  echo "ERROR: .env not found — run scripts/generate-env.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
. ./.env
set +a

if [ -z "${CROWDSEC_BOUNCER_KEY:-}" ]; then
  echo "ERROR: CROWDSEC_BOUNCER_KEY missing from .env — regenerate with scripts/generate-env.sh" >&2
  exit 1
fi

echo "Waiting for CrowdSec container to be ready..."
until docker exec crowdsec cscli version > /dev/null 2>&1; do
  echo "  CrowdSec not ready yet, retrying in 2s..."
  sleep 2
done

# Replace any prior registration (key may have rotated since last run).
# `bouncers delete` exits non-zero if the bouncer doesn't exist; swallow that
# so first-run installs don't fail.
docker exec crowdsec cscli bouncers delete angie-bouncer >/dev/null 2>&1 || true

echo "Registering angie-bouncer with key from .env..."
docker exec crowdsec cscli bouncers add angie-bouncer --key "$CROWDSEC_BOUNCER_KEY" >/dev/null

echo "Done. The Angie bouncer config (configs/angie/bouncers/crowdsec-nginx-bouncer.conf)"
echo "already carries this key — restart Angie to pick it up:"
echo "  docker compose restart angie"
