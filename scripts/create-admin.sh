#!/usr/bin/env bash
# Create a WAF platform admin user inside the running backend container.
# Usage: ./scripts/create-admin.sh --email admin@example.com [--password secret]
set -euo pipefail
exec docker compose exec backend python -m src.cli create-admin "$@"
