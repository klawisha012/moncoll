#!/usr/bin/env bash
#
# WAF — quick-start installer for macOS / Linux
#
#   curl -fsSL https://raw.githubusercontent.com/Cringeneers/demo-repository/main/scripts/install/install.sh | bash
#
# Optional environment variables:
#   WAF_REPO     git URL to clone           (default: https://github.com/Cringeneers/demo-repository.git)
#   WAF_DIR      target directory            (default: ./waf)
#   WAF_BRANCH   branch to check out         (default: main)
#   WAF_NO_START set to 1 to skip the build  (default: unset)
#
set -euo pipefail

WAF_REPO="${WAF_REPO:-https://github.com/Cringeneers/demo-repository.git}"
WAF_DIR="${WAF_DIR:-waf}"
WAF_BRANCH="${WAF_BRANCH:-main}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { printf "${GREEN}[*]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
step()  { printf "${BLUE}==>${NC} %s\n" "$*"; }
error() { printf "${RED}[x]${NC} %s\n" "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || error "'$1' is required but not installed. $2"
}

echo "==============================================="
echo "   WAF — Web Application Firewall Edge"
echo "   Quick-start installer (macOS / Linux)"
echo "==============================================="
echo

# --- 1. Prerequisites -------------------------------------------------------
step "Checking prerequisites"
need git "Install it from https://git-scm.com/downloads"
need docker "Install Docker Desktop / Engine from https://docs.docker.com/get-docker/"

if ! docker info >/dev/null 2>&1; then
  error "Docker daemon is not running. Start Docker and re-run this installer."
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  error "Docker Compose not found. Install the Compose plugin: https://docs.docker.com/compose/install/"
fi
info "git, docker and '${COMPOSE}' are available"

# --- 2. Clone --------------------------------------------------------------
step "Fetching the repository"
if [ -d "${WAF_DIR}/.git" ]; then
  info "'${WAF_DIR}' already exists — pulling latest on '${WAF_BRANCH}'"
  git -C "${WAF_DIR}" fetch --depth 1 origin "${WAF_BRANCH}"
  git -C "${WAF_DIR}" checkout "${WAF_BRANCH}"
  git -C "${WAF_DIR}" pull --ff-only origin "${WAF_BRANCH}"
elif [ -e "${WAF_DIR}" ]; then
  error "'${WAF_DIR}' exists but is not a git repository. Remove it or set WAF_DIR=<other>."
else
  git clone --branch "${WAF_BRANCH}" --depth 1 "${WAF_REPO}" "${WAF_DIR}"
fi
cd "${WAF_DIR}"

# --- 3. Environment --------------------------------------------------------
step "Generating environment variables and keys"
if [ -f .env ]; then
  warn ".env already exists — keeping it (delete it and re-run to regenerate)"
elif [ -x ./scripts/generate-env.sh ]; then
  ./scripts/generate-env.sh
else
  bash ./scripts/generate-env.sh
fi

# --- 4. Build & start ------------------------------------------------------
if [ "${WAF_NO_START:-}" = "1" ]; then
  warn "WAF_NO_START=1 set — skipping 'docker compose up'"
else
  step "Building and starting the stack (this may take a few minutes)"
  ${COMPOSE} up -d --build
fi

# --- 5. Next steps ---------------------------------------------------------
echo
info "WAF is up. Next steps:"
cat <<EOF

  1. Open ${WAF_DIR}/.env and set WAF_PUBLIC_BASE_URL
     (use http://localhost:5173 for local development).

  2. Create the first administrator:
       cd ${WAF_DIR}
       ./scripts/create-admin.sh --email you@yourdomain.com

  3. Open the control panel and register your TOTP (2FA) app.

  Useful commands:
     ${COMPOSE} ps            # service status
     ${COMPOSE} logs -f       # follow logs
     ${COMPOSE} down          # stop the stack

EOF
