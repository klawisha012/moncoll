# 🛡️ WAF: Modern Multi-Tenant Web Application Firewall Edge

A high-performance, secure-by-default Web Application Firewall (WAF) edge service designed to act as a reverse proxy for tenant-owned origin servers. It integrates **Angie** (a modern Nginx fork) with **FastAPI**, **SolidJS**, **CrowdSec** (for tenant-isolated dynamic threat blocking), and **ClickHouse** (for real-time logging and analytics).

> 🌐 **Languages:** **English** · [Русский](./i18n/README.ru.md)

---

## 🛠️ Quick Start

### 0. One-line install (recommended)

Clones the repo, generates a fresh `.env`, and brings the stack up with Docker Compose.

**macOS / Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/Cringeneers/demo-repository/main/scripts/install/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/Cringeneers/demo-repository/main/scripts/install/install.ps1 | iex
```

> Requires `git` and Docker (with Compose). On Windows, `bash` (Git Bash or WSL) is needed for the env-generation step. After it finishes, jump to [step 2](#2-provision-the-admin-account).

### 1. Clone & Spin up Local Stack

To get a local development environment running with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/Cringeneers/demo-repository.git waf
cd ./waf

# Generate fresh environment variables and keys
./scripts/setup/generate-env.sh

# Build and start all services
docker compose up -d --build
```

### 2. Provision the Admin Account

1. Edit the newly created `.env` file and set `WAF_PUBLIC_BASE_URL` to your domain or `http://localhost:5173` (for local development).
2. Run database migrations:
   ```bash
   docker compose exec backend alembic upgrade head
   ```
3. Create the initial administrative account:
   ```bash
   ./scripts/ops/create-admin.sh --email you@yourdomain.com
   ```
4. Access the control panel, log in, and register your **TOTP (2FA)** application to unlock administrative endpoints.

---

## ⚙️ Optional Integrations

*   **Cloudflare Turnstile (Anti-Bot):** Configure `WAF_TURNSTILE_SITE_KEY` and `WAF_TURNSTILE_SECRET_KEY` in `.env` to enforce anti-bot validation on login and registration pages. If omitted, captcha validation is automatically skipped.
*   **SMTP (Email Delivery):** Set `WAF_SMTP_HOST`, `WAF_SMTP_PORT`, `WAF_SMTP_USERNAME`, `WAF_SMTP_PASSWORD`, and `WAF_SMTP_FROM_EMAIL`. In development, if SMTP configurations are missing, all transactional emails (verification, password resets) are printed to the backend's stdout.
*   **Social Authentication (OAuth):** 
    *   **Google:** Configure `WAF_OAUTH_GOOGLE_CLIENT_ID` and `WAF_OAUTH_GOOGLE_CLIENT_SECRET`.
    *   **GitHub:** Configure `WAF_OAUTH_GITHUB_CLIENT_ID` and `WAF_OAUTH_GITHUB_CLIENT_SECRET`.
    *   *Callback URL structure:* `${WAF_PUBLIC_BASE_URL}/api/auth/oauth/[provider]/callback`.

---

## 📈 Horizontal Scaling (S3 mode)

By default (`WAF_STORAGE_BACKEND=local`) the backend writes per-tenant config, TLS
material and ban/registry state to a local volume and reloads a single Angie via
`docker exec` — **single-node behaviour is byte-for-byte unchanged**.

To run multiple backend replicas and multiple edge (Angie) nodes, switch the
shared source of truth to S3-compatible object storage (MinIO in dev):

```bash
# Strong creds are written by scripts/setup/generate-env.sh; set in .env:
#   WAF_STORAGE_BACKEND=s3
#   WAF_S3_ENDPOINT=minio:9000  WAF_S3_BUCKET=waf-state
#   WAF_S3_ACCESS_KEY=...  WAF_S3_SECRET_KEY=...           # backend RW
#   WAF_S3_EDGE_ACCESS_KEY=...  WAF_S3_EDGE_SECRET_KEY=... # edge RO
docker compose --profile s3 up -d
```

**How it works.** Every backend replica writes objects to S3 and then publishes a
**generation manifest** — the single atomic commit point. Each edge node runs an
`edge-sync` sidecar that polls the manifest (`WAF_EDGE_SYNC_INTERVAL`, default 10s),
materialises changed objects to the local Angie tree, validates with `angie -t`,
and reloads its own Angie. A tenant change converges on all edges within ~30s.

*   **Atomicity:** edges only apply a fully-downloaded generation; a half-written
    set is never served.
*   **Consistency:** concurrent backend publishes are resolved by a compare-and-set
    on the manifest (a Postgres advisory lock reduces contention); no lost updates.
*   **Resilience:** if S3 is unreachable the edge holds **last-known-good**; a fresh
    node cold-syncs from generation 0 with no operator action.
*   **Security:** scoped MinIO users (backend read-write, edge read-only); TLS key
    objects are written `sensitive` (SSE at rest). For prod, enable MinIO TLS and
    set `WAF_S3_USE_TLS=true` so credentials/keys never cross the wire in clear.

**Observability.** The backend exposes `state_published_generation`; each sidecar
exposes `edge_sync_applied_generation`, `edge_sync_lag_seconds`,
`edge_sync_errors_total` on `:9101`. Node lag = `published − applied`; Prometheus
alerts (`EdgeConvergenceLag`, `EdgeSyncErrors`) and a Grafana convergence dashboard
ship under `docker/prometheus/rules/` and `docker/grafana/provisioning/`.

**Scaling out.** For real multi-node 1:1 edge↔sidecar pairing use the Kubernetes
manifest (`k8s/angie.yaml`, sidecar in the Angie pod). In docker-compose the
sidecar pairs with `waf-angie-1` at scale=1 (Compose can't express pod-style
pairing); use k8s for a multi-edge demo.

