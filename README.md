# 🛡️ WAF: Modern Multi-Tenant Web Application Firewall Edge

A high-performance, secure-by-default Web Application Firewall (WAF) edge service designed to act as a reverse proxy for tenant-owned origin servers. It integrates **Angie** (a modern Nginx fork) with **FastAPI**, **SolidJS**, **CrowdSec** (for tenant-isolated dynamic threat blocking), and **ClickHouse** (for real-time logging and analytics).

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
./scripts/generate-env.sh

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
   ./scripts/create-admin.sh --email you@yourdomain.com
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

