# WAF

## Quick start

```bash
git clone https://github.com/Cringeneers/demo-repository.git waf
cd ./waf
./scripts/generate-env.sh
docker compose up -d --build
```

## Provisioning a new instance

1. `cp .env.example .env` and edit — or run `./scripts/generate-env.sh` to generate fresh secrets
2. Edit `WAF_PUBLIC_BASE_URL` in `.env` to your real HTTPS domain
3. `docker compose up -d --build`
4. `docker compose exec backend alembic upgrade head`
5. Create the first admin: `./scripts/create-admin.sh --email you@yourdomain.com`
6. Browse to the panel, log in — you will be required to enrol TOTP before accessing admin pages

### Optional integrations

- **Cloudflare Turnstile** (anti-bot on signup/login): set `WAF_TURNSTILE_SITE_KEY` + `WAF_TURNSTILE_SECRET_KEY`. Without these, captcha is skipped (suitable for dev / private instances).
- **SMTP** (email verification, password reset): set `WAF_SMTP_HOST`, `WAF_SMTP_PORT`, `WAF_SMTP_USERNAME`, `WAF_SMTP_PASSWORD`, `WAF_SMTP_FROM_EMAIL`. Without SMTP, verification and reset emails are logged to backend stdout — useful in dev mode, not suitable for production.
- **Google OAuth**: set `WAF_OAUTH_GOOGLE_CLIENT_ID`, `WAF_OAUTH_GOOGLE_CLIENT_SECRET`, `WAF_OAUTH_GOOGLE_REDIRECT_URI`. Redirect URI format: `${WAF_PUBLIC_BASE_URL}/api/auth/oauth/google/callback`.
- **GitHub OAuth**: set `WAF_OAUTH_GITHUB_CLIENT_ID`, `WAF_OAUTH_GITHUB_CLIENT_SECRET`, `WAF_OAUTH_GITHUB_REDIRECT_URI`. Redirect URI format: `${WAF_PUBLIC_BASE_URL}/api/auth/oauth/github/callback`.

## Deploy

```bash
./deploy.sh
```

## Connections

WAF runs as a reverse-proxy edge in front of customer-owned origin servers.
Users connect their websites by **changing DNS** — the platform never hosts
the site, never executes the customer's code, never mounts their volumes.

Full design: [docs/superpowers/specs/2026-05-22-connections-domain-only-design.md](docs/superpowers/specs/2026-05-22-connections-domain-only-design.md).
Approved wizard mockup: [docs/wireframes/connections-wizard/index.html](docs/wireframes/connections-wizard/index.html).

Onboarding (3 steps, Inset-Modal wizard in the admin UI):

1. **Domain** — user enters `acme.com` + name + Origin TLS mode (Strict or
   Lenient). Backend resolves the current A record, verifies the origin is
   reachable over HTTPS, and rejects any private/reserved/link-local
   address (RFC 1918, AWS IMDS `169.254.169.254`, IPv6 ULA, etc.).
2. **TXT verify** — user adds `_waf-verify.acme.com TXT <token>` to their
   DNS. Backend polls every 10s; on match, advances to step 3.
3. **DNS switch** — user points the `A` record of `acme.com` at
   `WAF_EDGE_IPV4`. The background poller detects the flip, triggers an
   ACME HTTP-01 cert issuance with exponential backoff (1m / 5m / 30m /
   2h / 12h ±20% jitter, MAX_RETRIES=5), and the connection enters
   `active` state.

State machine: `pending_verification` → `pending_dns` → `provisioning_cert`
→ `active` (or → `error` after exhausted retries; manual `/probe` clears it).

### Security model

The previous 4-mode source_type machinery (nginx_config / static_generate /
container / docker_compose) was removed in the 2026-05-22 rewrite. The
`admin` role no longer accepts arbitrary `docker-compose.yml` bodies — the
host-root-equivalent threat vector that came with that feature is gone.

What protects the platform now:

- All connection endpoints (`/api/connections/*`) are gated by
  `require_admin`. See [`backend/src/main.py`](backend/src/main.py).
- Every IP the backend ever resolves passes through `is_blocked_ip` in
  [`backend/src/connections/dns.py`](backend/src/connections/dns.py) before
  it touches an HTTP probe or an Angie `proxy_pass`. RFC 1918, loopback,
  link-local, multicast, reserved, IPv4 unspecified, and IPv6 ULA all
  reject with `422`. Closes the AWS-IMDS-style exfil vector.
- Domain ownership is proven via a TXT record (`_waf-verify.<domain>`)
  with a random 24-byte URL-safe token before the connection becomes
  active. Multi-tenant `user_id` FK on `connections` table means one
  admin cannot claim another's domain (decision 1B in the design spec).
- Origin TLS defaults to **strict** (`proxy_ssl_verify on` against the
  system CA bundle); operators can opt individual origins down to
  `lenient` for self-signed back-ends without losing channel encryption.

#### What you must NOT do

- Do **not** expose the WAF admin panel to untrusted networks. Put it
  behind your own VPN or IP allow-list.
- Do **not** loosen the `is_blocked_ip` deny-list without a security review.
- Do **not** disable TXT verification — the multi-tenant security model
  relies on it.

### Other notable security defaults

- Authentication: cookie-based sessions; auth/RBAC enforced in FastAPI
  dependencies (`require_password_changed`, `require_admin`).
- All dashboard / CrowdSec endpoints validate query parameters via
  Pydantic ranges (`hours: float = Query(..., ge=0.0167, le=8760)`,
  `connection_id: int = Query(..., ge=1)`).
- ClickHouse queries that interpolate per-domain filters strip `'`, `\`
  and `\x00` from domain names before building the SQL fragment
  (`_quote_domains` in [`backend/src/dashboard/service.py`](backend/src/dashboard/service.py)).

## Tests

```bash
# Unit + integration (no docker needed)
PYTHONPATH=backend pytest -m "unit or integration" tests/unit tests/integration -v

# Full stack e2e (requires the docker-compose stack running)
pytest -m e2e tests/e2e -v
```
