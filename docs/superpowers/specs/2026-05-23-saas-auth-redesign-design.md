# SaaS Auth Redesign

**Date:** 2026-05-23
**Status:** Draft (pending user review)
**Branch:** `main` (currently clean)

## 1. Goal

Replace the current `admin | viewer` single-tenant auth model with a SaaS auth model that supports:

- Two platform roles: `admin` (platform operator) and `client` (end customer).
- Multi-tenant data isolation: each client tenant has its own connections, configs, ModSecurity rules, CrowdSec data, etc.
- Self-service signup with email verification.
- OAuth login/signup via Google and GitHub, plus password login.
- Cloudflare Turnstile captcha on every anonymous form.
- TOTP-based 2FA, mandatory for admin role, optional for clients.
- PASETO v4.local session cookies (migrating off JWT).

## 2. Non-goals (deferred to follow-up specs)

- Plans / billing / Stripe integration. All tenants are free in v1.
- Rate limiting / brute-force lockout. Captcha is the only anti-bot mechanism in v1.
- Tenant-account deletion (right-to-be-forgotten). Admin can still delete tenants from the Clients page; tenant owners cannot delete their own tenant in v1.
- OAuth account-linking. A user signed up via password and another signed up via GitHub with the same email remain two unrelated accounts.
- Server-side session revocation (logout-all-devices). PASETO is stateless; revoke requires session table — out of scope.
- Postgres row-level security; schema-per-tenant. v1 uses service-layer filtering.

## 3. Data isolation model

Service-level filtering, enforced in Python.

- Each tenant-scoped resource (`connections`, ModSecurity rule sets, CrowdSec data, configs) gets a non-null `tenant_id FK tenants.id`.
- Every service function that reads or writes such a resource accepts an explicit `tenant: Tenant` argument and filters every SQL query by `tenant_id == tenant.id`.
- Tenant identity is injected at the router boundary via the `current_tenant` FastAPI dependency, which is itself derived from the authenticated user.
- A pytest guard test (AST-based) walks `backend/src/*/service.py` and fails the build if any `select(Resource)` against a tenant-scoped model lacks a `where(...tenant_id == ...)` clause.
- A suite of integration tests (Section 9) creates two tenants and verifies, endpoint by endpoint, that tenant A cannot read or mutate tenant B's resources.

Filesystem-level config isolation is bolted on top:

```
/var/lib/waf/
  tenants/
    <tenant_id>/
      compose/<connection_id>.conf
      modsec/<rule_set>.conf
      crowdsec/...
```

Generators in `backend/src/angie`, `backend/src/modsecurity`, `backend/src/connections` accept a `tenant: Tenant` and write under the tenant subtree. Angie's main config uses `include /var/lib/waf/tenants/*/compose/*.conf;` — wildcards expand on reload. Tenant deletion removes the subtree and reloads Angie.

## 4. Roles

Two independent role axes per user:

| Axis | Values | Notes |
|------|--------|-------|
| Platform | `admin`, `client` | `admin` has no `tenant_id`. `client` always has a `tenant_id`. |
| Tenant   | `owner`, `member`, NULL | NULL when `platform_role = 'admin'`. The first user of a tenant is `owner`. |

Semantics:
- `admin` — operates the platform; sees `Monitoring` and `Clients` only.
- `client` — operates a WAF instance for their organization; sees everything else in the sidebar (Home, Dashboard, Connections, Configuration, CrowdSec, Tests).
- `owner` (intra-tenant) — can invite/remove tenant users (deferred; v1 has no invite flow because tenants are 1-user at signup) and can ask admin for tenant deletion.
- `member` (intra-tenant) — no team-management ability. Same WAF capability as owner.

Admin **never** sees tenant content (no WAF logs, no connection configs, no rule sets). Admin sees tenant metadata only: name, owner email, counts, timestamps. This is a deliberate privacy posture for SaaS.

## 5. Database schema

### 5.1 New / changed tables

```sql
-- users (rewritten)
users
  id                    PK
  email                 unique, lowercased, citext
  display_name          text
  password_hash         text NULLABLE         -- NULL for OAuth-only accounts
  platform_role         text NOT NULL CHECK (in 'admin','client')
  tenant_id             FK tenants.id NULLABLE
  tenant_role           text NULLABLE CHECK (in 'owner','member')
  email_verified_at     timestamptz NULLABLE
  totp_secret           text NULLABLE          -- base32, stored as-is
  totp_enabled_at       timestamptz NULLABLE
  recovery_codes_hash   text[] NULLABLE        -- array of sha256 hashes
  last_login_at         timestamptz NULLABLE
  created_at, updated_at
  CHECK (
    (platform_role = 'admin' AND tenant_id IS NULL AND tenant_role IS NULL)
    OR
    (platform_role = 'client' AND tenant_id IS NOT NULL AND tenant_role IS NOT NULL)
  )

-- tenants (new)
tenants
  id              PK
  name            unique, lowercase slug, used in URLs/paths
  display_name    text
  suspended_at    timestamptz NULLABLE   -- admin-controlled flag
  created_at, updated_at

-- oauth_accounts (new)
oauth_accounts
  id                    PK
  user_id               FK users
  provider              text CHECK (in 'google','github')
  provider_account_id   text NOT NULL
  email_at_provider     text NOT NULL
  created_at
  UNIQUE (provider, provider_account_id)

-- email_verifications (new)
email_verifications
  id           PK
  user_id      FK users
  purpose      text CHECK (in 'verify_email','reset_password')
  token_hash   text NOT NULL              -- sha256 of opaque token
  expires_at   timestamptz NOT NULL
  used_at      timestamptz NULLABLE
  created_at

-- Every existing tenant-scoped resource gets:
ALTER TABLE connections           ADD COLUMN tenant_id FK tenants.id NOT NULL;
ALTER TABLE <crowdsec tables>     ADD COLUMN tenant_id FK tenants.id NOT NULL;
ALTER TABLE <modsec tables>       ADD COLUMN tenant_id FK tenants.id NOT NULL;
-- and so on for every owned resource.
```

Identifier change: `email` replaces `username` as the primary login identifier (required for OAuth integration; both Google and GitHub return verified email).

### 5.2 Removed columns / tables

- `users.username`, `users.role`, `users.must_change_password` — dropped.

## 6. Session tokens

- **Library:** `pyseto`.
- **Format:** PASETO **v4.local** (symmetric, XChaCha20 + BLAKE2b).
- **Storage:** httpOnly cookie `waf_session`, `SameSite=Lax`, `Secure` flag follows existing `WAF_COOKIE_SECURE` env var, `Path=/`.
- **TTL:** 8h (unchanged).
- **Payload:** `{sub: user_id, pr: platform_role, tn: tenant_id|null, tr: tenant_role|null, iat, exp}`.
- **Key:** persisted at `/var/lib/angie/.paseto_key` (the existing `.jwt_secret` file is replaced; first boot regenerates), or via `WAF_PASETO_KEY` env var.
- **Validation:** on every request, decode the token, then re-load the user row from the database (no in-memory cache in v1) to pick up suspension, role changes, etc.

Short-lived non-session tokens for special flows are **not** PASETO; they're opaque 256-bit random strings whose sha256 is stored in `email_verifications`:
- email-verify token — 24h TTL
- password-reset token — 1h TTL
- OAuth state token — 10min, signed HMAC, stored only in a short-lived cookie (never DB)

## 7. Auth flows

### 7.1 Password signup

```
POST /api/auth/signup
  body: { email, password, tenant_name, display_name?, captcha_token }
```

- `tenant_name`: lowercase letters, digits, hyphens; 3-32 chars; matched against `^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$` server-side. Becomes both `tenants.name` (URL/path slug) and `tenants.display_name` (the latter may be edited later from the UI).
- `display_name`: optional human name for the user; defaults to the email's local part if omitted.

1. Verify `captcha_token` via Cloudflare `siteverify`. Reject on failure.
2. Reject if email or `tenant_name` already exists (409). Reject on `tenant_name` format violation (400).
3. Create `Tenant(name=tenant_name, display_name=tenant_name)`, then `User` with `platform_role='client'`, `tenant_role='owner'`, `email_verified_at=NULL`.
4. Generate a 256-bit random verify-token; store its sha256 in `email_verifications` with 24h TTL.
5. Send verify email containing `https://<host>/verify-email?token=<plaintext>`.
6. Respond `202 Accepted` with `{ message: "check your email" }`. Do **not** issue a session cookie.

```
POST /api/auth/verify-email
  body: { token }
```

1. Look up `email_verifications` by sha256(token), `used_at IS NULL`, `expires_at > now()`.
2. Set `users.email_verified_at = now()`, `email_verifications.used_at = now()`.
3. Issue PASETO session cookie, return user payload.
4. Frontend redirects to `/home`.

### 7.2 OAuth signup / login

```
GET  /api/auth/oauth/{provider}/start?intent=signup|login&tenant_name=<...>
```

- `provider` ∈ {`google`, `github`}.
- `tenant_name` required only when `intent=signup`.
- Generate `state = HMAC(provider | intent | tenant_name | nonce, key)`; store `state` in a short-lived httpOnly cookie (10min TTL).
- Redirect to provider's authorize URL with scope `openid email profile` (Google) or `read:user user:email` (GitHub).

```
GET /api/auth/oauth/{provider}/callback?code=...&state=...
```

1. Validate `state` against the cookie; on mismatch, 400.
2. Exchange `code` for an access token via the provider.
3. Fetch `userinfo` (provider account id, email, verified flag, display name).
4. If provider reports `email_verified=false` (Google only — GitHub uses primary verified email), reject 400.
5. Look up `oauth_accounts(provider, provider_account_id)`:
   - **Existing OAuth account:** issue session cookie. Done.
   - **No OAuth account, `intent=login`:** 404 `"no account — please sign up"`.
   - **No OAuth account, `intent=signup`:**
     - If a user with this email already exists (any provider, any password-based): 409 `"email already in use — sign in instead"` (no auto-linking; see Section 2).
     - Otherwise create `Tenant(name=tenant_name)`, `User(email_verified_at=now())`, link `oauth_accounts` row, issue session cookie.
6. Redirect to `/home`.

Provider credentials via environment:

```
WAF_OAUTH_GOOGLE_CLIENT_ID
WAF_OAUTH_GOOGLE_CLIENT_SECRET
WAF_OAUTH_GOOGLE_REDIRECT_URI
WAF_OAUTH_GITHUB_CLIENT_ID
WAF_OAUTH_GITHUB_CLIENT_SECRET
WAF_OAUTH_GITHUB_REDIRECT_URI
```

If the env vars for a provider are absent at startup, that provider's button is hidden in the UI and the routes return 503.

Library: **`httpx-oauth`** (provider-neutral OAuth2 client; no opinions about the user model).

### 7.3 Password login

```
POST /api/auth/login
  body: { email, password, captcha_token, totp_code? }
```

1. Verify captcha. Reject on failure.
2. Authenticate `(email, password)`. Generic 401 on failure.
3. If `email_verified_at IS NULL`: 403 `"verify your email first"`, with a hint that the client should offer a resend.
4. If `platform_role == 'admin'`:
   - If `totp_secret IS NULL`: 403 with `enrol_required=true`. Frontend routes the user to `/totp-setup`. Auth state needed by `/totp-setup` is carried in a short-lived HMAC-signed `waf_totp_enrol` cookie issued at this point (valid 10min, payload `{user_id, exp}` + HMAC tag using the PASETO key; rejected if signature invalid or expired). The cookie alone never grants normal session access — it only authorizes `/api/auth/totp/setup` and `/api/auth/totp/confirm`.
   - If `totp_code` is missing or invalid: 401 with `totp_required=true`.
5. If `platform_role == 'client'` and `totp_enabled_at IS NOT NULL`:
   - If `totp_code` is missing: 401 with `totp_required=true`. Frontend prompts for the code and re-submits.
   - If `totp_code` is invalid: 401 generic.
6. Set `users.last_login_at = now()`, issue PASETO session cookie, return user payload.

Captcha is required on every login attempt (no rate-limit state means captcha is the only anti-bot mechanism).

### 7.4 TOTP enrollment

```
POST /api/auth/totp/setup
  (auth: session cookie OR the short-lived waf_totp_enrol cookie)
  → { secret_base32, qr_code_data_uri, recovery_codes: [10 strings] }
```

- Generate a TOTP secret (random 160 bits, base32-encoded).
- Generate 10 recovery codes (each 10 chars).
- Store the secret in `users.totp_secret`, store `sha256(code)` of each recovery code in `users.recovery_codes_hash`.
- Secret is **not active yet** until confirmed.

```
POST /api/auth/totp/confirm
  body: { code }
  → 200 if code matches secret. Set users.totp_enabled_at = now().
```

Library: **`pyotp`** for TOTP; **`qrcode`** for QR data URI.

Recovery codes consume on use (one-shot). Submitted in place of `totp_code` on `/api/auth/login`; if matching, the matching hash is removed from the array.

### 7.5 Password reset

```
POST /api/auth/password/forgot
  body: { email, captcha_token }
  → always 202 (anti-enumeration)
```

Internally: if the user exists and `email_verified_at IS NOT NULL`, generate a reset-token, store sha256 in `email_verifications(purpose='reset_password')` with 1h TTL, send email with `/reset-password?token=<plaintext>`. If the user doesn't exist or isn't verified, do nothing — but still 202.

```
POST /api/auth/password/reset
  body: { token, new_password }
```

1. Look up `email_verifications`, validate purpose/expiry/used.
2. Update `users.password_hash`, mark token used.
3. Do **not** issue a session — user must log in normally (and pass TOTP if enabled).

### 7.6 Logout

```
POST /api/auth/logout
  → 204, deletes waf_session cookie.
```

PASETO is stateless; cookie deletion is the entire logout. The token, if exfiltrated, remains valid until `exp`. v1 accepts this tradeoff (8h max exposure). A future spec may add a revocation table.

## 8. Admin "Clients" page

Replaces the current `/users` page for admin users.

### 8.1 List view — `/clients`

| Column | Source |
|---|---|
| Tenant name | `tenants.display_name` |
| Owner email | `users.email WHERE tenant_id=… AND tenant_role='owner'` |
| Users count | `count(users) WHERE tenant_id=…` |
| Connections count | `count(connections) WHERE tenant_id=…` |
| Created | `tenants.created_at` |
| Suspended | `tenants.suspended_at IS NOT NULL` |
| Last activity | `max(users.last_login_at) WHERE tenant_id=…` |
| Actions | view details, suspend/unsuspend, delete |

### 8.2 Detail view — `/clients/:tenant_id`

Read-only. Lists tenant's users (email, tenant_role, last_login, email_verified, totp_enabled) and a list of connection names + protected domains. **No WAF logs, no configs, no rule contents shown.**

### 8.3 API

- `GET    /api/admin/tenants`
- `GET    /api/admin/tenants/{id}`
- `POST   /api/admin/tenants/{id}/suspend`     -- toggles `suspended_at`
- `DELETE /api/admin/tenants/{id}`             -- requires `?confirm=<tenant_name>`

All gated by `require_admin`. Suspending a tenant: all users with `tenant_id == ...` are logged out (next request returns 403 because `tenants.suspended_at` is checked in `require_verified`), and Angie configs for that tenant are not served (suspended config block is excluded from `include`).

## 9. Frontend changes

### 9.1 New pages

- `/signup` — email + password + tenant_name + display_name + Turnstile widget + Google/GitHub buttons.
- `/verify-email` — accepts `?token=` from URL, calls API, shows success or error.
- `/forgot-password`, `/reset-password`.
- `/totp-setup` — protected route requiring either an active session or the short-lived `waf_totp_enrol` cookie. Renders QR + recovery codes. Admin gets bumped here automatically after first login.
- `/clients`, `/clients/:id` — admin-only.

### 9.2 Updated pages

- `/login` — adds Turnstile widget; adds Google/GitHub buttons (each hidden if its env-driven `enabled` flag is false on the `/api/auth/providers` endpoint); shows a conditional TOTP-code field after a 401-with-`totp_required` response.
- `Layout.tsx` — sidebar restructured to a single declarative array of `{ section, label, path, requires: 'admin'|'client'|'any' }`, rendered against `user.platform_role`.
  - `admin` sees `Operations`: `Monitoring`, `Clients`.
  - `client` sees `Overview` (Home, Dashboard), `Management` (Connections, Configuration), `Security` (CrowdSec, Tests).
- `AdminOnly.tsx` → renamed `RequireRole`, takes a `role` prop, used at the route level.

### 9.3 Removed pages

- `/users` — deleted. Tenant-internal team management is out of scope for v1.

### 9.4 `AuthContext`

Type updated:

```ts
interface User {
  id: number;
  email: string;
  display_name: string;
  platform_role: 'admin' | 'client';
  tenant_id: number | null;
  tenant_role: 'owner' | 'member' | null;
  email_verified: boolean;
  totp_enabled: boolean;
}
```

### 9.5 New endpoint for capability discovery

`GET /api/auth/providers` — returns `{ google: bool, github: bool, captcha_site_key: string|null }`. Frontend uses this on Login/Signup mount to decide which buttons and widgets to render.

## 10. Migration and seeding

v1 is wipe-and-restart. There is no data preservation path from the old schema.

### 10.1 Alembic migration

Single migration `redesign_auth`:
1. `DROP TABLE users`.
2. `DROP TABLE` any auth-derived state (e.g., active sessions if such a table exists).
3. `CREATE TABLE tenants, users (new shape), oauth_accounts, email_verifications`.
4. For every tenant-scoped resource table: `ALTER TABLE ... ADD COLUMN tenant_id NOT NULL ...`. Because there are no rows to preserve, this is straightforward.
5. Drop `/var/lib/waf/compose/*` and recreate `/var/lib/waf/tenants/`.

### 10.2 Seeding

- The previous default `admin/admin` seed is **removed**. It was a security liability.
- New CLI: `python -m backend.cli create-admin --email <e>`. Prompts for password, creates the admin user, prints a one-time confirmation. The user then logs in normally and is forced through TOTP enrollment.
- If the admin row count is zero, the login endpoint returns `503 Service Unavailable` with a body `{ "error": "system not provisioned", "hint": "run scripts/create-admin.sh" }`.

### 10.3 Environment variables (new)

```
WAF_PASETO_KEY                          # optional; auto-persisted otherwise
WAF_TURNSTILE_SITE_KEY
WAF_TURNSTILE_SECRET_KEY
WAF_SMTP_HOST
WAF_SMTP_PORT                           # default 587
WAF_SMTP_USERNAME
WAF_SMTP_PASSWORD
WAF_SMTP_FROM_EMAIL
WAF_SMTP_FROM_NAME
WAF_OAUTH_GOOGLE_CLIENT_ID
WAF_OAUTH_GOOGLE_CLIENT_SECRET
WAF_OAUTH_GOOGLE_REDIRECT_URI
WAF_OAUTH_GITHUB_CLIENT_ID
WAF_OAUTH_GITHUB_CLIENT_SECRET
WAF_OAUTH_GITHUB_REDIRECT_URI
WAF_PUBLIC_BASE_URL                     # used in email links (e.g. https://waf.example.com)
```

`scripts/generate-env.sh` is updated to scaffold these. The deployment doc (`README.md` / `CLAUDE.md`) gets a section on provisioning the admin and configuring OAuth credentials.

## 11. Testing strategy

### 11.1 Unit tests

- PASETO encode/decode round-trip and tamper detection.
- bcrypt hash/verify (existing).
- TOTP code verification, drift tolerance (default ±1 step).
- Recovery-code consumption.
- Captcha-verify wrapper (mock Cloudflare).
- Email-token generation and one-shot consumption.

### 11.2 Two-tenant safety integration tests

Setup fixture: tenant A with user_a and one connection, tenant B with user_b and one connection.

For each tenant-scoped resource (connections, configs, ModSec rule sets, CrowdSec entries, …) and each verb (`GET list`, `GET item`, `POST`, `PUT`, `DELETE`):

- Logged in as user_a, perform the verb against B's resource id (when applicable). Expect `404` or `403`, never the data.
- Logged in as user_a, perform a list verb. Expect zero B resources in the response.

This is mechanical and must be exhaustive; a missing test is the only way a leak ships.

### 11.3 Service-layer AST guard

A pytest test walks each `backend/src/*/service.py` for tenant-scoped models and asserts that every `select(Resource)` is followed (within the same call expression) by `.where(...)` referencing `tenant_id`. Failure modes: a service forgets the filter, or someone introduces a new tenant-scoped model without updating the AST guard's model list.

### 11.4 OAuth tests

Mock `httpx-oauth` responses to cover:
- signup new account
- signup with email collision
- login with existing OAuth account
- login with no OAuth account (404)
- provider returns `email_verified=false` (Google)
- GitHub primary email not verified

### 11.5 E2E flows

Using the existing `tests/e2e/` curl-based harness or Playwright (decision deferred to plan):

- **Full signup**: signup → receive verify-token via test-mode SMTP capture → verify → login → create connection → logout.
- **Admin lifecycle**: CLI create-admin → login → forced TOTP enrol → /clients → suspend tenant → confirm tenant user gets 403.
- **OAuth signup**: mock provider flow end-to-end.
- **Captcha enforcement**: submit without captcha_token → 400.

## 12. Component map

Files / modules touched:

```
backend/src/
  auth/
    security.py          # rewritten: pyseto instead of jose; keep bcrypt
    service.py           # new flows: signup, oauth, totp, email-verify, reset
    router.py            # endpoints listed in Section 7
    dependencies.py      # current_tenant, require_admin/client/owner, require_verified
    schemas.py           # User/Tenant Pydantic types; remove username
    oauth.py             # NEW: httpx-oauth client factories
    captcha.py           # NEW: Turnstile siteverify wrapper
    email.py             # NEW: aiosmtplib + jinja templates
    totp.py              # NEW: pyotp + qrcode wrappers
  db/
    models.py            # rewritten User, new Tenant, OAuthAccount, EmailVerification
    migrations/          # one new alembic migration: redesign_auth
  cli/
    __init__.py          # NEW: typer/argparse entrypoint
    create_admin.py      # NEW
  connections/, modsecurity/, crowdsec/, ...:
    service.py           # every fn gains tenant: Tenant parameter, adds where clauses
    router.py            # every endpoint gains current_tenant dep
  admin/                 # NEW module
    router.py            # /api/admin/tenants endpoints
    service.py
  angie/
    generator.py         # writes under /var/lib/waf/tenants/<id>/...
  realtime/              # check: ensure publish channels are tenant-scoped

frontend/src/
  pages/
    Login.tsx            # Turnstile + OAuth buttons + TOTP field
    Signup.tsx           # NEW
    VerifyEmail.tsx      # NEW
    ForgotPassword.tsx   # NEW
    ResetPassword.tsx    # NEW
    TotpSetup.tsx        # NEW
    Clients.tsx          # NEW (replaces Users for admin)
    ClientDetail.tsx     # NEW
    Users.tsx            # DELETED
  components/
    AdminOnly.tsx → RequireRole.tsx   # generalized
    Layout.tsx           # sidebar reshape
    TurnstileWidget.tsx  # NEW
  context/
    AuthContext.tsx      # User type updates, login() supports totp_code
  api/
    client.ts            # new endpoints

docker-compose.yml, docker-compose.swarm.yml
  # add SMTP-relevant env passthrough; new volume for /var/lib/waf/tenants

scripts/
  generate-env.sh        # scaffold new env vars
  create-admin.sh        # thin wrapper for python -m backend.cli create-admin
```

## 13. Open questions deferred to writing-plans

These don't change the design but need plan-level decisions:

- Exact alembic migration ordering (one big migration vs split into auth-tables + per-resource tenant_id).
- Whether E2E tests use the existing curl harness or introduce Playwright (curl preferred for consistency with `tests/e2e/`).
- Concrete admin-CLI library choice (typer vs argparse).
- Whether to ship a docker-compose dev override with mailhog out of the box, or document its addition.

## 14. Acceptance criteria

This spec is shipped when:

1. A fresh wipe-and-restart deployment cannot be logged into until `create-admin` CLI is run.
2. Admin login requires TOTP after the first password step.
3. Admin's sidebar contains only `Monitoring` and `Clients`. Clients page lists tenants with metadata only.
4. A new tenant can be created end-to-end via password signup + email verification, via Google OAuth, and via GitHub OAuth.
5. Captcha is enforced on signup, login, and forgot-password. Submitting without a valid Turnstile token returns 400.
6. Two-tenant safety tests pass for every tenant-scoped resource (Section 11.2).
7. AST guard test passes (Section 11.3).
8. PASETO v4.local tokens are issued; the old JWT code path is removed.
9. Suspending a tenant logs its users out within one request.
