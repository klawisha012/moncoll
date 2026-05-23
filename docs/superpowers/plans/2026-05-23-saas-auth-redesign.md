# SaaS Auth Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace single-tenant `admin|viewer` auth with a SaaS model — multi-tenant data isolation, PASETO sessions, Google/GitHub OAuth, Cloudflare Turnstile captcha, mandatory TOTP for admin, self-service signup with email verification.

**Architecture:** Python FastAPI backend (async SQLAlchemy 2 + asyncpg + alembic), React frontend. Service-layer tenant filtering enforced by FastAPI deps + AST guard test + per-resource two-tenant integration tests. Filesystem configs isolated under `/var/lib/waf/tenants/<id>/`. Wipe-and-restart database migration (no legacy preservation).

**Tech Stack:** `pyseto` (PASETO v4.local), `pyotp` + `qrcode` (TOTP), `httpx-oauth` (OAuth2), `aiosmtplib` + `jinja2` (email), `httpx` (Turnstile siteverify), existing `passlib[bcrypt]`, `sqlalchemy`, `fastapi`, `alembic`, React + Vite.

**Spec:** [docs/superpowers/specs/2026-05-23-saas-auth-redesign-design.md](../specs/2026-05-23-saas-auth-redesign-design.md)

---

## Phases

0. Foundations — deps, env scaffolding
1. Database schema rewrite (wipe-and-restart)
2. PASETO session security primitives
3. Tenant + User services
4. FastAPI dependencies (current_user / current_tenant / require_*)
5. Tenant isolation across existing services
6. AST guard + two-tenant integration tests
7. Captcha (Turnstile)
8. Email transport (SMTP + templates)
9. Password auth flows (signup, verify, login, reset)
10. TOTP enrollment + login gating
11. OAuth (Google + GitHub)
12. Admin endpoints + Clients page (backend)
13. CLI admin seeding + bootstrap guard
14. Filesystem isolation (Angie/ModSec tenants/<id>/)
15. Frontend — auth primitives
16. Frontend — auth pages
17. Frontend — admin pages
18. Sidebar reshape + route gating
19. Docker / env / scripts / docs
20. E2E

Each phase ends with a green test run + commit. The build stays passing at every commit.

---

## Phase 0 — Foundations

### Task 0.1: Add Python dependencies

**Files:**
- Modify: `backend/requirements.txt`

- [ ] **Step 1: Edit requirements.txt**

Replace `python-jose[cryptography]>=3.3.0` and add new lines so the file becomes:

```
fastapi>=0.109.0
uvicorn>=0.27.0
pydantic>=2.5.0
pyyaml>=6.0
docker>=7.0.0
prometheus-fastapi-instrumentator>=6.1.0
clickhouse-driver>=0.2.6
passlib[bcrypt]>=1.7.4
bcrypt>=4.0.0,<4.1.0
pyseto>=1.7.6
python-multipart>=0.0.9
sqlalchemy[asyncio]>=2.0.25
asyncpg>=0.29.0
alembic>=1.13.0
pydantic-settings>=2.1.0
httpx>=0.27.0
dnspython>=2.6.0
redis>=5.0.0
pyotp>=2.9.0
qrcode[pil]>=7.4.2
httpx-oauth>=0.15.0
aiosmtplib>=3.0.0
jinja2>=3.1.0
typer>=0.12.0
email-validator>=2.1.0
```

- [ ] **Step 2: Rebuild the backend container locally**

Run:
```bash
docker compose build backend
```

Expected: build succeeds; pip resolves all packages.

- [ ] **Step 3: Commit**

```bash
git add backend/requirements.txt
git commit -m "build: add pyseto, pyotp, httpx-oauth, aiosmtplib, typer; drop python-jose"
```

### Task 0.2: Settings module for new env vars

**Files:**
- Create: `backend/src/config.py`
- Test: `tests/unit/backend/test_config.py`

- [ ] **Step 1: Write failing test**

```python
# tests/unit/backend/test_config.py
import os
import pytest
from backend.src.config import get_settings

def test_settings_reads_env(monkeypatch):
    monkeypatch.setenv("WAF_PUBLIC_BASE_URL", "https://example.com")
    monkeypatch.setenv("WAF_TURNSTILE_SITE_KEY", "site-key")
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "secret-key")
    get_settings.cache_clear()
    s = get_settings()
    assert s.public_base_url == "https://example.com"
    assert s.turnstile_site_key == "site-key"
    assert s.oauth_google_enabled is False  # default when client id missing

def test_settings_oauth_enabled(monkeypatch):
    monkeypatch.setenv("WAF_OAUTH_GOOGLE_CLIENT_ID", "x")
    monkeypatch.setenv("WAF_OAUTH_GOOGLE_CLIENT_SECRET", "y")
    monkeypatch.setenv("WAF_OAUTH_GOOGLE_REDIRECT_URI", "z")
    get_settings.cache_clear()
    s = get_settings()
    assert s.oauth_google_enabled is True
```

- [ ] **Step 2: Run failing**

Run: `pytest tests/unit/backend/test_config.py -v`
Expected: ImportError / module not found.

- [ ] **Step 3: Implement config**

```python
# backend/src/config.py
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WAF_", case_sensitive=False, extra="ignore")

    public_base_url: str = "http://localhost"
    cookie_secure: bool = False
    paseto_key: str | None = None

    turnstile_site_key: str | None = None
    turnstile_secret_key: str | None = None

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str = "noreply@waf.local"
    smtp_from_name: str = "WAF"
    smtp_starttls: bool = True

    oauth_google_client_id: str | None = None
    oauth_google_client_secret: str | None = None
    oauth_google_redirect_uri: str | None = None

    oauth_github_client_id: str | None = None
    oauth_github_client_secret: str | None = None
    oauth_github_redirect_uri: str | None = None

    @property
    def oauth_google_enabled(self) -> bool:
        return bool(
            self.oauth_google_client_id
            and self.oauth_google_client_secret
            and self.oauth_google_redirect_uri
        )

    @property
    def oauth_github_enabled(self) -> bool:
        return bool(
            self.oauth_github_client_id
            and self.oauth_github_client_secret
            and self.oauth_github_redirect_uri
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 4: Run tests pass**

Run: `pytest tests/unit/backend/test_config.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/config.py tests/unit/backend/test_config.py
git commit -m "feat(config): centralised Settings for new SaaS auth env vars"
```

---

## Phase 1 — Database schema rewrite

### Task 1.1: Define new ORM models

**Files:**
- Modify: `backend/src/db/models.py` (full rewrite of `User`, add `Tenant`, `OAuthAccount`, `EmailVerification`)
- Add `tenant_id` to `Connection`

- [ ] **Step 1: Replace `User` class and add new models**

Replace the existing `User` class in `backend/src/db/models.py` and add the three new classes. Final block:

```python
from datetime import UTC, datetime
from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "(platform_role = 'admin' AND tenant_id IS NULL AND tenant_role IS NULL) "
            "OR (platform_role = 'client' AND tenant_id IS NOT NULL AND tenant_role IS NOT NULL)",
            name="users_platform_tenant_consistency",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform_role: Mapped[str] = mapped_column(
        Enum("admin", "client", name="platform_role"), nullable=False
    )
    tenant_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    tenant_role: Mapped[str | None] = mapped_column(
        Enum("owner", "member", name="tenant_role"), nullable=True
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovery_codes_hash: Mapped[list[str] | None] = mapped_column(ARRAY(String(64)), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_account_id", name="uq_oauth_provider_account"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(Enum("google", "github", name="oauth_provider"), nullable=False)
    provider_account_id: Mapped[str] = mapped_column(String(128), nullable=False)
    email_at_provider: Mapped[str] = mapped_column(String(254), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(
        Enum("verify_email", "reset_password", name="email_verification_purpose"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
```

- [ ] **Step 2: Add tenant_id to Connection**

In the same file, edit the `Connection` class — replace the existing `user_id` column with `tenant_id`:

```python
    tenant_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
```

(Remove the `user_id` column entirely.)

- [ ] **Step 3: Verify imports**

Run: `python -c "from backend.src.db.models import User, Tenant, OAuthAccount, EmailVerification, Connection"` (inside backend container or active venv).
Expected: no import error.

- [ ] **Step 4: Commit**

```bash
git add backend/src/db/models.py
git commit -m "feat(db): redesign users + add tenants/oauth_accounts/email_verifications; tenant_id on connections"
```

### Task 1.2: Alembic migration — wipe and recreate

**Files:**
- Create: `backend/alembic/versions/0006_saas_auth_redesign.py`

- [ ] **Step 1: Generate empty migration scaffold**

Run:
```bash
cd backend && alembic revision -m "saas_auth_redesign" --rev-id 0006
```
This produces `backend/alembic/versions/0006_saas_auth_redesign.py` with `down_revision = "0005"`.

- [ ] **Step 2: Fill `upgrade()` body**

```python
def upgrade() -> None:
    # Drop legacy auth state. Wipe-and-restart per spec §10.
    op.execute("DROP TABLE IF EXISTS connections CASCADE")
    op.execute("DROP TABLE IF EXISTS users CASCADE")
    op.execute("DROP TYPE IF EXISTS origin_tls_mode CASCADE")
    op.execute("DROP TYPE IF EXISTS connection_status CASCADE")

    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(32), nullable=False, unique=True),
        sa.Column("display_name", sa.String(64), nullable=False),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_tenants_name", "tenants", ["name"])

    platform_role = postgresql.ENUM("admin", "client", name="platform_role")
    tenant_role = postgresql.ENUM("owner", "member", name="tenant_role")
    platform_role.create(op.get_bind(), checkfirst=True)
    tenant_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False, unique=True),
        sa.Column("display_name", sa.String(64), nullable=False, server_default=""),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("platform_role", platform_role, nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("tenant_role", tenant_role, nullable=True),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totp_secret", sa.String(64), nullable=True),
        sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovery_codes_hash", postgresql.ARRAY(sa.String(64)), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "(platform_role = 'admin' AND tenant_id IS NULL AND tenant_role IS NULL) "
            "OR (platform_role = 'client' AND tenant_id IS NOT NULL AND tenant_role IS NOT NULL)",
            name="users_platform_tenant_consistency",
        ),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    oauth_provider = postgresql.ENUM("google", "github", name="oauth_provider")
    oauth_provider.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "oauth_accounts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", oauth_provider, nullable=False),
        sa.Column("provider_account_id", sa.String(128), nullable=False),
        sa.Column("email_at_provider", sa.String(254), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("provider", "provider_account_id", name="uq_oauth_provider_account"),
    )
    op.create_index("ix_oauth_accounts_user_id", "oauth_accounts", ["user_id"])

    email_verification_purpose = postgresql.ENUM("verify_email", "reset_password", name="email_verification_purpose")
    email_verification_purpose.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "email_verifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", email_verification_purpose, nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_email_verifications_token_hash", "email_verifications", ["token_hash"])
    op.create_index("ix_email_verifications_user_id", "email_verifications", ["user_id"])

    origin_tls_mode = postgresql.ENUM("strict", "lenient", name="origin_tls_mode")
    connection_status = postgresql.ENUM(
        "pending_verification", "pending_dns", "provisioning_cert", "active", "error", name="connection_status"
    )
    origin_tls_mode.create(op.get_bind(), checkfirst=True)
    connection_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False, unique=True),
        sa.Column("origin_hosts", sa.JSON(), nullable=False),
        sa.Column("origin_port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("origin_tls_mode", origin_tls_mode, nullable=False, server_default="strict"),
        sa.Column("verify_token", sa.String(64), nullable=False, server_default=""),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", connection_status, nullable=False, server_default="pending_verification"),
        sa.Column("status_detail", sa.Text(), nullable=True),
        sa.Column("acme_retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("acme_next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dns_ttl_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("http_versions", sa.String(32), nullable=False, server_default="h1,h2"),
        sa.Column("compression_algo", sa.String(16), nullable=False, server_default="auto"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("ssl_cert_path", sa.String(512), nullable=True),
        sa.Column("ssl_key_path", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_connections_tenant_id", "connections", ["tenant_id"])


def downgrade() -> None:
    raise RuntimeError("wipe-and-restart migration is not reversible")
```

Required imports at top: `from alembic import op`, `import sqlalchemy as sa`, `from sqlalchemy.dialects import postgresql`.

- [ ] **Step 3: Run migration locally**

Run:
```bash
docker compose down -v
docker compose up -d postgres
docker compose run --rm backend alembic upgrade head
```

Expected: no errors. Confirm with `docker compose exec postgres psql -U waf -d waf -c "\dt"` showing `tenants users oauth_accounts email_verifications connections` (and nothing else for now besides existing non-auth tables — drop any extra resource tables in the migration if they cross-reference users; see Task 5.x).

- [ ] **Step 4: Commit**

```bash
git add backend/alembic/versions/0006_saas_auth_redesign.py
git commit -m "feat(db): alembic migration 0006 saas_auth_redesign (wipe & recreate)"
```

### Task 1.3: Add tenant_id to other tenant-scoped tables

If `backend/src/crowdsec` or `backend/src/modsecurity` or any other module has DB tables (check via `grep -rn "__tablename__" backend/src/`), each gets a `tenant_id` column. Repeat the pattern from Task 1.2 inside the same migration before committing — extend `upgrade()` with `ALTER TABLE` calls if those tables exist, or rebuild them via DROP+CREATE in the same wipe step.

- [ ] **Step 1: Enumerate tenant-scoped tables**

Run: `grep -rn "__tablename__" backend/src/`
For each table that holds tenant-owned data (CrowdSec decisions, ModSec custom rules, monitoring exclusions if any), add a `tenant_id` column + FK + index.

- [ ] **Step 2: Update models + migration**

Mirror the Connection pattern in `models.py` and extend the 0006 migration. Re-run `alembic upgrade head` against a clean db.

- [ ] **Step 3: Commit**

```bash
git add backend/src/db/models.py backend/alembic/versions/0006_saas_auth_redesign.py
git commit -m "feat(db): tenant_id on all tenant-scoped tables"
```

---

## Phase 2 — PASETO session security

### Task 2.1: PASETO key management + token helpers

**Files:**
- Replace: `backend/src/auth/security.py`
- Test: `tests/unit/backend/test_security_paseto.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/backend/test_security_paseto.py
import pytest
from backend.src.auth import security


def test_hash_and_verify_password():
    h = security.hash_password("hello")
    assert security.verify_password("hello", h)
    assert not security.verify_password("wrong", h)


def test_paseto_roundtrip(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    security._cached_key = None
    token = security.create_session_token(user_id=1, platform_role="client", tenant_id=2, tenant_role="owner")
    payload = security.decode_session_token(token)
    assert payload["sub"] == "1"
    assert payload["pr"] == "client"
    assert payload["tn"] == 2
    assert payload["tr"] == "owner"


def test_paseto_tamper_rejected(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    security._cached_key = None
    token = security.create_session_token(user_id=1, platform_role="admin", tenant_id=None, tenant_role=None)
    tampered = token[:-4] + "AAAA"
    assert security.decode_session_token(tampered) is None


def test_hmac_signed_cookie_roundtrip(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "1" * 64)
    security._cached_key = None
    value = security.sign_short_lived({"user_id": 5}, ttl_seconds=600, purpose="totp_enrol")
    payload = security.verify_short_lived(value, purpose="totp_enrol")
    assert payload == {"user_id": 5}


def test_short_lived_wrong_purpose(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "1" * 64)
    security._cached_key = None
    value = security.sign_short_lived({"user_id": 5}, ttl_seconds=600, purpose="totp_enrol")
    assert security.verify_short_lived(value, purpose="oauth_state") is None
```

- [ ] **Step 2: Run failing**

Run: `pytest tests/unit/backend/test_security_paseto.py -v`
Expected: ImportError / missing attribute.

- [ ] **Step 3: Implement security.py**

```python
# backend/src/auth/security.py
import hmac
import hashlib
import json
import logging
import os
import secrets
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyseto
from pyseto import Key
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 8 * 60 * 60
PASETO_KEY_FILE = Path("/var/lib/angie/.paseto_key")

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_cached_key: bytes | None = None


def _load_or_create_paseto_key() -> bytes:
    global _cached_key
    if _cached_key is not None:
        return _cached_key

    env = os.environ.get("WAF_PASETO_KEY")
    if env:
        # 32-byte raw key, hex-encoded (64 chars) in env
        _cached_key = bytes.fromhex(env) if len(env) == 64 else env.encode()[:32].ljust(32, b"\0")
        return _cached_key

    try:
        if PASETO_KEY_FILE.exists():
            _cached_key = PASETO_KEY_FILE.read_bytes()
            return _cached_key
        PASETO_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_bytes(32)
        PASETO_KEY_FILE.write_bytes(new_key)
        try:
            os.chmod(PASETO_KEY_FILE, 0o600)
        except OSError:
            pass
        _cached_key = new_key
        return _cached_key
    except OSError as exc:
        logger.warning("Cannot persist PASETO key (%s) — using ephemeral key", exc)
        _cached_key = secrets.token_bytes(32)
        return _cached_key


def _paseto_key() -> Key:
    return Key.new(version=4, purpose="local", key=_load_or_create_paseto_key())


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return _pwd_context.verify(plain, hashed)
    except (ValueError, TypeError):
        return False


def create_session_token(*, user_id: int, platform_role: str, tenant_id: int | None, tenant_role: str | None) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "pr": platform_role,
        "tn": tenant_id,
        "tr": tenant_role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=SESSION_TTL_SECONDS)).timestamp()),
    }
    return pyseto.encode(_paseto_key(), json.dumps(payload).encode()).decode()


def decode_session_token(token: str) -> dict | None:
    try:
        decoded = pyseto.decode(_paseto_key(), token)
        data = json.loads(decoded.payload)
        if data.get("exp", 0) < int(datetime.now(UTC).timestamp()):
            return None
        return data
    except Exception:
        return None


def sign_short_lived(payload: dict, *, ttl_seconds: int, purpose: str) -> str:
    """HMAC-signed opaque cookie value. Returns base64url(payload_json | tag)."""
    body = {**payload, "exp": int(datetime.now(UTC).timestamp()) + ttl_seconds, "p": purpose}
    raw = json.dumps(body, separators=(",", ":")).encode()
    tag = hmac.new(_load_or_create_paseto_key(), raw, hashlib.sha256).digest()
    return urlsafe_b64encode(raw + b"." + tag).rstrip(b"=").decode()


def verify_short_lived(value: str, *, purpose: str) -> dict | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = urlsafe_b64decode(padded.encode())
        raw, tag = decoded.rsplit(b".", 1)
        expected = hmac.new(_load_or_create_paseto_key(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return None
        body = json.loads(raw)
        if body.get("p") != purpose:
            return None
        if body.get("exp", 0) < int(datetime.now(UTC).timestamp()):
            return None
        body.pop("p")
        body.pop("exp")
        return body
    except Exception:
        return None
```

- [ ] **Step 4: Run tests pass**

Run: `pytest tests/unit/backend/test_security_paseto.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/auth/security.py tests/unit/backend/test_security_paseto.py
git commit -m "feat(auth): PASETO v4.local session tokens + HMAC short-lived cookies"
```

---

## Phase 3 — Tenant + User services

### Task 3.1: Tenant service (CRUD primitives)

**Files:**
- Create: `backend/src/tenants/__init__.py`, `backend/src/tenants/service.py`
- Test: `tests/integration/backend/test_tenant_service.py`

- [ ] **Step 1: Write failing test**

```python
# tests/integration/backend/test_tenant_service.py
import pytest
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_create_and_get_tenant(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    assert t.id is not None
    assert t.name == "acme"
    got = await tenants.get_by_name(db_session, "acme")
    assert got.id == t.id


@pytest.mark.asyncio
async def test_duplicate_name_raises(db_session):
    await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    with pytest.raises(tenants.TenantNameTaken):
        await tenants.create_tenant(db_session, name="acme", display_name="Other")


@pytest.mark.asyncio
async def test_invalid_name_raises(db_session):
    with pytest.raises(tenants.InvalidTenantName):
        await tenants.create_tenant(db_session, name="No Spaces", display_name="X")
    with pytest.raises(tenants.InvalidTenantName):
        await tenants.create_tenant(db_session, name="ab", display_name="X")
```

`db_session` fixture comes from a shared `tests/integration/backend/conftest.py` — see Task 3.3.

- [ ] **Step 2: Run failing**

Run: `pytest tests/integration/backend/test_tenant_service.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement service**

```python
# backend/src/tenants/__init__.py
from . import service  # noqa: F401
```

```python
# backend/src/tenants/service.py
import re
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db.models import Tenant

TENANT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")


class InvalidTenantName(ValueError): ...
class TenantNameTaken(ValueError): ...


def _validate_name(name: str) -> None:
    if not TENANT_NAME_RE.match(name):
        raise InvalidTenantName(name)


async def create_tenant(session: AsyncSession, *, name: str, display_name: str) -> Tenant:
    _validate_name(name)
    existing = await session.execute(select(Tenant).where(Tenant.name == name))
    if existing.scalar_one_or_none():
        raise TenantNameTaken(name)
    t = Tenant(name=name, display_name=display_name or name)
    session.add(t)
    await session.commit()
    await session.refresh(t)
    return t


async def get(session: AsyncSession, tenant_id: int) -> Tenant | None:
    return await session.get(Tenant, tenant_id)


async def get_by_name(session: AsyncSession, name: str) -> Tenant | None:
    result = await session.execute(select(Tenant).where(Tenant.name == name))
    return result.scalar_one_or_none()


async def suspend(session: AsyncSession, tenant_id: int) -> Tenant | None:
    from datetime import UTC, datetime
    t = await session.get(Tenant, tenant_id)
    if not t:
        return None
    t.suspended_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(t)
    return t


async def unsuspend(session: AsyncSession, tenant_id: int) -> Tenant | None:
    t = await session.get(Tenant, tenant_id)
    if not t:
        return None
    t.suspended_at = None
    await session.commit()
    await session.refresh(t)
    return t


async def delete(session: AsyncSession, tenant_id: int) -> bool:
    t = await session.get(Tenant, tenant_id)
    if not t:
        return False
    await session.delete(t)
    await session.commit()
    return True
```

- [ ] **Step 4: Run tests pass**

Run: `pytest tests/integration/backend/test_tenant_service.py -v`
Expected: PASS (after Task 3.3 fixture is in place — may need to do 3.3 first).

- [ ] **Step 5: Commit**

```bash
git add backend/src/tenants/ tests/integration/backend/test_tenant_service.py
git commit -m "feat(tenants): tenant service CRUD + slug validation"
```

### Task 3.2: User service rewrite

**Files:**
- Rewrite: `backend/src/auth/service.py`
- Rewrite: `backend/src/auth/schemas.py`
- Test: `tests/integration/backend/test_auth_user_service.py`

- [ ] **Step 1: Replace schemas.py**

```python
# backend/src/auth/schemas.py
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, EmailStr, Field

PlatformRole = Literal["admin", "client"]
TenantRole = Literal["owner", "member"]


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    display_name: str
    platform_role: PlatformRole
    tenant_id: int | None
    tenant_role: TenantRole | None
    email_verified: bool
    totp_enabled: bool

    @classmethod
    def from_user(cls, user) -> "UserPublic":
        return cls(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            platform_role=user.platform_role,
            tenant_id=user.tenant_id,
            tenant_role=user.tenant_role,
            email_verified=user.email_verified_at is not None,
            totp_enabled=user.totp_enabled_at is not None,
        )


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    tenant_name: str = Field(min_length=3, max_length=32)
    display_name: str | None = Field(default=None, max_length=64)
    captcha_token: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    captcha_token: str
    totp_code: str | None = None


class VerifyEmailRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    captcha_token: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=256)


class TotpConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class LoginResponse(BaseModel):
    user: UserPublic
```

- [ ] **Step 2: Rewrite service.py — user operations**

```python
# backend/src/auth/service.py
from datetime import UTC, datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db.models import User
from .security import hash_password, verify_password


class EmailTaken(ValueError): ...
class UserNotFound(ValueError): ...


async def get_user(session: AsyncSession, user_id: int) -> User | None:
    return await session.get(User, user_id)


async def get_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()


async def count_admins(session: AsyncSession) -> int:
    from sqlalchemy import func
    result = await session.execute(select(func.count()).select_from(User).where(User.platform_role == "admin"))
    return int(result.scalar_one())


async def create_client_user(
    session: AsyncSession,
    *,
    email: str,
    password: str | None,
    tenant_id: int,
    tenant_role: str = "owner",
    display_name: str = "",
    email_verified: bool = False,
) -> User:
    email = email.lower()
    if await get_by_email(session, email):
        raise EmailTaken(email)
    user = User(
        email=email,
        display_name=display_name or email.split("@")[0],
        password_hash=hash_password(password) if password else None,
        platform_role="client",
        tenant_id=tenant_id,
        tenant_role=tenant_role,
        email_verified_at=datetime.now(UTC) if email_verified else None,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def create_admin(session: AsyncSession, *, email: str, password: str) -> User:
    email = email.lower()
    if await get_by_email(session, email):
        raise EmailTaken(email)
    user = User(
        email=email,
        display_name=email.split("@")[0],
        password_hash=hash_password(password),
        platform_role="admin",
        tenant_id=None,
        tenant_role=None,
        email_verified_at=datetime.now(UTC),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def authenticate(session: AsyncSession, email: str, password: str) -> User | None:
    user = await get_by_email(session, email)
    if not user or not verify_password(password, user.password_hash):
        return None
    return user


async def mark_email_verified(session: AsyncSession, user: User) -> None:
    user.email_verified_at = datetime.now(UTC)
    await session.commit()


async def update_password(session: AsyncSession, user: User, new_password: str) -> None:
    user.password_hash = hash_password(new_password)
    await session.commit()


async def touch_login(session: AsyncSession, user: User) -> None:
    user.last_login_at = datetime.now(UTC)
    await session.commit()
```

- [ ] **Step 3: Add integration tests**

```python
# tests/integration/backend/test_auth_user_service.py
import pytest
from backend.src.auth import service as auth
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_create_client_user(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id)
    assert u.platform_role == "client"
    assert u.tenant_role == "owner"


@pytest.mark.asyncio
async def test_authenticate(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id)
    u = await auth.authenticate(db_session, "a@b.com", "hunter22a")
    assert u is not None
    assert await auth.authenticate(db_session, "a@b.com", "wrong") is None


@pytest.mark.asyncio
async def test_email_taken(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id)
    with pytest.raises(auth.EmailTaken):
        await auth.create_client_user(db_session, email="A@B.com", password="hunter22a", tenant_id=t.id)
```

- [ ] **Step 4: Run tests pass**

Run: `pytest tests/integration/backend/test_auth_user_service.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/auth/service.py backend/src/auth/schemas.py tests/integration/backend/test_auth_user_service.py
git commit -m "feat(auth): rewrite user service for SaaS model (email, platform/tenant roles, hashing)"
```

### Task 3.3: Integration test fixture for DB sessions

**Files:**
- Create: `tests/integration/__init__.py` (if missing), `tests/integration/backend/__init__.py`, `tests/integration/backend/conftest.py`

- [ ] **Step 1: Conftest**

```python
# tests/integration/backend/conftest.py
import asyncio
import os
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from backend.src.db.base import Base


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session():
    url = os.environ.get("TEST_DATABASE_URL", "postgresql+asyncpg://waf:waf@localhost:5432/waf_test")
    engine = create_async_engine(url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as session:
        yield session
    await engine.dispose()
```

The integration tests run against a postgres database — locally, against the docker-compose `postgres` service with `TEST_DATABASE_URL` exported. Document this in README.

- [ ] **Step 2: Verify**

Run: `pytest tests/integration/backend/test_tenant_service.py tests/integration/backend/test_auth_user_service.py -v`
Expected: PASS (db must be reachable).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/backend/conftest.py tests/integration/__init__.py tests/integration/backend/__init__.py
git commit -m "test(integration): db_session fixture for backend integration tests"
```

---

## Phase 4 — FastAPI dependencies

### Task 4.1: Rewrite `dependencies.py`

**Files:**
- Replace: `backend/src/auth/dependencies.py`
- Test: `tests/integration/backend/test_auth_dependencies.py`

- [ ] **Step 1: Replace file**

```python
# backend/src/auth/dependencies.py
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from ..db.models import Tenant, User
from ..db.session import get_session
from . import service as auth_service
from .security import decode_session_token

SESSION_COOKIE = "waf_session"
TOTP_ENROL_COOKIE = "waf_totp_enrol"


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="not authenticated")
    payload = decode_session_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="invalid or expired session")
    try:
        user_id = int(payload.get("sub", "0"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="invalid session") from None
    user = await auth_service.get_user(session, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user no longer exists")
    return user


async def require_verified(user: User = Depends(get_current_user)) -> User:
    if user.email_verified_at is None:
        raise HTTPException(status_code=403, detail="email not verified")
    # Check suspended tenant (logout-on-suspend per spec §8.3)
    return user


async def require_admin(user: User = Depends(require_verified)) -> User:
    if user.platform_role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    if user.totp_enabled_at is None:
        raise HTTPException(status_code=403, detail="admin must enrol totp")
    return user


async def require_client(
    user: User = Depends(require_verified),
    session: AsyncSession = Depends(get_session),
) -> User:
    if user.platform_role != "client":
        raise HTTPException(status_code=403, detail="client role required")
    tenant = await session.get(Tenant, user.tenant_id)
    if tenant and tenant.suspended_at is not None:
        raise HTTPException(status_code=403, detail="tenant suspended")
    return user


async def require_tenant_owner(user: User = Depends(require_client)) -> User:
    if user.tenant_role != "owner":
        raise HTTPException(status_code=403, detail="tenant owner required")
    return user


async def current_tenant(
    user: User = Depends(require_client),
    session: AsyncSession = Depends(get_session),
) -> Tenant:
    tenant = await session.get(Tenant, user.tenant_id)
    if not tenant:
        raise HTTPException(status_code=403, detail="tenant missing")
    return tenant
```

- [ ] **Step 2: Smoke test via FastAPI TestClient**

```python
# tests/integration/backend/test_auth_dependencies.py
import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import Depends, FastAPI
from backend.src.auth.dependencies import (
    get_current_user, require_admin, require_client, current_tenant, SESSION_COOKIE,
)
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth
from backend.src.tenants import service as tenants


def _app():
    app = FastAPI()
    @app.get("/me")
    async def me(u=Depends(get_current_user)):
        return {"id": u.id}
    @app.get("/admin")
    async def admin(u=Depends(require_admin)):
        return {"ok": True}
    @app.get("/client")
    async def client(t=Depends(current_tenant)):
        return {"tenant": t.name}
    return app


@pytest.mark.asyncio
async def test_unauthenticated_401(db_session):
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get("/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_client_can_access_current_tenant(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id, email_verified=True)
    token = create_session_token(user_id=u.id, platform_role="client", tenant_id=t.id, tenant_role="owner")
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get("/client", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    assert r.json()["tenant"] == "acme"
```

(Note: this test will only pass once `get_session` is wired to the test db. Either monkeypatch `get_session` in conftest, or extract the dependency override pattern — recommend overriding via `app.dependency_overrides[get_session] = lambda: db_session`.)

- [ ] **Step 3: Run tests pass**

Run: `pytest tests/integration/backend/test_auth_dependencies.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/src/auth/dependencies.py tests/integration/backend/test_auth_dependencies.py
git commit -m "feat(auth): new FastAPI dependencies for SaaS auth (platform/tenant gating)"
```

---

## Phase 5 — Tenant isolation across services

### Task 5.1: Refactor connections service

**Files:**
- Modify: `backend/src/connections/service.py`
- Modify: `backend/src/connections/router.py`
- Test: `tests/integration/backend/test_connections_tenant_scoping.py`

- [ ] **Step 1: Audit current functions**

Run: `grep -n "select(Connection)" backend/src/connections/service.py` — list all queries.

- [ ] **Step 2: Add `tenant: Tenant` argument to every service function**

For each `list/get/create/update/delete` function, add `tenant: Tenant` as the first arg after `session` and add `.where(Connection.tenant_id == tenant.id)` to every `select`. On `create`, set `tenant_id=tenant.id`. Example:

```python
async def list_connections(session: AsyncSession, tenant: Tenant) -> list[Connection]:
    result = await session.execute(
        select(Connection).where(Connection.tenant_id == tenant.id).order_by(Connection.id)
    )
    return list(result.scalars().all())


async def get_connection(session: AsyncSession, tenant: Tenant, connection_id: int) -> Connection | None:
    result = await session.execute(
        select(Connection).where(Connection.id == connection_id, Connection.tenant_id == tenant.id)
    )
    return result.scalar_one_or_none()
```

- [ ] **Step 3: Update router**

Every endpoint adds `tenant: Tenant = Depends(current_tenant)` and passes through:

```python
@router.get("/connections")
async def list_(
    tenant: Tenant = Depends(current_tenant),
    session: AsyncSession = Depends(get_session),
):
    return await service.list_connections(session, tenant)
```

- [ ] **Step 4: Write two-tenant safety test**

```python
# tests/integration/backend/test_connections_tenant_scoping.py
import pytest
from backend.src.connections import service as conns
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_tenant_a_cannot_list_b_connections(db_session):
    a = await tenants.create_tenant(db_session, name="a", display_name="A")
    b = await tenants.create_tenant(db_session, name="b", display_name="B")
    # Create a connection in B
    await conns.create_connection(db_session, b, domain="b.example.com", ...)  # fill required args
    listed = await conns.list_connections(db_session, a)
    assert listed == []


@pytest.mark.asyncio
async def test_tenant_a_cannot_get_b_connection_by_id(db_session):
    a = await tenants.create_tenant(db_session, name="a", display_name="A")
    b = await tenants.create_tenant(db_session, name="b", display_name="B")
    c_b = await conns.create_connection(db_session, b, domain="b.example.com", ...)
    assert await conns.get_connection(db_session, a, c_b.id) is None
```

- [ ] **Step 5: Run tests pass**

Run: `pytest tests/integration/backend/test_connections_tenant_scoping.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/connections/service.py backend/src/connections/router.py tests/integration/backend/test_connections_tenant_scoping.py
git commit -m "feat(connections): tenant-scoped service + router; two-tenant safety tests"
```

### Task 5.2: Repeat for crowdsec, modsecurity, dashboard, monitoring, tests

For each module under `backend/src/` that owns tenant-scoped resources (per Task 1.3 audit):

- [ ] Apply the same pattern: `tenant: Tenant` first arg after `session`, filter every `select` by `tenant.id`, set `tenant_id=tenant.id` on create.
- [ ] Add a two-tenant safety test mirroring the structure of `test_connections_tenant_scoping.py`.
- [ ] Commit per module (e.g., `feat(crowdsec): tenant scoping`).

Monitoring is **admin-only** (not tenant-scoped) — its endpoints use `require_admin`, not `current_tenant`. Document this exception in the test for that module.

### Task 5.3: AST guard test

**Files:**
- Create: `tests/unit/backend/test_tenant_filter_guard.py`

- [ ] **Step 1: Write the guard**

```python
# tests/unit/backend/test_tenant_filter_guard.py
import ast
from pathlib import Path

TENANT_SCOPED_MODELS = {"Connection"}  # extend as more tenant-scoped models are introduced
SERVICE_DIRS = ["connections"]  # extend per module reviewed in Task 5.2


def _all_select_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "select":
            if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in TENANT_SCOPED_MODELS:
                yield node


def _has_tenant_filter(call_node: ast.Call, source: str) -> bool:
    # Walk up the surrounding expression and look for ".where(...tenant_id...)"
    # Simple heuristic: the source line and the next 5 should mention "tenant_id"
    start = call_node.lineno
    snippet = "\n".join(source.splitlines()[start - 1 : start + 8])
    return "tenant_id" in snippet


def test_tenant_scoped_selects_have_tenant_filter():
    repo_root = Path(__file__).resolve().parents[3]
    offenders = []
    for module in SERVICE_DIRS:
        path = repo_root / "backend" / "src" / module / "service.py"
        if not path.exists():
            continue
        source = path.read_text()
        tree = ast.parse(source)
        for call in _all_select_calls(tree):
            if not _has_tenant_filter(call, source):
                offenders.append(f"{path}:{call.lineno}")
    assert offenders == [], f"tenant_id filter missing at: {offenders}"
```

Update `TENANT_SCOPED_MODELS` and `SERVICE_DIRS` as new tenant-scoped resources are added.

- [ ] **Step 2: Run pass**

Run: `pytest tests/unit/backend/test_tenant_filter_guard.py -v`
Expected: PASS.

- [ ] **Step 3: Verify the guard actually catches violations**

Temporarily remove the `.where(...tenant_id...)` from one service query, re-run the test — it must FAIL — then restore.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/backend/test_tenant_filter_guard.py
git commit -m "test(guard): AST check that tenant-scoped selects filter by tenant_id"
```

---

## Phase 6 — Captcha (Turnstile)

### Task 6.1: Turnstile verifier

**Files:**
- Create: `backend/src/auth/captcha.py`
- Test: `tests/unit/backend/test_captcha.py`

- [ ] **Step 1: Failing test**

```python
# tests/unit/backend/test_captcha.py
import pytest
import respx
from httpx import Response
from backend.src.auth import captcha


@pytest.mark.asyncio
@respx.mock
async def test_verify_success(monkeypatch):
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "sec")
    from backend.src.config import get_settings
    get_settings.cache_clear()
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").respond(
        200, json={"success": True}
    )
    assert await captcha.verify("token", remote_ip="1.2.3.4") is True


@pytest.mark.asyncio
@respx.mock
async def test_verify_failure(monkeypatch):
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "sec")
    from backend.src.config import get_settings
    get_settings.cache_clear()
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").respond(
        200, json={"success": False, "error-codes": ["invalid-input-response"]}
    )
    assert await captcha.verify("token", remote_ip="1.2.3.4") is False


@pytest.mark.asyncio
async def test_verify_disabled_passes(monkeypatch):
    monkeypatch.delenv("WAF_TURNSTILE_SECRET_KEY", raising=False)
    from backend.src.config import get_settings
    get_settings.cache_clear()
    # When no secret configured, verify is a no-op pass (dev mode)
    assert await captcha.verify("anything") is True
```

Add `respx>=0.20` to `tests/requirements.txt`.

- [ ] **Step 2: Implement**

```python
# backend/src/auth/captcha.py
import httpx
from ..config import get_settings

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify(token: str | None, remote_ip: str | None = None) -> bool:
    settings = get_settings()
    if not settings.turnstile_secret_key:
        return True
    if not token:
        return False
    data = {"secret": settings.turnstile_secret_key, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.post(SITEVERIFY_URL, data=data)
            return bool(r.json().get("success", False))
        except httpx.HTTPError:
            return False
```

- [ ] **Step 3: Run tests pass + commit**

```bash
pytest tests/unit/backend/test_captcha.py -v
git add backend/src/auth/captcha.py tests/unit/backend/test_captcha.py tests/requirements.txt
git commit -m "feat(auth): Cloudflare Turnstile siteverify wrapper"
```

---

## Phase 7 — Email transport

### Task 7.1: SMTP sender + Jinja templates

**Files:**
- Create: `backend/src/auth/email.py`
- Create: `backend/src/auth/email_templates/verify_email.html`, `reset_password.html`
- Test: `tests/unit/backend/test_email.py`

- [ ] **Step 1: Templates**

```html
<!-- backend/src/auth/email_templates/verify_email.html -->
<p>Hi {{ display_name }},</p>
<p>Confirm your email to activate your WAF account:</p>
<p><a href="{{ verify_url }}">{{ verify_url }}</a></p>
<p>This link expires in 24 hours.</p>
```

```html
<!-- backend/src/auth/email_templates/reset_password.html -->
<p>Hi {{ display_name }},</p>
<p>Reset your password:</p>
<p><a href="{{ reset_url }}">{{ reset_url }}</a></p>
<p>This link expires in 1 hour. Ignore if you didn't request it.</p>
```

- [ ] **Step 2: Email module**

```python
# backend/src/auth/email.py
import logging
from email.message import EmailMessage
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
import aiosmtplib
from ..config import get_settings

logger = logging.getLogger(__name__)
_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "email_templates"),
    autoescape=select_autoescape(["html"]),
)


async def send_verify_email(*, to_email: str, display_name: str, verify_url: str) -> None:
    body = _env.get_template("verify_email.html").render(display_name=display_name, verify_url=verify_url)
    await _send(to_email, "Verify your WAF email", body)


async def send_password_reset(*, to_email: str, display_name: str, reset_url: str) -> None:
    body = _env.get_template("reset_password.html").render(display_name=display_name, reset_url=reset_url)
    await _send(to_email, "Reset your WAF password", body)


async def _send(to_email: str, subject: str, html_body: str) -> None:
    s = get_settings()
    if not s.smtp_host:
        logger.warning("SMTP not configured — would send to %s subj=%s", to_email, subject)
        logger.info("EMAIL BODY (dev):\n%s", html_body)
        return
    msg = EmailMessage()
    msg["From"] = f"{s.smtp_from_name} <{s.smtp_from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("This message requires an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")
    await aiosmtplib.send(
        msg,
        hostname=s.smtp_host,
        port=s.smtp_port,
        username=s.smtp_username,
        password=s.smtp_password,
        start_tls=s.smtp_starttls,
    )
```

- [ ] **Step 3: Test (mocking aiosmtplib)**

```python
# tests/unit/backend/test_email.py
import pytest
from unittest.mock import patch
from backend.src.auth import email


@pytest.mark.asyncio
async def test_dev_mode_logs_when_no_smtp(monkeypatch, caplog):
    monkeypatch.delenv("WAF_SMTP_HOST", raising=False)
    from backend.src.config import get_settings
    get_settings.cache_clear()
    caplog.set_level("INFO")
    await email.send_verify_email(to_email="a@b.com", display_name="Joe", verify_url="https://x/v?t=1")
    assert "EMAIL BODY" in caplog.text
    assert "https://x/v?t=1" in caplog.text


@pytest.mark.asyncio
async def test_sends_via_smtp_when_configured(monkeypatch):
    monkeypatch.setenv("WAF_SMTP_HOST", "smtp.example.com")
    from backend.src.config import get_settings
    get_settings.cache_clear()
    with patch("aiosmtplib.send") as m:
        await email.send_verify_email(to_email="a@b.com", display_name="Joe", verify_url="https://x/v?t=1")
        m.assert_awaited_once()
```

- [ ] **Step 4: Run tests pass + commit**

```bash
pytest tests/unit/backend/test_email.py -v
git add backend/src/auth/email.py backend/src/auth/email_templates/ tests/unit/backend/test_email.py
git commit -m "feat(auth): SMTP email transport + Jinja templates for verify & reset"
```

---

## Phase 8 — Password auth flows

### Task 8.1: Email verification service

**Files:**
- Create: `backend/src/auth/verification.py`
- Test: `tests/integration/backend/test_email_verification.py`

- [ ] **Step 1: Test**

```python
import pytest
from backend.src.auth import verification, service as auth
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_issue_and_consume(db_session):
    t = await tenants.create_tenant(db_session, name="a", display_name="A")
    u = await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id)
    token = await verification.issue(db_session, u, purpose="verify_email")
    assert isinstance(token, str)
    user_back = await verification.consume(db_session, token, purpose="verify_email")
    assert user_back.id == u.id
    # Second consume fails
    assert await verification.consume(db_session, token, purpose="verify_email") is None
```

- [ ] **Step 2: Implement**

```python
# backend/src/auth/verification.py
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db.models import EmailVerification, User

TTL = {"verify_email": timedelta(hours=24), "reset_password": timedelta(hours=1)}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def issue(session: AsyncSession, user: User, *, purpose: str) -> str:
    token = secrets.token_urlsafe(32)
    row = EmailVerification(
        user_id=user.id,
        purpose=purpose,
        token_hash=_hash(token),
        expires_at=datetime.now(UTC) + TTL[purpose],
    )
    session.add(row)
    await session.commit()
    return token


async def consume(session: AsyncSession, token: str, *, purpose: str) -> User | None:
    result = await session.execute(
        select(EmailVerification).where(
            EmailVerification.token_hash == _hash(token),
            EmailVerification.purpose == purpose,
            EmailVerification.used_at.is_(None),
            EmailVerification.expires_at > datetime.now(UTC),
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        return None
    row.used_at = datetime.now(UTC)
    user = await session.get(User, row.user_id)
    await session.commit()
    return user
```

- [ ] **Step 3: Run + commit**

```bash
pytest tests/integration/backend/test_email_verification.py -v
git add backend/src/auth/verification.py tests/integration/backend/test_email_verification.py
git commit -m "feat(auth): email-verification + password-reset token issuance & consumption"
```

### Task 8.2: Signup + verify-email endpoints

**Files:**
- Modify: `backend/src/auth/router.py` (rewrite to use new schemas + services)
- Test: `tests/integration/backend/test_auth_signup_flow.py`

- [ ] **Step 1: Replace router contents**

Build out a fresh `router.py` (full rewrite — old endpoints removed):

```python
# backend/src/auth/router.py
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import User
from ..db.session import get_session
from ..tenants import service as tenants_service
from . import service as auth_service, verification, email as mailer, captcha
from .dependencies import SESSION_COOKIE, TOTP_ENROL_COOKIE, get_current_user, require_verified
from .schemas import (
    ForgotPasswordRequest, LoginRequest, LoginResponse, ResetPasswordRequest,
    SignupRequest, UserPublic, VerifyEmailRequest,
)
from .security import (
    SESSION_TTL_SECONDS, create_session_token, sign_short_lived, verify_password,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


def _set_session_cookie(response: Response, token: str) -> None:
    s = get_settings()
    response.set_cookie(
        SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS,
        httponly=True, secure=s.cookie_secure, samesite="lax", path="/",
    )


@router.get("/providers")
async def providers():
    s = get_settings()
    return {
        "google": s.oauth_google_enabled,
        "github": s.oauth_github_enabled,
        "captcha_site_key": s.turnstile_site_key,
    }


@router.post("/signup", status_code=202)
async def signup(
    payload: SignupRequest, request: Request, session: AsyncSession = Depends(get_session),
):
    if not await captcha.verify(payload.captcha_token, remote_ip=request.client.host if request.client else None):
        raise HTTPException(status_code=400, detail="captcha failed")
    try:
        tenant = await tenants_service.create_tenant(
            session, name=payload.tenant_name, display_name=payload.tenant_name,
        )
    except tenants_service.InvalidTenantName:
        raise HTTPException(status_code=400, detail="invalid tenant name") from None
    except tenants_service.TenantNameTaken:
        raise HTTPException(status_code=409, detail="tenant name taken") from None

    try:
        user = await auth_service.create_client_user(
            session, email=payload.email, password=payload.password,
            tenant_id=tenant.id, tenant_role="owner",
            display_name=payload.display_name or "", email_verified=False,
        )
    except auth_service.EmailTaken:
        raise HTTPException(status_code=409, detail="email already in use") from None

    token = await verification.issue(session, user, purpose="verify_email")
    verify_url = f"{get_settings().public_base_url}/verify-email?token={token}"
    await mailer.send_verify_email(to_email=user.email, display_name=user.display_name, verify_url=verify_url)
    return {"message": "check your email"}


@router.post("/verify-email", response_model=LoginResponse)
async def verify_email(
    payload: VerifyEmailRequest, response: Response, session: AsyncSession = Depends(get_session),
):
    user = await verification.consume(session, payload.token, purpose="verify_email")
    if not user:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    await auth_service.mark_email_verified(session, user)
    token = create_session_token(
        user_id=user.id, platform_role=user.platform_role,
        tenant_id=user.tenant_id, tenant_role=user.tenant_role,
    )
    _set_session_cookie(response, token)
    return LoginResponse(user=UserPublic.from_user(user))


# /login, /logout, /forgot, /reset implemented in Task 8.3
```

- [ ] **Step 2: Integration test**

```python
# tests/integration/backend/test_auth_signup_flow.py
import pytest
from httpx import AsyncClient, ASGITransport
from backend.src.main import app  # adjust import
from backend.src.db.session import get_session
from backend.src.auth.dependencies import SESSION_COOKIE


@pytest.mark.asyncio
async def test_signup_then_verify(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    app.dependency_overrides[get_session] = lambda: db_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/auth/signup", json={
            "email": "a@b.com", "password": "hunter22a",
            "tenant_name": "acme", "captcha_token": "tok",
        })
        assert r.status_code == 202

        # Pluck the verify token directly out of the DB (we're in test)
        from sqlalchemy import select
        from backend.src.db.models import EmailVerification
        ev = (await db_session.execute(select(EmailVerification))).scalar_one()
        # Token cannot be recovered from hash — patch the issue path to capture, or
        # use a test-mode env var to dump tokens to logs. For this test, intercept
        # the email send via monkeypatch (recommended approach — see test_signup_via_email_capture).
```

(Adjust test to monkeypatch `mailer.send_verify_email` and capture the URL/token.)

- [ ] **Step 3: Run + commit**

```bash
pytest tests/integration/backend/test_auth_signup_flow.py -v
git add backend/src/auth/router.py tests/integration/backend/test_auth_signup_flow.py
git commit -m "feat(auth): /signup + /verify-email endpoints (captcha + email)"
```

### Task 8.3: Login, logout, forgot/reset password

**Files:**
- Modify: `backend/src/auth/router.py` (append)
- Test: `tests/integration/backend/test_auth_login_flow.py`, `test_auth_reset_flow.py`

- [ ] **Step 1: Append login/logout/forgot/reset to router**

```python
@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest, request: Request, response: Response,
    session: AsyncSession = Depends(get_session),
):
    if not await captcha.verify(payload.captcha_token, remote_ip=request.client.host if request.client else None):
        raise HTTPException(status_code=400, detail="captcha failed")
    user = await auth_service.authenticate(session, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")
    if user.email_verified_at is None:
        raise HTTPException(status_code=403, detail="email not verified")

    # TOTP handling
    from .totp import verify_code, verify_recovery
    needs_totp = (
        user.platform_role == "admin"
        or (user.platform_role == "client" and user.totp_enabled_at is not None)
    )
    if needs_totp and user.totp_secret is None:
        # Admin first-login enrol bootstrap
        enrol_cookie = sign_short_lived({"user_id": user.id}, ttl_seconds=600, purpose="totp_enrol")
        response.set_cookie(TOTP_ENROL_COOKIE, enrol_cookie, max_age=600, httponly=True,
                            secure=get_settings().cookie_secure, samesite="lax", path="/")
        raise HTTPException(status_code=403, detail="totp_enrol_required")
    if needs_totp:
        if not payload.totp_code:
            raise HTTPException(status_code=401, detail="totp_required")
        if not (verify_code(user.totp_secret, payload.totp_code) or await verify_recovery(session, user, payload.totp_code)):
            raise HTTPException(status_code=401, detail="invalid totp")

    await auth_service.touch_login(session, user)
    token = create_session_token(
        user_id=user.id, platform_role=user.platform_role,
        tenant_id=user.tenant_id, tenant_role=user.tenant_role,
    )
    _set_session_cookie(response, token)
    return LoginResponse(user=UserPublic.from_user(user))


@router.post("/logout", status_code=204)
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return None


@router.get("/me", response_model=UserPublic)
async def me(user: User = Depends(get_current_user)):
    return UserPublic.from_user(user)


@router.post("/password/forgot", status_code=202)
async def forgot(
    payload: ForgotPasswordRequest, request: Request, session: AsyncSession = Depends(get_session),
):
    if not await captcha.verify(payload.captcha_token, remote_ip=request.client.host if request.client else None):
        raise HTTPException(status_code=400, detail="captcha failed")
    user = await auth_service.get_by_email(session, payload.email)
    if user and user.email_verified_at:
        token = await verification.issue(session, user, purpose="reset_password")
        reset_url = f"{get_settings().public_base_url}/reset-password?token={token}"
        await mailer.send_password_reset(to_email=user.email, display_name=user.display_name, reset_url=reset_url)
    return {"message": "if that email exists, a reset link was sent"}


@router.post("/password/reset", status_code=204)
async def reset(payload: ResetPasswordRequest, session: AsyncSession = Depends(get_session)):
    user = await verification.consume(session, payload.token, purpose="reset_password")
    if not user:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    await auth_service.update_password(session, user, payload.new_password)
    return None
```

- [ ] **Step 2: Tests**

`test_auth_login_flow.py`: cover successful login, wrong password (401), unverified email (403), captcha fail (400).
`test_auth_reset_flow.py`: cover the full forgot → reset → login-with-new-password cycle, and the anti-enumeration 202.

- [ ] **Step 3: Run + commit**

```bash
pytest tests/integration/backend/test_auth_login_flow.py tests/integration/backend/test_auth_reset_flow.py -v
git add backend/src/auth/router.py tests/integration/backend/test_auth_login_flow.py tests/integration/backend/test_auth_reset_flow.py
git commit -m "feat(auth): /login + /logout + /password/forgot + /password/reset"
```

---

## Phase 9 — TOTP

### Task 9.1: TOTP helpers + endpoints

**Files:**
- Create: `backend/src/auth/totp.py`
- Modify: `backend/src/auth/router.py` (append TOTP endpoints)
- Test: `tests/unit/backend/test_totp.py`, `tests/integration/backend/test_auth_totp_flow.py`

- [ ] **Step 1: totp.py**

```python
# backend/src/auth/totp.py
import base64
import hashlib
import io
import secrets
from datetime import UTC, datetime
import pyotp
import qrcode
from sqlalchemy.ext.asyncio import AsyncSession
from ..db.models import User


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, *, account_label: str, issuer: str = "WAF") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account_label, issuer_name=issuer)


def qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def verify_code(secret: str | None, code: str) -> bool:
    if not secret:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(n: int = 10) -> tuple[list[str], list[str]]:
    """Returns (plain_codes, sha256_hashes)."""
    plain = [secrets.token_hex(5) for _ in range(n)]
    hashes = [hashlib.sha256(c.encode()).hexdigest() for c in plain]
    return plain, hashes


async def verify_recovery(session: AsyncSession, user: User, code: str) -> bool:
    if not user.recovery_codes_hash:
        return False
    h = hashlib.sha256(code.encode()).hexdigest()
    if h not in user.recovery_codes_hash:
        return False
    user.recovery_codes_hash = [x for x in user.recovery_codes_hash if x != h]
    await session.commit()
    return True


async def activate(session: AsyncSession, user: User) -> None:
    user.totp_enabled_at = datetime.now(UTC)
    await session.commit()
```

- [ ] **Step 2: Endpoints (append to router.py)**

```python
@router.post("/totp/setup")
async def totp_setup(
    request: Request, session: AsyncSession = Depends(get_session),
):
    from .security import verify_short_lived
    # Accept either a session cookie OR the totp-enrol cookie
    user: User | None = None
    sess_token = request.cookies.get(SESSION_COOKIE)
    if sess_token:
        try:
            user = await get_current_user(request, session)
        except HTTPException:
            user = None
    if user is None:
        enrol = request.cookies.get(TOTP_ENROL_COOKIE)
        payload = verify_short_lived(enrol or "", purpose="totp_enrol") if enrol else None
        if payload:
            user = await auth_service.get_user(session, payload["user_id"])
    if user is None:
        raise HTTPException(status_code=401, detail="not authorized for totp enrol")

    from . import totp
    secret = totp.generate_secret()
    plain, hashes = totp.generate_recovery_codes()
    user.totp_secret = secret
    user.recovery_codes_hash = hashes
    await session.commit()
    label = user.email
    return {
        "secret_base32": secret,
        "qr_code_data_uri": totp.qr_data_uri(totp.provisioning_uri(secret, account_label=label)),
        "recovery_codes": plain,
    }


@router.post("/totp/confirm")
async def totp_confirm(
    payload: TotpConfirmRequest, response: Response,
    request: Request, session: AsyncSession = Depends(get_session),
):
    from .security import verify_short_lived
    from . import totp
    user: User | None = None
    try:
        user = await get_current_user(request, session)
    except HTTPException:
        user = None
    if user is None:
        enrol = request.cookies.get(TOTP_ENROL_COOKIE)
        token_payload = verify_short_lived(enrol or "", purpose="totp_enrol") if enrol else None
        if token_payload:
            user = await auth_service.get_user(session, token_payload["user_id"])
    if user is None or not user.totp_secret:
        raise HTTPException(status_code=401, detail="not enrolled")
    if not totp.verify_code(user.totp_secret, payload.code):
        raise HTTPException(status_code=400, detail="invalid code")
    await totp.activate(session, user)
    # Issue session, clear enrol cookie
    response.delete_cookie(TOTP_ENROL_COOKIE, path="/")
    s_token = create_session_token(
        user_id=user.id, platform_role=user.platform_role,
        tenant_id=user.tenant_id, tenant_role=user.tenant_role,
    )
    _set_session_cookie(response, s_token)
    return {"ok": True, "user": UserPublic.from_user(user).model_dump()}


# Add schemas import: TotpConfirmRequest
```

- [ ] **Step 3: Tests**

`test_totp.py` (unit): verify_code with secret/no-secret, generate_recovery_codes uniqueness/length, provisioning_uri format.

`test_auth_totp_flow.py` (integration): admin user → first login → 403 totp_enrol_required + cookie set → POST /totp/setup with enrol-cookie → confirm with valid code → final session cookie issued.

- [ ] **Step 4: Run + commit**

```bash
pytest tests/unit/backend/test_totp.py tests/integration/backend/test_auth_totp_flow.py -v
git add backend/src/auth/totp.py backend/src/auth/router.py tests/unit/backend/test_totp.py tests/integration/backend/test_auth_totp_flow.py
git commit -m "feat(auth): TOTP enrol/confirm endpoints + recovery codes + login gating"
```

---

## Phase 10 — OAuth

### Task 10.1: OAuth client wiring + start endpoint

**Files:**
- Create: `backend/src/auth/oauth.py`
- Modify: `backend/src/auth/router.py` (append OAuth endpoints)
- Test: `tests/integration/backend/test_oauth_flow.py`

- [ ] **Step 1: oauth.py**

```python
# backend/src/auth/oauth.py
from httpx_oauth.clients.google import GoogleOAuth2
from httpx_oauth.clients.github import GitHubOAuth2
from ..config import get_settings


def get_client(provider: str):
    s = get_settings()
    if provider == "google" and s.oauth_google_enabled:
        return GoogleOAuth2(s.oauth_google_client_id, s.oauth_google_client_secret)
    if provider == "github" and s.oauth_github_enabled:
        return GitHubOAuth2(s.oauth_github_client_id, s.oauth_github_client_secret)
    return None


def redirect_uri(provider: str) -> str | None:
    s = get_settings()
    return {
        "google": s.oauth_google_redirect_uri,
        "github": s.oauth_github_redirect_uri,
    }.get(provider)


GOOGLE_SCOPES = ["openid", "email", "profile"]
GITHUB_SCOPES = ["read:user", "user:email"]


def scopes_for(provider: str) -> list[str]:
    return GOOGLE_SCOPES if provider == "google" else GITHUB_SCOPES
```

- [ ] **Step 2: Endpoints (append router.py)**

```python
from fastapi.responses import RedirectResponse
from .oauth import get_client, redirect_uri, scopes_for


OAUTH_STATE_COOKIE = "waf_oauth_state"


@router.get("/oauth/{provider}/start")
async def oauth_start(provider: str, intent: str, tenant_name: str | None = None):
    client = get_client(provider)
    ru = redirect_uri(provider)
    if not client or not ru or intent not in ("signup", "login"):
        raise HTTPException(status_code=400, detail="provider unavailable or invalid intent")
    state = sign_short_lived(
        {"intent": intent, "tenant_name": tenant_name, "provider": provider},
        ttl_seconds=600, purpose="oauth_state",
    )
    url = await client.get_authorization_url(ru, state=state, scope=scopes_for(provider))
    response = RedirectResponse(url=url, status_code=307)
    response.set_cookie(OAUTH_STATE_COOKIE, state, max_age=600, httponly=True,
                        secure=get_settings().cookie_secure, samesite="lax", path="/")
    return response


@router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str, code: str, state: str, request: Request, response: Response,
    session: AsyncSession = Depends(get_session),
):
    from .security import verify_short_lived
    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not cookie_state or cookie_state != state:
        raise HTTPException(status_code=400, detail="invalid oauth state")
    payload = verify_short_lived(state, purpose="oauth_state")
    if not payload or payload.get("provider") != provider:
        raise HTTPException(status_code=400, detail="invalid oauth state")
    client = get_client(provider)
    ru = redirect_uri(provider)
    if not client or not ru:
        raise HTTPException(status_code=400, detail="provider unavailable")

    token = await client.get_access_token(code, ru)
    # Fetch profile
    if provider == "google":
        profile = await _fetch_google_profile(token["access_token"])
    else:
        profile = await _fetch_github_profile(token["access_token"])

    if not profile.get("email") or not profile.get("email_verified", False):
        raise HTTPException(status_code=400, detail="provider email not verified")

    # Look up existing OAuth account
    from sqlalchemy import select
    from ..db.models import OAuthAccount
    existing = (await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.provider == provider,
            OAuthAccount.provider_account_id == profile["sub"],
        )
    )).scalar_one_or_none()

    if existing:
        user = await auth_service.get_user(session, existing.user_id)
    else:
        # No OAuth account. Branch on intent.
        intent = payload["intent"]
        if intent == "login":
            raise HTTPException(status_code=404, detail="no account; sign up first")
        # signup
        tenant_name = payload.get("tenant_name")
        if not tenant_name:
            raise HTTPException(status_code=400, detail="tenant_name required for signup")
        # Reject if email already exists (no auto-linking; spec §2)
        if await auth_service.get_by_email(session, profile["email"]):
            raise HTTPException(status_code=409, detail="email already in use; sign in with password")
        try:
            tenant = await tenants_service.create_tenant(
                session, name=tenant_name, display_name=tenant_name,
            )
        except (tenants_service.InvalidTenantName, tenants_service.TenantNameTaken) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        user = await auth_service.create_client_user(
            session, email=profile["email"], password=None,
            tenant_id=tenant.id, tenant_role="owner",
            display_name=profile.get("name", ""), email_verified=True,
        )
        session.add(OAuthAccount(
            user_id=user.id, provider=provider,
            provider_account_id=profile["sub"], email_at_provider=profile["email"],
        ))
        await session.commit()

    await auth_service.touch_login(session, user)
    s_token = create_session_token(
        user_id=user.id, platform_role=user.platform_role,
        tenant_id=user.tenant_id, tenant_role=user.tenant_role,
    )
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    _set_session_cookie(response, s_token)
    return RedirectResponse(url="/home", status_code=303)


async def _fetch_google_profile(access_token: str) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    r.raise_for_status()
    j = r.json()
    return {"sub": j["sub"], "email": j["email"], "email_verified": j.get("email_verified", False), "name": j.get("name", "")}


async def _fetch_github_profile(access_token: str) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=5.0) as c:
        h = {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"}
        u = (await c.get("https://api.github.com/user", headers=h)).json()
        emails = (await c.get("https://api.github.com/user/emails", headers=h)).json()
    primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
    if not primary:
        return {"email": None, "email_verified": False}
    return {"sub": str(u["id"]), "email": primary["email"], "email_verified": True, "name": u.get("name") or u.get("login", "")}
```

- [ ] **Step 3: Tests**

```python
# tests/integration/backend/test_oauth_flow.py
import pytest
from unittest.mock import AsyncMock, patch
# Mock client.get_authorization_url, client.get_access_token, _fetch_google_profile
# Cover: signup new, signup with email collision (409), signup with taken tenant (400),
# login existing, login no-account (404), provider email not verified (400).
```

- [ ] **Step 4: Run + commit**

```bash
pytest tests/integration/backend/test_oauth_flow.py -v
git add backend/src/auth/oauth.py backend/src/auth/router.py tests/integration/backend/test_oauth_flow.py
git commit -m "feat(auth): Google + GitHub OAuth (signup/login with no auto-linking)"
```

---

## Phase 11 — Admin endpoints

### Task 11.1: Admin tenants router

**Files:**
- Create: `backend/src/admin/__init__.py`, `backend/src/admin/router.py`, `backend/src/admin/service.py`
- Test: `tests/integration/backend/test_admin_tenants.py`

- [ ] **Step 1: service.py**

```python
# backend/src/admin/service.py
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db.models import Connection, Tenant, User


async def list_tenants(session: AsyncSession) -> list[dict]:
    result = await session.execute(
        select(
            Tenant,
            func.count(User.id).label("user_count"),
            func.max(User.last_login_at).label("last_activity"),
        ).outerjoin(User, User.tenant_id == Tenant.id).group_by(Tenant.id)
    )
    rows = []
    for tenant, user_count, last_activity in result.all():
        conn_count = await session.scalar(
            select(func.count(Connection.id)).where(Connection.tenant_id == tenant.id)
        )
        owner = (await session.execute(
            select(User).where(User.tenant_id == tenant.id, User.tenant_role == "owner")
        )).scalar_one_or_none()
        rows.append({
            "id": tenant.id, "name": tenant.name, "display_name": tenant.display_name,
            "owner_email": owner.email if owner else None,
            "user_count": user_count, "connection_count": conn_count,
            "created_at": tenant.created_at, "suspended_at": tenant.suspended_at,
            "last_activity": last_activity,
        })
    return rows


async def get_tenant_detail(session: AsyncSession, tenant_id: int) -> dict | None:
    t = await session.get(Tenant, tenant_id)
    if not t:
        return None
    users = (await session.execute(select(User).where(User.tenant_id == tenant_id))).scalars().all()
    conns = (await session.execute(select(Connection).where(Connection.tenant_id == tenant_id))).scalars().all()
    return {
        "tenant": {
            "id": t.id, "name": t.name, "display_name": t.display_name,
            "created_at": t.created_at, "suspended_at": t.suspended_at,
        },
        "users": [
            {"id": u.id, "email": u.email, "tenant_role": u.tenant_role,
             "last_login_at": u.last_login_at, "email_verified": u.email_verified_at is not None,
             "totp_enabled": u.totp_enabled_at is not None}
            for u in users
        ],
        "connections": [{"id": c.id, "name": c.name, "domain": c.domain, "status": c.status} for c in conns],
    }
```

- [ ] **Step 2: router.py**

```python
# backend/src/admin/router.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth.dependencies import require_admin
from ..db.session import get_session
from ..tenants import service as tenants_service
from . import service

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/tenants", dependencies=[Depends(require_admin)])
async def list_(session: AsyncSession = Depends(get_session)):
    return await service.list_tenants(session)


@router.get("/tenants/{tenant_id}", dependencies=[Depends(require_admin)])
async def detail(tenant_id: int, session: AsyncSession = Depends(get_session)):
    d = await service.get_tenant_detail(session, tenant_id)
    if not d:
        raise HTTPException(status_code=404, detail="tenant not found")
    return d


@router.post("/tenants/{tenant_id}/suspend", dependencies=[Depends(require_admin)])
async def suspend(tenant_id: int, session: AsyncSession = Depends(get_session)):
    t = await tenants_service.suspend(session, tenant_id)
    if not t:
        raise HTTPException(status_code=404)
    return {"suspended_at": t.suspended_at}


@router.post("/tenants/{tenant_id}/unsuspend", dependencies=[Depends(require_admin)])
async def unsuspend(tenant_id: int, session: AsyncSession = Depends(get_session)):
    t = await tenants_service.unsuspend(session, tenant_id)
    if not t:
        raise HTTPException(status_code=404)
    return {"suspended_at": None}


@router.delete("/tenants/{tenant_id}", status_code=204, dependencies=[Depends(require_admin)])
async def delete_(
    tenant_id: int, confirm: str = Query(...), session: AsyncSession = Depends(get_session),
):
    t = await tenants_service.get(session, tenant_id)
    if not t:
        raise HTTPException(status_code=404)
    if confirm != t.name:
        raise HTTPException(status_code=400, detail="confirm value must equal tenant name")
    await tenants_service.delete(session, tenant_id)
```

- [ ] **Step 3: Wire router into `backend/src/main.py`**

Add `from .admin.router import router as admin_router` and `app.include_router(admin_router)`.

- [ ] **Step 4: Test**

Cover: non-admin gets 403, admin without TOTP gets 403, admin gets list/detail, suspend/unsuspend toggles `suspended_at`, delete requires confirm matching tenant name.

- [ ] **Step 5: Commit**

```bash
git add backend/src/admin/ tests/integration/backend/test_admin_tenants.py backend/src/main.py
git commit -m "feat(admin): /api/admin/tenants list/detail/suspend/delete"
```

---

## Phase 12 — CLI admin seeding

### Task 12.1: typer CLI + bootstrap guard

**Files:**
- Create: `backend/src/cli/__init__.py`, `backend/src/cli/__main__.py`, `backend/src/cli/create_admin.py`
- Create: `scripts/create-admin.sh`
- Modify: `backend/src/main.py` (503-on-no-admin)

- [ ] **Step 1: CLI**

```python
# backend/src/cli/__main__.py
import asyncio
import typer
from .create_admin import create_admin_cmd

app = typer.Typer()
app.command("create-admin")(create_admin_cmd)

if __name__ == "__main__":
    app()
```

```python
# backend/src/cli/create_admin.py
import asyncio
import getpass
import secrets
import typer
from ..auth import service as auth
from ..db.base import get_sessionmaker


def create_admin_cmd(email: str = typer.Option(..., "--email"), password: str | None = typer.Option(None, "--password")):
    async def _run():
        Session = get_sessionmaker()
        async with Session() as session:
            pw = password or getpass.getpass("admin password (or blank to auto-generate): ") or secrets.token_urlsafe(16)
            user = await auth.create_admin(session, email=email, password=pw)
            typer.echo(f"created admin id={user.id} email={user.email}")
            if not password:
                typer.echo(f"PASSWORD: {pw}")
    asyncio.run(_run())
```

- [ ] **Step 2: 503-on-no-admin in login**

In `backend/src/auth/router.py`, at the top of `/login`:

```python
if await auth_service.count_admins(session) == 0:
    raise HTTPException(status_code=503, detail="system not provisioned")
```

- [ ] **Step 3: shell wrapper**

```bash
#!/usr/bin/env bash
# scripts/create-admin.sh
exec docker compose exec backend python -m backend.cli create-admin "$@"
```

- [ ] **Step 4: Test + commit**

Manual test:
```bash
docker compose down -v && docker compose up -d postgres && docker compose run --rm backend alembic upgrade head
./scripts/create-admin.sh --email a@b.com
# Then attempt login flow from frontend; first login must require TOTP enrol.
```

```bash
git add backend/src/cli/ scripts/create-admin.sh backend/src/auth/router.py
git commit -m "feat(cli): create-admin command + 503 when no admin exists"
```

---

## Phase 13 — Filesystem isolation (Angie/ModSec)

### Task 13.1: Move config writers to tenant subtree

**Files:**
- Modify: `backend/src/angie/*.py` (generator)
- Modify: `backend/src/modsecurity/*.py`
- Modify: `backend/src/connections/service.py` (pass tenant through to generators)

- [ ] **Step 1: Identify base path**

Find where current code writes `/var/lib/waf/compose/...`. Replace with `/var/lib/waf/tenants/<tenant_id>/compose/...`.

- [ ] **Step 2: Refactor generator function signatures**

Add `tenant: Tenant` parameter; compute `base = Path("/var/lib/waf/tenants") / str(tenant.id)`.

- [ ] **Step 3: Update Angie include directive**

In Angie main config (`configs/angie.conf` or similar): change `include /var/lib/waf/compose/*.conf;` to `include /var/lib/waf/tenants/*/compose/*.conf;`.

- [ ] **Step 4: Tenant deletion hook**

In `backend/src/admin/service.py` (or `tenants/service.py`), on tenant delete: `shutil.rmtree(Path("/var/lib/waf/tenants") / str(tenant_id), ignore_errors=True)`. Then trigger Angie reload (existing reload pathway).

- [ ] **Step 5: Suspended tenant excluded from include**

On suspend: rename `/var/lib/waf/tenants/<id>/compose/` to `/var/lib/waf/tenants/<id>/compose.suspended/` (excluded from `*/compose/*.conf` glob). On unsuspend: rename back. Reload Angie.

- [ ] **Step 6: Commit**

```bash
git add backend/src/angie/ backend/src/modsecurity/ backend/src/connections/ configs/
git commit -m "feat(isolation): per-tenant /var/lib/waf/tenants/<id>/ config tree + suspend hook"
```

---

## Phase 14 — Frontend primitives

### Task 14.1: AuthContext + types update

**Files:**
- Modify: `frontend/src/context/AuthContext.tsx`

- [ ] **Step 1: Update User type + context API**

```ts
// frontend/src/context/AuthContext.tsx (top)
export interface User {
  id: number;
  email: string;
  display_name: string;
  platform_role: "admin" | "client";
  tenant_id: number | null;
  tenant_role: "owner" | "member" | null;
  email_verified: boolean;
  totp_enabled: boolean;
}

// login() signature now: (email, password, captchaToken, totpCode?) -> Promise<{ user: User } | { totp_required: true } | { enrol_required: true }>
// signup(email, password, tenantName, captchaToken, displayName?) -> Promise<{ message: string }>
// oauthStart(provider, intent, tenantName?) -> redirects window.location
```

Update all call sites of the old `login(username, password)` to the new signature.

- [ ] **Step 2: Commit**

```bash
git add frontend/src/context/AuthContext.tsx
git commit -m "feat(frontend): AuthContext typed for SaaS user shape"
```

### Task 14.2: RequireRole + TurnstileWidget

**Files:**
- Create: `frontend/src/components/RequireRole.tsx` (rename of AdminOnly.tsx)
- Delete: `frontend/src/components/AdminOnly.tsx`
- Create: `frontend/src/components/TurnstileWidget.tsx`

- [ ] **Step 1: RequireRole**

```tsx
// frontend/src/components/RequireRole.tsx
import { Navigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../context/AuthContext";

type Role = "admin" | "client";
export default function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (user.platform_role !== role) return <Navigate to={user.platform_role === "admin" ? "/monitoring" : "/home"} replace />;
  return <>{children}</>;
}
```

- [ ] **Step 2: TurnstileWidget**

```tsx
// frontend/src/components/TurnstileWidget.tsx
import { useEffect, useRef } from "react";

declare global { interface Window { turnstile?: any; } }

export default function TurnstileWidget({
  siteKey, onToken,
}: { siteKey: string; onToken: (token: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const renderWidget = () => {
      if (!ref.current || !window.turnstile) return;
      window.turnstile.render(ref.current, { sitekey: siteKey, callback: onToken });
    };
    if (window.turnstile) renderWidget();
    else {
      const s = document.createElement("script");
      s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
      s.async = true;
      s.onload = renderWidget;
      document.head.appendChild(s);
    }
  }, [siteKey, onToken]);

  return <div ref={ref} />;
}
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/RequireRole.tsx frontend/src/components/TurnstileWidget.tsx
git rm frontend/src/components/AdminOnly.tsx
git commit -m "feat(frontend): RequireRole + TurnstileWidget primitives"
```

---

## Phase 15 — Frontend auth pages

### Task 15.1: Login.tsx — Turnstile + OAuth + TOTP

**Files:**
- Modify: `frontend/src/pages/Login.tsx`

- [ ] **Step 1: Replace login form**

Add: email field instead of username, Turnstile widget, OAuth buttons (gated by `providers.google/github` from `/api/auth/providers`), conditional TOTP field that appears after a 401-with-`totp_required`. Wire login() to new signature. Redirect targets:
- `enrol_required` → `/totp-setup`
- `totp_required` → show TOTP input field, retry submit
- success → `/home` (or `/monitoring` for admin)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/pages/Login.tsx frontend/src/api/client.ts
git commit -m "feat(frontend): Login page — email + captcha + OAuth + TOTP"
```

### Task 15.2: Signup.tsx (new)

**Files:**
- Create: `frontend/src/pages/Signup.tsx`

Mirror Login.tsx layout. Fields: email, password, `tenant_name` (with regex hint), display_name (optional), Turnstile. OAuth buttons routed to `/api/auth/oauth/{provider}/start?intent=signup&tenant_name=...`. Submit → POST `/api/auth/signup`, on 202 show "check your email" screen.

- [ ] Commit:
```bash
git add frontend/src/pages/Signup.tsx
git commit -m "feat(frontend): Signup page"
```

### Task 15.3: VerifyEmail, ForgotPassword, ResetPassword, TotpSetup

**Files:**
- Create: `frontend/src/pages/VerifyEmail.tsx`, `ForgotPassword.tsx`, `ResetPassword.tsx`, `TotpSetup.tsx`

Each one is a focused page that calls a single endpoint. Keep them small (50-100 LOC each). Use the existing CSS variables (`--ink`, `--cream`, `--red`) for visual consistency.

- [ ] Commit each separately:
```bash
git add frontend/src/pages/VerifyEmail.tsx
git commit -m "feat(frontend): VerifyEmail page"
# repeat for the others
```

---

## Phase 16 — Frontend admin pages

### Task 16.1: Clients.tsx + ClientDetail.tsx

**Files:**
- Create: `frontend/src/pages/Clients.tsx`, `ClientDetail.tsx`
- Delete: `frontend/src/pages/Users.tsx`

- [ ] **Step 1: Clients list**

Table with columns matching spec §8.1. Calls `GET /api/admin/tenants`. Actions: suspend/unsuspend (POST), delete (DELETE with `?confirm=<name>`).

- [ ] **Step 2: Detail page**

Read-only. Lists users and connections (metadata only — no logs/config content). Calls `GET /api/admin/tenants/:id`.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/Clients.tsx frontend/src/pages/ClientDetail.tsx
git rm frontend/src/pages/Users.tsx
git commit -m "feat(frontend): Clients admin page + detail; remove Users page"
```

---

## Phase 17 — Sidebar reshape + routes

### Task 17.1: Layout.tsx sidebar restructure

**Files:**
- Modify: `frontend/src/components/Layout.tsx`
- Modify: `frontend/src/App.tsx` (or wherever routes are declared)

- [ ] **Step 1: Sidebar config**

Replace the conditional `user?.role === "admin"` blocks with a declarative array:

```tsx
type NavItem = { path: string; label: string; icon: ReactNode; requires: "admin" | "client" };
type NavSection = { title: string; items: NavItem[] };

const NAV: Record<"admin" | "client", NavSection[]> = {
  admin: [
    { title: t("nav.operations"), items: [
      { path: "/monitoring", label: t("nav.monitoring"), icon: <Activity />, requires: "admin" },
      { path: "/clients",    label: t("nav.clients"),    icon: <UsersIcon />, requires: "admin" },
    ]},
  ],
  client: [
    { title: t("nav.overview"), items: [
      { path: "/home",      label: t("nav.home"),      icon: <HomeIcon />,        requires: "client" },
      { path: "/dashboard", label: t("nav.dashboard"), icon: <LayoutDashboard />, requires: "client" },
    ]},
    { title: t("nav.management"), items: [
      { path: "/connections", label: t("nav.connections"),   icon: <Link2 />,    requires: "client" },
      { path: "/config",      label: t("nav.configuration"), icon: <Settings />, requires: "client" },
    ]},
    { title: t("nav.security"), items: [
      { path: "/crowdsec", label: t("nav.crowdsec"), icon: <Ban />,      requires: "client" },
      { path: "/tests",    label: t("nav.tests"),    icon: <TestTube />, requires: "client" },
    ]},
  ],
};
```

Render the appropriate side of the map based on `user.platform_role`.

- [ ] **Step 2: App routes**

Wrap each route in `<RequireRole role="admin">` or `<RequireRole role="client">`. Public routes: `/login`, `/signup`, `/verify-email`, `/forgot-password`, `/reset-password`, `/totp-setup`.

- [ ] **Step 3: i18n strings**

Add `nav.operations`, `nav.clients` (admin), and verify `nav.overview/management/security` exist for client. Update `frontend/src/i18n/translations.ts`.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/Layout.tsx frontend/src/App.tsx frontend/src/i18n/translations.ts
git commit -m "feat(frontend): sidebar split by platform_role; RequireRole at route level"
```

---

## Phase 18 — Env, scripts, deployment docs

### Task 18.1: docker-compose env passthrough

**Files:**
- Modify: `docker-compose.yml`, `docker-compose.swarm.yml`

- [ ] Add env passthrough in `backend.environment`:

```yaml
- WAF_PUBLIC_BASE_URL
- WAF_COOKIE_SECURE
- WAF_PASETO_KEY
- WAF_TURNSTILE_SITE_KEY
- WAF_TURNSTILE_SECRET_KEY
- WAF_SMTP_HOST
- WAF_SMTP_PORT
- WAF_SMTP_USERNAME
- WAF_SMTP_PASSWORD
- WAF_SMTP_FROM_EMAIL
- WAF_SMTP_FROM_NAME
- WAF_OAUTH_GOOGLE_CLIENT_ID
- WAF_OAUTH_GOOGLE_CLIENT_SECRET
- WAF_OAUTH_GOOGLE_REDIRECT_URI
- WAF_OAUTH_GITHUB_CLIENT_ID
- WAF_OAUTH_GITHUB_CLIENT_SECRET
- WAF_OAUTH_GITHUB_REDIRECT_URI
```

- [ ] Commit:
```bash
git add docker-compose.yml docker-compose.swarm.yml
git commit -m "build(compose): env passthrough for SaaS auth"
```

### Task 18.2: scripts/generate-env.sh + scripts/create-admin.sh

**Files:**
- Modify: `scripts/generate-env.sh`

- [ ] Append `WAF_*` placeholders for all new vars with sensible defaults (e.g., `WAF_COOKIE_SECURE=true`, `WAF_PUBLIC_BASE_URL=https://CHANGEME`, etc.). Mark OAuth/SMTP/Turnstile blocks as optional with `# (optional) ...` comments.

- [ ] Commit:
```bash
git add scripts/generate-env.sh
git commit -m "build(scripts): env scaffolding for SaaS auth"
```

### Task 18.3: README/CLAUDE.md update

**Files:**
- Modify: `README.md`, `CLAUDE.md`

- [ ] Add a "Provisioning" section: how to run `scripts/create-admin.sh`, how to configure OAuth (redirect URIs format `${WAF_PUBLIC_BASE_URL}/api/auth/oauth/{provider}/callback`), how to configure Turnstile (link to Cloudflare docs), how to configure SMTP.

- [ ] Commit:
```bash
git add README.md CLAUDE.md
git commit -m "docs: SaaS auth provisioning guide"
```

---

## Phase 19 — End-to-end tests

### Task 19.1: E2E full signup

**Files:**
- Create: `tests/e2e/auth/test_signup_flow.py`

- [ ] **Test outline:**

```python
import os
import re
import requests
import pytest

BASE = os.environ.get("WAF_E2E_URL", "http://localhost")

@pytest.mark.e2e
def test_full_signup_and_login():
    # Configure backend with WAF_TURNSTILE_SECRET_KEY unset → captcha is no-op
    email = "e2e@test.local"
    tenant_name = f"e2e-{os.getpid()}"
    r = requests.post(f"{BASE}/api/auth/signup", json={
        "email": email, "password": "hunter22a", "tenant_name": tenant_name,
        "captcha_token": "skip",
    })
    assert r.status_code == 202

    # In dev mode (no SMTP), backend logs the verify URL. Tail container logs:
    import subprocess
    logs = subprocess.check_output(["docker", "compose", "logs", "--tail=200", "backend"]).decode()
    m = re.search(r"verify-email\?token=([A-Za-z0-9_\-]+)", logs)
    assert m
    token = m.group(1)
    r = requests.post(f"{BASE}/api/auth/verify-email", json={"token": token})
    assert r.status_code == 200
    cookie = r.cookies.get("waf_session")
    assert cookie

    # Authenticated /me
    r = requests.get(f"{BASE}/api/auth/me", cookies={"waf_session": cookie})
    assert r.json()["email"] == email

    # Create a connection — should succeed under our tenant
    r = requests.post(f"{BASE}/api/connections", json={
        "name": "test", "domain": f"{tenant_name}.example.com",
    }, cookies={"waf_session": cookie})
    assert r.status_code in (200, 201)
```

- [ ] Commit:
```bash
git add tests/e2e/auth/test_signup_flow.py
git commit -m "test(e2e): full signup + verify + login + create connection"
```

### Task 19.2: E2E admin lifecycle

**Files:**
- Create: `tests/e2e/auth/test_admin_lifecycle.py`

Outline: create-admin via CLI → login (expect 403 enrol_required) → POST /totp/setup with enrol cookie → confirm with code from `pyotp.TOTP(secret).now()` → final session cookie → GET /api/admin/tenants → POST suspend → confirm client is logged out.

- [ ] Commit per test pass.

### Task 19.3: OAuth mocked E2E

Mock provider endpoints by configuring `WAF_OAUTH_GOOGLE_REDIRECT_URI` to point at a local mock server (small FastAPI app started inside the test). Two cases: signup new user, login existing user.

- [ ] Commit per test pass.

---

## Phase 20 — Final integration check

- [ ] **Step 1:** Run full test suite

```bash
docker compose down -v
docker compose up -d
docker compose run --rm backend alembic upgrade head
pytest tests/unit tests/integration -v
pytest tests/e2e -v -m e2e
```

Expected: all green.

- [ ] **Step 2:** Manual smoke

1. Create admin via CLI → login → TOTP enrol → see Monitoring + Clients only.
2. Sign up new tenant via password → email verify → see Home/Dashboard/Connections/etc.
3. Sign up new tenant via Google OAuth → tenant created, redirect to /home.
4. Admin suspends tenant → tenant user gets 403 on next request.
5. Admin deletes tenant with confirm=name → tenant + connections + /var/lib/waf/tenants/<id>/ wiped.

- [ ] **Step 3:** Final commit (if any cleanup needed) — otherwise no commit.

---

## Self-review checklist

- [x] Spec §3 (data isolation): Phase 5 + AST guard (Task 5.3) + two-tenant tests
- [x] Spec §4 (roles): Phase 4 deps + Phase 14 RequireRole + sidebar split
- [x] Spec §5 (schema): Task 1.1 + 1.2 + 1.3
- [x] Spec §6 (PASETO): Task 2.1
- [x] Spec §7.1 (password signup + verify): Task 8.1 + 8.2
- [x] Spec §7.2 (OAuth): Task 10.1
- [x] Spec §7.3 (login + captcha + TOTP gating): Task 6.1 + 8.3 + 9.1
- [x] Spec §7.4 (TOTP enrol): Task 9.1
- [x] Spec §7.5 (forgot/reset): Task 8.3
- [x] Spec §7.6 (logout): Task 8.3
- [x] Spec §8 (admin Clients page): Task 11.1 + 16.1
- [x] Spec §9 (frontend changes): Phases 14-17
- [x] Spec §10 (migration + CLI seed): Task 1.2 + 12.1
- [x] Spec §11 (testing strategy): unit tests in each phase + Phase 19 E2E
- [x] Spec §13 (filesystem isolation): Phase 13

## Notes for the executing agent

- Some tasks reference fixtures and routes that are introduced later. Run the test suite per phase, expecting cross-phase failures to clear up as phases complete. Each commit should leave the codebase coherent for the phase boundary, not necessarily for sub-task boundaries within a phase.
- Where exact pre-existing function signatures are not enumerated (e.g., `conns.create_connection(...)` in tests), substitute the real signature from the codebase at execution time — these stubs assume you'll inspect first.
- When deleting frontend files (`Users.tsx`, `AdminOnly.tsx`), grep for imports first and patch call sites in the same commit.
