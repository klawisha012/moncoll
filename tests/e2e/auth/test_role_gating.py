"""E2E: role gating — client vs admin vs anonymous.

Three principal cases from design doc D8:
  1. Client session   → GET /api/admin/tenants         → 403
  2. Admin session    → GET /api/connections/           → 403
  3. Unauthenticated  → GET /api/auth/me                → 401

Admin setup requires pyotp for TOTP confirmation.

Run:
    docker compose up -d
    docker compose exec backend alembic upgrade head
    WAF_API_URL=http://localhost:8000 \
        python -m pytest -m e2e tests/e2e/auth/test_role_gating.py -v
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import uuid

import pytest
import requests

try:
    import pyotp
    _PYOTP_AVAILABLE = True
except ImportError:
    _PYOTP_AVAILABLE = False

API_URL = os.environ.get("WAF_API_URL", "http://localhost:8000")
_CAPTCHA = "e2e-test-bypass"


def _unique() -> str:
    return uuid.uuid4().hex[:8]


def _seed_admin(email: str, password: str) -> bool:
    try:
        result = subprocess.run(
            [
                "docker", "compose", "exec", "-T", "backend",
                "python", "-m", "src.cli", "create-admin",
                "--email", email,
                "--password", password,
            ],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _login_client(email: str, password: str, tenant_name: str) -> requests.Session | None:
    """Sign up, extract verify token from logs, verify, return authenticated session."""
    s = requests.Session()
    r = s.post(
        f"{API_URL}/api/auth/signup",
        json={
            "email": email, "password": password,
            "tenant_name": tenant_name, "captcha_token": _CAPTCHA,
        },
        timeout=15,
    )
    if r.status_code != 202:
        s.close()
        return None

    time.sleep(1)
    try:
        logs = subprocess.check_output(
            ["docker", "compose", "logs", "--tail", "300", "backend"],
            stderr=subprocess.STDOUT, timeout=15,
        ).decode(errors="replace")
        m = re.search(r"/verify-email\?token=([A-Za-z0-9_\-]+)", logs)
    except Exception:
        m = None

    if not m:
        s.close()
        return None

    r = s.post(
        f"{API_URL}/api/auth/verify-email",
        json={"token": m.group(1)},
        timeout=10,
    )
    if r.status_code != 200:
        s.close()
        return None
    return s


def _login_admin(email: str, password: str) -> requests.Session | None:
    """Login admin and complete TOTP enrolment, return authenticated session."""
    if not _PYOTP_AVAILABLE:
        return None
    s = requests.Session()
    r = s.post(
        f"{API_URL}/api/auth/login",
        json={"email": email, "password": password, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    if r.status_code != 403 or r.json().get("detail") != "totp_enrol_required":
        s.close()
        return None

    r = s.post(f"{API_URL}/api/auth/totp/setup", timeout=10)
    if r.status_code != 200:
        s.close()
        return None
    secret = r.json()["secret_base32"]

    r = s.post(
        f"{API_URL}/api/auth/totp/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        timeout=10,
    )
    if r.status_code != 200:
        s.close()
        return None
    return s


# ---------------------------------------------------------------------------
# Test 1: Client → /api/admin/tenants → 403
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_client_cannot_access_admin_endpoints():
    """Client role must be rejected from /api/admin/tenants with 403."""
    email = f"gating-client-{_unique()}@example.com"
    tenant = f"gating{_unique()}"
    client = _login_client(email, "Password1!", tenant)
    if client is None:
        pytest.skip("Could not create/verify client account; check stack is running + SMTP dev mode")

    r = client.get(f"{API_URL}/api/admin/tenants", timeout=10)
    assert r.status_code == 403, (
        f"client should get 403 on admin endpoint, got {r.status_code}: {r.text}"
    )
    client.close()


# ---------------------------------------------------------------------------
# Test 2: Admin → /api/connections/ → 403
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.skipif(not _PYOTP_AVAILABLE, reason="pyotp not installed")
def test_admin_cannot_access_client_connections():
    """Admin role must be rejected from /api/connections/ with 403."""
    email = f"gating-admin-{_unique()}@example.com"
    if not _seed_admin(email, "AdminPass1!"):
        pytest.skip("Could not seed admin via CLI; check stack is running")

    admin = _login_admin(email, "AdminPass1!")
    if admin is None:
        pytest.skip("Could not complete admin TOTP enrolment")

    r = admin.get(f"{API_URL}/api/connections/", timeout=10)
    assert r.status_code == 403, (
        f"admin should get 403 on client connections endpoint, got {r.status_code}: {r.text}"
    )
    admin.close()


# ---------------------------------------------------------------------------
# Test 3: Unauthenticated → /api/auth/me → 401
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_unauthenticated_me_returns_401():
    """No cookie → /api/auth/me must return 401."""
    r = requests.get(f"{API_URL}/api/auth/me", timeout=10)
    assert r.status_code == 401, (
        f"unauthenticated /me should return 401, got {r.status_code}: {r.text}"
    )


@pytest.mark.e2e
def test_unauthenticated_admin_returns_401():
    """No cookie → /api/admin/tenants must return 401."""
    r = requests.get(f"{API_URL}/api/admin/tenants", timeout=10)
    assert r.status_code == 401, (
        f"unauthenticated /admin/tenants should return 401, got {r.status_code}: {r.text}"
    )
