"""E2E: admin lifecycle — CLI seed → login → TOTP enrol → admin actions → suspend.

Prerequisites:
- docker-compose stack running with `alembic upgrade head` applied.
- pyotp installed in the test environment: pip install pyotp

Run:
    docker compose up -d
    WAF_API_URL=http://localhost \
        python -m pytest -m e2e tests/e2e/auth/test_admin_lifecycle.py -v
"""
from __future__ import annotations

import os
import subprocess
import uuid

import pytest
import requests

try:
    import pyotp
    _PYOTP_AVAILABLE = True
except ImportError:
    _PYOTP_AVAILABLE = False

API_URL = os.environ.get("WAF_API_URL", "http://localhost")
_CAPTCHA = "e2e-test-bypass"


def _seed_admin(email: str, password: str) -> bool:
    """Run create-admin CLI inside the gobackend container. Returns True on success."""
    try:
        result = subprocess.run(
            [
                "docker", "compose", "exec", "-T", "gobackend",
                "/server", "create-admin",
                "-email", email,
                "-password", password,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _unique_email() -> str:
    return f"admin-e2e-{uuid.uuid4().hex[:8]}@example.com"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.skipif(not _PYOTP_AVAILABLE, reason="pyotp not installed")
def test_admin_lifecycle():
    """Full admin lifecycle: seed → login (403 enrol) → TOTP setup/confirm → list tenants."""
    admin_email = _unique_email()
    admin_password = "AdminPass1!"

    # ── 1. Seed admin via CLI ─────────────────────────────────────────────────
    seeded = _seed_admin(admin_email, admin_password)
    if not seeded:
        pytest.skip(
            "Could not seed admin via docker compose exec — "
            "check that the stack is running and alembic migrations applied."
        )

    s = requests.Session()

    # ── 2. Login → expect 403 totp_enrol_required ────────────────────────────
    r = s.post(
        f"{API_URL}/api/auth/login",
        json={"email": admin_email, "password": admin_password, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    assert r.status_code == 403, f"expected 403 enrol_required, got {r.status_code}: {r.text}"
    assert r.json().get("detail") == "totp_enrol_required"
    # The response must set the waf_totp_enrol cookie.
    assert "waf_totp_enrol" in s.cookies, "TOTP enrol cookie not set"

    # ── 3. POST /totp/setup with enrol cookie ─────────────────────────────────
    r = s.post(f"{API_URL}/api/auth/totp/setup", timeout=10)
    assert r.status_code == 200, f"totp/setup failed: {r.status_code} {r.text}"
    setup_body = r.json()
    assert "secret_base32" in setup_body
    assert "recovery_codes" in setup_body
    secret = setup_body["secret_base32"]
    recovery_codes: list[str] = setup_body["recovery_codes"]
    assert len(recovery_codes) > 0

    # ── 4. POST /totp/confirm with live TOTP code ─────────────────────────────
    totp_code = pyotp.TOTP(secret).now()
    r = s.post(
        f"{API_URL}/api/auth/totp/confirm",
        json={"code": totp_code},
        timeout=10,
    )
    assert r.status_code == 200, f"totp/confirm failed: {r.status_code} {r.text}"
    # Session cookie should now be set.
    assert "waf_session" in s.cookies, "Session cookie not set after TOTP confirm"

    # ── 5. GET /api/admin/tenants ─────────────────────────────────────────────
    r = s.get(f"{API_URL}/api/admin/tenants", timeout=10)
    assert r.status_code == 200, f"admin/tenants failed: {r.status_code} {r.text}"
    tenants = r.json()
    assert isinstance(tenants, list)

    s.close()


@pytest.mark.e2e
@pytest.mark.skipif(not _PYOTP_AVAILABLE, reason="pyotp not installed")
def test_admin_suspend_tenant():
    """Admin can suspend a client tenant; the tenant's session then returns 403."""
    admin_email = _unique_email()
    admin_password = "AdminPass2!"
    client_email = f"client-e2e-{uuid.uuid4().hex[:8]}@example.com"
    client_password = "ClientPass1!"
    tenant_name = f"tenant{uuid.uuid4().hex[:6]}"

    # ── Seed admin ────────────────────────────────────────────────────────────
    if not _seed_admin(admin_email, admin_password):
        pytest.skip("Could not seed admin; skipping suspend test")

    # ── Create + verify a client ──────────────────────────────────────────────
    import re, subprocess as sp, time

    client_session = requests.Session()
    r = client_session.post(
        f"{API_URL}/api/auth/signup",
        json={
            "email": client_email,
            "password": client_password,
            "tenant_name": tenant_name,
            "captcha_token": _CAPTCHA,
        },
        timeout=15,
    )
    if r.status_code == 503:
        pytest.skip("System not provisioned; skipping suspend test")
    assert r.status_code == 202

    time.sleep(1)
    try:
        logs = sp.check_output(
            ["docker", "compose", "logs", "--tail", "300", "gobackend"],
            stderr=sp.STDOUT, timeout=15,
        ).decode(errors="replace")
        m = re.search(r"/verify-email\?token=([A-Za-z0-9_\-]+)", logs)
    except Exception:
        m = None

    if not m:
        pytest.skip("Could not capture verify token; skipping suspend test")

    r = client_session.post(
        f"{API_URL}/api/auth/verify-email",
        json={"token": m.group(1)},
        timeout=10,
    )
    assert r.status_code == 200, f"client verify failed: {r.text}"
    tenant_id = r.json()["user"]["tenant_id"]

    # Client session should work now.
    r = client_session.get(f"{API_URL}/api/auth/me", timeout=10)
    assert r.status_code == 200

    # ── Admin login + TOTP ────────────────────────────────────────────────────
    admin_session = requests.Session()
    r = admin_session.post(
        f"{API_URL}/api/auth/login",
        json={"email": admin_email, "password": admin_password, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    assert r.status_code == 403 and r.json().get("detail") == "totp_enrol_required"

    r = admin_session.post(f"{API_URL}/api/auth/totp/setup", timeout=10)
    assert r.status_code == 200
    secret = r.json()["secret_base32"]

    r = admin_session.post(
        f"{API_URL}/api/auth/totp/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        timeout=10,
    )
    assert r.status_code == 200

    # ── Suspend the client tenant ─────────────────────────────────────────────
    r = admin_session.post(f"{API_URL}/api/admin/tenants/{tenant_id}/suspend", timeout=10)
    assert r.status_code == 200, f"suspend failed: {r.status_code} {r.text}"

    # ── Client /me should now return 403 (tenant suspended) ──────────────────
    r = client_session.get(f"{API_URL}/api/auth/me", timeout=10)
    assert r.status_code == 403, (
        f"expected 403 for suspended tenant, got {r.status_code}: {r.text}"
    )

    admin_session.close()
    client_session.close()
