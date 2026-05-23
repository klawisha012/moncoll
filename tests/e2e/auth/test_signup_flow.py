"""E2E: full signup → email verify → /me → create connection.

Requires the docker-compose stack to be running with dev-mode SMTP (no
WAF_SMTP_HOST configured). In dev mode the backend logs the verify URL
to stdout, which we capture via `docker compose logs`.

Run:
    docker compose up -d
    docker compose exec backend alembic upgrade head
    WAF_E2E_URL=http://localhost WAF_API_URL=http://localhost:8000 \
        python -m pytest -m e2e tests/e2e/auth/test_signup_flow.py -v
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import uuid

import pytest
import requests

API_URL = os.environ.get("WAF_API_URL", "http://localhost:8000")

# Captcha is skipped server-side when WAF_TURNSTILE_SECRET_KEY is unset.
# The sentinel value satisfies the non-empty field constraint on the client.
_CAPTCHA = "e2e-test-bypass"


def _unique_email() -> str:
    return f"e2e-{uuid.uuid4().hex[:8]}@example.com"


def _unique_tenant() -> str:
    return f"tenant{uuid.uuid4().hex[:6]}"


def _extract_verify_token_from_logs(since_lines: int = 300) -> str | None:
    """Tail the backend container logs and extract a verify-email token."""
    try:
        out = subprocess.check_output(
            ["docker", "compose", "logs", "--tail", str(since_lines), "backend"],
            stderr=subprocess.STDOUT,
            timeout=15,
        ).decode(errors="replace")
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    # Dev-mode log line format: "verify_url: .../verify-email?token=<TOKEN>"
    m = re.search(r"/verify-email\?token=([A-Za-z0-9_\-]+)", out)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_signup_verify_me_create_connection():
    """Happy path: signup → verify email from logs → /me → create connection."""
    s = requests.Session()

    email = _unique_email()
    tenant = _unique_tenant()
    password = "StrongPass1!"

    # ── 1. Signup ────────────────────────────────────────────────────────────
    r = s.post(
        f"{API_URL}/api/auth/signup",
        json={
            "email": email,
            "password": password,
            "tenant_name": tenant,
            "captcha_token": _CAPTCHA,
        },
        timeout=15,
    )
    if r.status_code == 503:
        pytest.skip("System not provisioned (no admin seeded); skipping signup test")
    assert r.status_code == 202, f"signup failed: {r.status_code} {r.text}"

    # ── 2. Capture verify token from backend logs ────────────────────────────
    # Give the mailer a moment to log.
    time.sleep(1)
    token = _extract_verify_token_from_logs()
    if token is None:
        pytest.skip(
            "Could not find verify-email token in backend logs. "
            "Check that SMTP is NOT configured (dev-mode logs the URL to stdout)."
        )

    # ── 3. Verify email ──────────────────────────────────────────────────────
    r = s.post(
        f"{API_URL}/api/auth/verify-email",
        json={"token": token},
        timeout=10,
    )
    assert r.status_code == 200, f"verify-email failed: {r.status_code} {r.text}"
    body = r.json()
    assert body["user"]["email"] == email
    assert body["user"]["email_verified"] is True

    # ── 4. GET /me using the session cookie set by verify-email ──────────────
    r = s.get(f"{API_URL}/api/auth/me", timeout=10)
    assert r.status_code == 200, f"/me failed: {r.status_code} {r.text}"
    assert r.json()["platform_role"] == "client"

    # ── 5. Create a connection (checks tenant isolation is active) ───────────
    domain = f"e2e-{uuid.uuid4().hex[:8]}.example.com"
    r = s.post(
        f"{API_URL}/api/connections/",
        json={"name": "e2e-test", "domain": domain},
        timeout=15,
    )
    # 201 = created; 422 = domain didn't resolve — both are acceptable here.
    assert r.status_code in (201, 422), (
        f"unexpected status creating connection: {r.status_code} {r.text}"
    )

    s.close()


@pytest.mark.e2e
def test_signup_duplicate_email_409():
    """Signing up with an already-used email returns 409."""
    email = _unique_email()
    tenant_a = _unique_tenant()
    tenant_b = _unique_tenant()
    password = "StrongPass1!"

    def _signup(tn):
        return requests.post(
            f"{API_URL}/api/auth/signup",
            json={
                "email": email,
                "password": password,
                "tenant_name": tn,
                "captcha_token": _CAPTCHA,
            },
            timeout=15,
        )

    r1 = _signup(tenant_a)
    if r1.status_code == 503:
        pytest.skip("System not provisioned; skipping dup-email test")
    assert r1.status_code == 202, r1.text

    r2 = _signup(tenant_b)
    assert r2.status_code == 409, f"expected 409 for dup email, got {r2.status_code}: {r2.text}"


@pytest.mark.e2e
def test_login_unverified_email_403():
    """Logging in before verifying email returns 403."""
    s = requests.Session()
    email = _unique_email()
    password = "StrongPass1!"
    tenant = _unique_tenant()

    r = s.post(
        f"{API_URL}/api/auth/signup",
        json={
            "email": email,
            "password": password,
            "tenant_name": tenant,
            "captcha_token": _CAPTCHA,
        },
        timeout=15,
    )
    if r.status_code == 503:
        pytest.skip("System not provisioned; skipping unverified test")
    assert r.status_code == 202

    r = s.post(
        f"{API_URL}/api/auth/login",
        json={"email": email, "password": password, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    assert r.status_code == 403, (
        f"expected 403 for unverified login, got {r.status_code}: {r.text}"
    )
    s.close()
