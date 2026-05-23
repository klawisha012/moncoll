"""E2E: full password-reset cycle — forgot → reset → login with new password.

Requires dev-mode SMTP (no WAF_SMTP_HOST) so the reset URL is logged to
backend stdout. The test captures it via `docker compose logs`.

Run:
    docker compose up -d
    docker compose exec backend alembic upgrade head
    WAF_API_URL=http://localhost:8000 \
        python -m pytest -m e2e tests/e2e/auth/test_reset_password.py -v
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
_CAPTCHA = "e2e-test-bypass"


def _unique_email() -> str:
    return f"reset-e2e-{uuid.uuid4().hex[:8]}@example.com"


def _unique_tenant() -> str:
    return f"rst{uuid.uuid4().hex[:6]}"


def _latest_token_from_logs(pattern: str, tail: int = 300) -> str | None:
    """Return the last match of `pattern` group 1 in backend logs."""
    try:
        out = subprocess.check_output(
            ["docker", "compose", "logs", "--tail", str(tail), "backend"],
            stderr=subprocess.STDOUT, timeout=15,
        ).decode(errors="replace")
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    matches = re.findall(pattern, out)
    return matches[-1] if matches else None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_forgot_always_202():
    """POST /password/forgot with unknown email still returns 202 (no oracle)."""
    r = requests.post(
        f"{API_URL}/api/auth/password/forgot",
        json={"email": "nobody@nowhere.invalid", "captcha_token": _CAPTCHA},
        timeout=10,
    )
    assert r.status_code == 202, f"expected 202, got {r.status_code}: {r.text}"


@pytest.mark.e2e
def test_reset_password_full_cycle():
    """Signup → verify → forgot → reset → login with new password."""
    s = requests.Session()
    email = _unique_email()
    tenant = _unique_tenant()
    old_pw = "OldPassword1!"
    new_pw = "NewPassword2!"

    # ── 1. Signup ─────────────────────────────────────────────────────────────
    r = s.post(
        f"{API_URL}/api/auth/signup",
        json={
            "email": email, "password": old_pw,
            "tenant_name": tenant, "captcha_token": _CAPTCHA,
        },
        timeout=15,
    )
    if r.status_code == 503:
        pytest.skip("System not provisioned; skipping password reset test")
    assert r.status_code == 202, f"signup failed: {r.text}"

    # ── 2. Verify email ───────────────────────────────────────────────────────
    time.sleep(1)
    verify_token = _latest_token_from_logs(r"/verify-email\?token=([A-Za-z0-9_\-]+)")
    if not verify_token:
        pytest.skip("Could not capture verify token from logs; check dev-mode SMTP")

    r = s.post(
        f"{API_URL}/api/auth/verify-email",
        json={"token": verify_token},
        timeout=10,
    )
    assert r.status_code == 200, f"verify-email failed: {r.text}"

    # ── 3. Forgot password ────────────────────────────────────────────────────
    r = s.post(
        f"{API_URL}/api/auth/password/forgot",
        json={"email": email, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    assert r.status_code == 202, f"forgot failed: {r.text}"

    time.sleep(1)
    reset_token = _latest_token_from_logs(r"/reset-password\?token=([A-Za-z0-9_\-]+)")
    if not reset_token:
        pytest.skip("Could not capture reset token from logs; check dev-mode SMTP")

    # ── 4. Reset password ─────────────────────────────────────────────────────
    r = s.post(
        f"{API_URL}/api/auth/password/reset",
        json={"token": reset_token, "new_password": new_pw},
        timeout=10,
    )
    assert r.status_code == 204, f"password/reset failed: {r.status_code} {r.text}"

    # ── 5. Old password no longer works ──────────────────────────────────────
    r = requests.post(
        f"{API_URL}/api/auth/login",
        json={"email": email, "password": old_pw, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    assert r.status_code == 401, (
        f"old password should be rejected, got {r.status_code}: {r.text}"
    )

    # ── 6. New password works ─────────────────────────────────────────────────
    r = requests.post(
        f"{API_URL}/api/auth/login",
        json={"email": email, "password": new_pw, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    assert r.status_code == 200, (
        f"login with new password failed: {r.status_code} {r.text}"
    )

    s.close()


@pytest.mark.e2e
def test_reset_token_single_use():
    """A consumed reset token cannot be replayed."""
    s = requests.Session()
    email = _unique_email()
    tenant = _unique_tenant()
    password = "SingleUse1!"

    r = s.post(
        f"{API_URL}/api/auth/signup",
        json={
            "email": email, "password": password,
            "tenant_name": tenant, "captcha_token": _CAPTCHA,
        },
        timeout=15,
    )
    if r.status_code == 503:
        pytest.skip("System not provisioned; skipping token replay test")
    assert r.status_code == 202

    time.sleep(1)
    verify_token = _latest_token_from_logs(r"/verify-email\?token=([A-Za-z0-9_\-]+)")
    if not verify_token:
        pytest.skip("Could not capture verify token")

    s.post(f"{API_URL}/api/auth/verify-email", json={"token": verify_token}, timeout=10)

    # Request reset
    s.post(
        f"{API_URL}/api/auth/password/forgot",
        json={"email": email, "captcha_token": _CAPTCHA},
        timeout=10,
    )
    time.sleep(1)
    reset_token = _latest_token_from_logs(r"/reset-password\?token=([A-Za-z0-9_\-]+)")
    if not reset_token:
        pytest.skip("Could not capture reset token")

    # First use — success
    r = s.post(
        f"{API_URL}/api/auth/password/reset",
        json={"token": reset_token, "new_password": "NewPass1!"},
        timeout=10,
    )
    assert r.status_code == 204

    # Second use — must fail
    r = s.post(
        f"{API_URL}/api/auth/password/reset",
        json={"token": reset_token, "new_password": "AnotherPass1!"},
        timeout=10,
    )
    assert r.status_code == 400, (
        f"replayed reset token should return 400, got {r.status_code}: {r.text}"
    )
    s.close()
