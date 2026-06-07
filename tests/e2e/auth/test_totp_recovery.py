"""E2E: TOTP recovery code single-use enforcement.

Scenario:
  1. Seed admin → login → enrol TOTP → capture recovery codes.
  2. Login with a recovery code → success.
  3. Login with the same recovery code again → fail (single-use).

Requires pyotp. Uses the admin flow because admin is the primary TOTP user.

Run:
    pip install pyotp
    docker compose up -d
    WAF_API_URL=http://localhost \
        python -m pytest -m e2e tests/e2e/auth/test_totp_recovery.py -v
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


def _unique_email() -> str:
    return f"totp-rec-{uuid.uuid4().hex[:8]}@example.com"


def _seed_admin(email: str, password: str) -> bool:
    try:
        result = subprocess.run(
            [
                "docker", "compose", "exec", "-T", "gobackend",
                "/server", "create-admin",
                "-email", email,
                "-password", password,
            ],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _enrol_admin(email: str, password: str) -> tuple[str, list[str]] | None:
    """Login admin, complete TOTP enrolment. Returns (secret, recovery_codes) or None."""
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
    setup = r.json()
    secret = setup["secret_base32"]
    recovery_codes: list[str] = setup["recovery_codes"]

    r = s.post(
        f"{API_URL}/api/auth/totp/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        timeout=10,
    )
    if r.status_code != 200:
        s.close()
        return None

    s.close()
    return secret, recovery_codes


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.skipif(not _PYOTP_AVAILABLE, reason="pyotp not installed")
def test_recovery_code_single_use():
    """A recovery code can be used once; the second use must fail."""
    email = _unique_email()
    password = "RecoveryTest1!"

    if not _seed_admin(email, password):
        pytest.skip("Could not seed admin via CLI; check stack is running")

    result = _enrol_admin(email, password)
    if result is None:
        pytest.skip("Could not complete TOTP enrolment")

    _secret, recovery_codes = result
    assert recovery_codes, "No recovery codes returned from /totp/setup"
    code = recovery_codes[0]

    # ── First use: login with recovery code ───────────────────────────────────
    r = requests.post(
        f"{API_URL}/api/auth/login",
        json={"email": email, "password": password, "captcha_token": _CAPTCHA, "totp_code": code},
        timeout=10,
    )
    assert r.status_code == 200, (
        f"first recovery code login failed: {r.status_code} {r.text}"
    )

    # ── Second use: must be rejected ─────────────────────────────────────────
    r = requests.post(
        f"{API_URL}/api/auth/login",
        json={"email": email, "password": password, "captcha_token": _CAPTCHA, "totp_code": code},
        timeout=10,
    )
    assert r.status_code == 401, (
        f"replayed recovery code should return 401, got {r.status_code}: {r.text}"
    )


@pytest.mark.e2e
@pytest.mark.skipif(not _PYOTP_AVAILABLE, reason="pyotp not installed")
def test_all_recovery_codes_distinct():
    """Recovery codes from /totp/setup must all be unique strings."""
    email = _unique_email()
    password = "RecoveryTest2!"

    if not _seed_admin(email, password):
        pytest.skip("Could not seed admin via CLI")

    result = _enrol_admin(email, password)
    if result is None:
        pytest.skip("Could not complete TOTP enrolment")

    _secret, recovery_codes = result
    assert len(recovery_codes) == len(set(recovery_codes)), (
        f"Duplicate recovery codes returned: {recovery_codes}"
    )
    # Sanity: each code is non-empty
    for c in recovery_codes:
        assert c, "Empty recovery code in list"


@pytest.mark.e2e
@pytest.mark.skipif(not _PYOTP_AVAILABLE, reason="pyotp not installed")
def test_invalid_totp_code_rejected():
    """A completely wrong TOTP code is rejected with 401."""
    email = _unique_email()
    password = "RecoveryTest3!"

    if not _seed_admin(email, password):
        pytest.skip("Could not seed admin via CLI")

    result = _enrol_admin(email, password)
    if result is None:
        pytest.skip("Could not complete TOTP enrolment")

    r = requests.post(
        f"{API_URL}/api/auth/login",
        json={
            "email": email,
            "password": password,
            "captcha_token": _CAPTCHA,
            "totp_code": "000000",
        },
        timeout=10,
    )
    assert r.status_code == 401, (
        f"invalid TOTP should return 401, got {r.status_code}: {r.text}"
    )
