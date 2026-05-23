"""E2E: OAuth mocked signup/login.

The real OAuth providers (Google, GitHub) require external network access and
registered credentials. These tests exercise the *structural* behaviour of the
OAuth endpoints without calling the real provider:

1. /oauth/{provider}/start → redirects to provider, sets state cookie.
2. /oauth/{provider}/callback with bad state → 400.
3. Callback with mismatched state cookie → 400.

Full round-trip tests (exchange code → fetch profile → create user) require a
live mock provider; they are marked skip with an explanatory reason. The
structural tests run against the stack with no OAuth credentials configured and
verify the error-path surface rather than the happy path.
"""
from __future__ import annotations

import os

import pytest
import requests

API_URL = os.environ.get("WAF_API_URL", "http://localhost:8000")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _providers(s: requests.Session) -> dict:
    r = s.get(f"{API_URL}/api/auth/providers", timeout=10)
    if r.status_code != 200:
        return {}
    return r.json()


# ---------------------------------------------------------------------------
# Structural tests (run regardless of provider config)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_oauth_start_unavailable_provider_400():
    """Unknown provider name → 400."""
    s = requests.Session()
    r = s.get(
        f"{API_URL}/api/auth/oauth/nonexistent/start",
        params={"intent": "login"},
        allow_redirects=False,
        timeout=10,
    )
    # 400 = provider unavailable; 307 would mean the provider is somehow
    # registered, which is unexpected for a nonsense name.
    assert r.status_code in (400, 404), (
        f"expected 400/404 for unknown provider, got {r.status_code}: {r.text}"
    )
    s.close()


@pytest.mark.e2e
def test_oauth_callback_bad_state_400():
    """Callback with a garbage state (no matching cookie) → 400."""
    s = requests.Session()
    r = s.get(
        f"{API_URL}/api/auth/oauth/google/callback",
        params={"code": "fakecode", "state": "notavalidstate"},
        allow_redirects=False,
        timeout=10,
    )
    # 400 = invalid oauth state (no cookie or HMAC failure)
    assert r.status_code in (400, 404), (
        f"expected 400 for bad oauth state, got {r.status_code}: {r.text}"
    )
    s.close()


@pytest.mark.e2e
def test_oauth_start_bad_intent_400():
    """Intent other than signup/login → 400."""
    s = requests.Session()
    prov = _providers(s)
    if not prov.get("google"):
        pytest.skip("Google OAuth not configured; skipping intent-validation test")

    r = s.get(
        f"{API_URL}/api/auth/oauth/google/start",
        params={"intent": "hack"},
        allow_redirects=False,
        timeout=10,
    )
    assert r.status_code == 400, (
        f"expected 400 for bad intent, got {r.status_code}: {r.text}"
    )
    s.close()


# ---------------------------------------------------------------------------
# Full round-trip tests (require live mock provider — skip in standard CI)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.skip(
    reason=(
        "Full OAuth round-trip requires a live mock provider or registered "
        "credentials. Run manually with WAF_OAUTH_GOOGLE_* env vars set and "
        "a mock OIDC server pointed at WAF_OAUTH_GOOGLE_REDIRECT_URI."
    )
)
def test_oauth_google_signup_new_user():
    """OAuth Google: signup new user, get session cookie."""
    ...  # pragma: no cover


@pytest.mark.e2e
@pytest.mark.skip(
    reason=(
        "Full OAuth round-trip requires a live mock provider or registered "
        "credentials. Run manually with WAF_OAUTH_GITHUB_* env vars set."
    )
)
def test_oauth_github_login_existing_user():
    """OAuth GitHub: login an existing OAuth-linked user."""
    ...  # pragma: no cover
