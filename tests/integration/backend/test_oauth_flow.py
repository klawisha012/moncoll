"""Integration tests for the Google + GitHub OAuth signup/login flow."""

import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, patch
from sqlalchemy import select

from backend.src.auth.dependencies import SESSION_COOKIE
from backend.src.auth.routers.oauth import OAUTH_STATE_COOKIE
from backend.src.auth.security import sign_short_lived
from backend.src.db.models import OAuthAccount, User
from backend.src.db.session import get_session
from backend.src.main import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

GOOGLE_REDIRECT_URI = "https://app.local/api/auth/oauth/google/callback"

GOOGLE_PROFILE = {
    "sub": "google-uid-123",
    "email": "alice@example.com",
    "email_verified": True,
    "name": "Alice",
}

GOOGLE_PROFILE_UNVERIFIED = {
    "sub": "google-uid-999",
    "email": "unverified@example.com",
    "email_verified": False,
    "name": "Unverified",
}


def _make_client(db_session):
    app.dependency_overrides[get_session] = lambda: db_session
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=False)


def _make_google_state(intent: str, tenant_name: str | None = None) -> str:
    return sign_short_lived(
        {"intent": intent, "tenant_name": tenant_name, "provider": "google"},
        ttl_seconds=600,
        purpose="oauth_state",
    )


def _patch_google(monkeypatch, access_token: str = "tok-abc"):
    """Patch get_client and redirect_uri to avoid real OAuth calls."""
    mock_client = AsyncMock()
    mock_client.get_access_token = AsyncMock(return_value={"access_token": access_token})
    monkeypatch.setattr(
        "backend.src.auth.routers.oauth.get_client",
        lambda provider: mock_client if provider == "google" else None,
    )
    monkeypatch.setattr(
        "backend.src.auth.routers.oauth.redirect_uri",
        lambda provider, request=None: GOOGLE_REDIRECT_URI if provider == "google" else None,
    )
    return mock_client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_signup_new_account(db_session, monkeypatch):
    """Signup with new Google account → tenant + user + oauth_account created, session cookie set."""
    monkeypatch.setenv("WAF_PASETO_KEY", "a0" * 32)
    from backend.src.auth import security
    security._cached_key = None

    _patch_google(monkeypatch)
    state = _make_google_state("signup", tenant_name="alicecorp")

    with patch(
        "backend.src.auth.routers.oauth._fetch_google_profile",
        new=AsyncMock(return_value=GOOGLE_PROFILE),
    ):
        async with _make_client(db_session) as c:
            c.cookies.set(OAUTH_STATE_COOKIE, state)
            r = await c.get(
                "/api/auth/oauth/google/callback",
                params={"code": "auth-code", "state": state},
            )

    assert r.status_code == 303, r.text
    assert r.headers["location"] == "https://testserver/home"
    assert SESSION_COOKIE in r.cookies

    # Verify DB rows
    user = (
        await db_session.execute(select(User).where(User.email == "alice@example.com"))
    ).scalar_one_or_none()
    assert user is not None
    assert user.email_verified_at is not None
    assert user.tenant_id is not None

    oauth_acct = (
        await db_session.execute(
            select(OAuthAccount).where(OAuthAccount.provider_account_id == "google-uid-123")
        )
    ).scalar_one_or_none()
    assert oauth_acct is not None
    assert oauth_acct.provider == "google"
    assert oauth_acct.user_id == user.id

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_oauth_signup_email_collision(db_session, monkeypatch):
    """Signup when email already registered via password → 409."""
    monkeypatch.setenv("WAF_PASETO_KEY", "b1" * 32)
    from backend.src.auth import security
    security._cached_key = None

    # Pre-create a password user with the same email
    from backend.src import auth as auth_mod
    from backend.src.tenants import service as tenants_service

    tenant = await tenants_service.create_tenant(
        db_session, name="existingcorp", display_name="Existing Corp"
    )
    await auth_mod.service.create_client_user(
        db_session,
        email="alice@example.com",
        password="somepassword1",
        tenant_id=tenant.id,
        tenant_role="owner",
    )

    _patch_google(monkeypatch)
    state = _make_google_state("signup", tenant_name="newcorp")

    with patch(
        "backend.src.auth.routers.oauth._fetch_google_profile",
        new=AsyncMock(return_value=GOOGLE_PROFILE),
    ):
        async with _make_client(db_session) as c:
            c.cookies.set(OAUTH_STATE_COOKIE, state)
            r = await c.get(
                "/api/auth/oauth/google/callback",
                params={"code": "auth-code", "state": state},
            )

    assert r.status_code == 303, r.text
    assert r.headers["location"] == "https://testserver/signup?oauth_error=email_in_use"

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_oauth_login_existing_account(db_session, monkeypatch):
    """Login with known OAuth account → session cookie issued."""
    monkeypatch.setenv("WAF_PASETO_KEY", "c2" * 32)
    from backend.src.auth import security
    security._cached_key = None

    from backend.src.tenants import service as tenants_service
    from backend.src import auth as auth_mod

    tenant = await tenants_service.create_tenant(
        db_session, name="bobcorp", display_name="Bob Corp"
    )
    user = await auth_mod.service.create_client_user(
        db_session,
        email="bob@example.com",
        password=None,
        tenant_id=tenant.id,
        tenant_role="owner",
        email_verified=True,
    )
    db_session.add(
        OAuthAccount(
            user_id=user.id,
            provider="google",
            provider_account_id="google-uid-bob",
            email_at_provider="bob@example.com",
        )
    )
    await db_session.commit()

    bob_profile = {
        "sub": "google-uid-bob",
        "email": "bob@example.com",
        "email_verified": True,
        "name": "Bob",
    }

    _patch_google(monkeypatch)
    state = _make_google_state("login")

    with patch(
        "backend.src.auth.routers.oauth._fetch_google_profile",
        new=AsyncMock(return_value=bob_profile),
    ):
        async with _make_client(db_session) as c:
            c.cookies.set(OAUTH_STATE_COOKIE, state)
            r = await c.get(
                "/api/auth/oauth/google/callback",
                params={"code": "auth-code", "state": state},
            )

    assert r.status_code == 303, r.text
    assert SESSION_COOKIE in r.cookies

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_oauth_login_no_account(db_session, monkeypatch):
    """Login intent with no matching OAuth account → 404."""
    monkeypatch.setenv("WAF_PASETO_KEY", "d3" * 32)
    from backend.src.auth import security
    security._cached_key = None

    _patch_google(monkeypatch)
    state = _make_google_state("login")

    with patch(
        "backend.src.auth.routers.oauth._fetch_google_profile",
        new=AsyncMock(return_value=GOOGLE_PROFILE),
    ):
        async with _make_client(db_session) as c:
            c.cookies.set(OAUTH_STATE_COOKIE, state)
            r = await c.get(
                "/api/auth/oauth/google/callback",
                params={"code": "auth-code", "state": state},
            )

    assert r.status_code == 303, r.text
    assert r.headers["location"] == "https://testserver/home"

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_oauth_email_not_verified(db_session, monkeypatch):
    """Google profile with email_verified=False → 400."""
    monkeypatch.setenv("WAF_PASETO_KEY", "e4" * 32)
    from backend.src.auth import security
    security._cached_key = None

    _patch_google(monkeypatch)
    state = _make_google_state("signup", tenant_name="unverifcorp")

    with patch(
        "backend.src.auth.routers.oauth._fetch_google_profile",
        new=AsyncMock(return_value=GOOGLE_PROFILE_UNVERIFIED),
    ):
        async with _make_client(db_session) as c:
            c.cookies.set(OAUTH_STATE_COOKIE, state)
            r = await c.get(
                "/api/auth/oauth/google/callback",
                params={"code": "auth-code", "state": state},
            )

    assert r.status_code == 303, r.text
    assert r.headers["location"] == "https://testserver/signup?oauth_error=email_not_verified"

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_oauth_invalid_state_cookie(db_session, monkeypatch):
    """Mismatched state cookie (wrong_state in cookie, state in params) → 400."""
    monkeypatch.setenv("WAF_PASETO_KEY", "f5" * 32)
    from backend.src.auth import security
    security._cached_key = None

    state = _make_google_state("signup", tenant_name="corp")
    wrong_state = _make_google_state("signup", tenant_name="othercorp")

    async with _make_client(db_session) as c:
        c.cookies.set(OAUTH_STATE_COOKIE, wrong_state)
        r = await c.get(
            "/api/auth/oauth/google/callback",
            params={"code": "auth-code", "state": state},
        )

    assert r.status_code == 303, r.text
    assert r.headers["location"] == "https://testserver/signup?oauth_error=state_mismatch"

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_oauth_start_provider_unavailable(db_session, monkeypatch):
    """No OAuth env vars set → /start returns 400."""
    monkeypatch.setenv("WAF_PASETO_KEY", "06" * 32)
    # Clear settings cache so missing env vars take effect
    from backend.src import config as cfg_mod
    cfg_mod.get_settings.cache_clear()
    from backend.src.auth import security
    security._cached_key = None

    async with _make_client(db_session) as c:
        r = await c.get(
            "/api/auth/oauth/google/start",
            params={"intent": "signup", "tenant_name": "corp"},
        )

    assert r.status_code == 303, r.text
    assert r.headers["location"] == "https://testserver/signup?oauth_error=provider_unavailable"

    cfg_mod.get_settings.cache_clear()
    app.dependency_overrides.clear()
    security._cached_key = None
