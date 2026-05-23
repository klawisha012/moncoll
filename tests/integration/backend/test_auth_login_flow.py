"""Integration tests for /login, /logout, /me endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.src.auth import service as auth_service
from backend.src.auth.dependencies import SESSION_COOKIE
from backend.src.db.session import get_session
from backend.src.main import app
from backend.src.tenants import service as tenants


def _make_client(db_session):
    app.dependency_overrides[get_session] = lambda: db_session
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


async def _create_verified_user(db_session, email="login@example.com", password="hunter22a"):
    t = await tenants.create_tenant(db_session, name="login-tenant", display_name="Login Tenant")
    user = await auth_service.create_client_user(
        db_session,
        email=email,
        password=password,
        tenant_id=t.id,
        email_verified=True,
    )
    return user


@pytest.mark.asyncio
async def test_login_success(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "1" * 64)
    from backend.src.auth import security
    security._cached_key = None

    await _create_verified_user(db_session)

    async with _make_client(db_session) as c:
        r = await c.post(
            "/api/auth/login",
            json={
                "email": "login@example.com",
                "password": "hunter22a",
                "captcha_token": "tok",
            },
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["user"]["email"] == "login@example.com"
        assert SESSION_COOKIE in r.cookies

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_login_wrong_password(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "2" * 64)
    from backend.src.auth import security
    security._cached_key = None

    await _create_verified_user(db_session, email="wrong@example.com")

    async with _make_client(db_session) as c:
        r = await c.post(
            "/api/auth/login",
            json={
                "email": "wrong@example.com",
                "password": "badpassword",
                "captcha_token": "tok",
            },
        )
        assert r.status_code == 401, r.text

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_login_unverified_email(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "3" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants.create_tenant(
        db_session, name="unverified-tenant", display_name="Unverified"
    )
    await auth_service.create_client_user(
        db_session,
        email="unverified@example.com",
        password="hunter22a",
        tenant_id=t.id,
        email_verified=False,
    )

    async with _make_client(db_session) as c:
        r = await c.post(
            "/api/auth/login",
            json={
                "email": "unverified@example.com",
                "password": "hunter22a",
                "captcha_token": "tok",
            },
        )
        assert r.status_code == 403, r.text
        assert "not verified" in r.json()["detail"]

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_login_captcha_fail(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "4" * 64)
    from backend.src.auth import security
    security._cached_key = None

    # Configure a fake Turnstile secret so captcha verification actually runs
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "real-secret")
    from backend.src.config import get_settings
    get_settings.cache_clear()

    import httpx
    import respx

    async with _make_client(db_session) as c:
        with respx.mock:
            respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").mock(
                return_value=httpx.Response(200, json={"success": False})
            )
            r = await c.post(
                "/api/auth/login",
                json={
                    "email": "captcha@example.com",
                    "password": "hunter22a",
                    "captcha_token": "bad-token",
                },
            )
        assert r.status_code == 400, r.text
        assert "captcha" in r.json()["detail"]

    app.dependency_overrides.clear()
    security._cached_key = None
    monkeypatch.delenv("WAF_TURNSTILE_SECRET_KEY", raising=False)
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_me_requires_auth(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "5" * 64)
    from backend.src.auth import security
    security._cached_key = None

    async with _make_client(db_session) as c:
        r = await c.get("/api/auth/me")
        assert r.status_code == 401

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_logout_clears_cookie(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "6" * 64)
    from backend.src.auth import security
    security._cached_key = None

    await _create_verified_user(db_session, email="logout@example.com")

    async with _make_client(db_session) as c:
        login_r = await c.post(
            "/api/auth/login",
            json={
                "email": "logout@example.com",
                "password": "hunter22a",
                "captcha_token": "tok",
            },
        )
        assert login_r.status_code == 200
        assert SESSION_COOKIE in login_r.cookies

        logout_r = await c.post("/api/auth/logout")
        assert logout_r.status_code == 204

    app.dependency_overrides.clear()
    security._cached_key = None
