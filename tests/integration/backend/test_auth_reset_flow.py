"""Integration tests for /password/forgot and /password/reset."""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.src.auth import service as auth_service
from backend.src.db.session import get_session
from backend.src.main import app
from backend.src.tenants import service as tenants


def _make_client(db_session):
    app.dependency_overrides[get_session] = lambda: db_session
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


async def _setup_verified_user(db_session, email="reset@example.com", password="oldpass88"):
    t = await tenants.create_tenant(
        db_session, name="reset-tenant", display_name="Reset Tenant"
    )
    user = await auth_service.create_client_user(
        db_session,
        email=email,
        password=password,
        tenant_id=t.id,
        email_verified=True,
    )
    return user


@pytest.mark.asyncio
async def test_forgot_then_reset_then_login(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "f" * 64)
    from backend.src.auth import security
    security._cached_key = None

    captured = {}

    async def fake_reset_email(*, to_email, display_name, reset_url):
        captured["url"] = reset_url

    monkeypatch.setattr("backend.src.auth.email.send_password_reset", fake_reset_email)

    await _setup_verified_user(db_session)

    async with _make_client(db_session) as c:
        # Step 1: forgot
        r = await c.post(
            "/api/auth/password/forgot",
            json={"email": "reset@example.com", "captcha_token": "tok"},
        )
        assert r.status_code == 202, r.text
        assert "reset link" in r.json()["message"]

        assert "url" in captured
        token = captured["url"].split("token=")[1]

        # Step 2: reset
        r2 = await c.post(
            "/api/auth/password/reset",
            json={"token": token, "new_password": "newpass99"},
        )
        assert r2.status_code == 204, r2.text

        # Step 3: login with new password
        r3 = await c.post(
            "/api/auth/login",
            json={
                "email": "reset@example.com",
                "password": "newpass99",
                "captcha_token": "tok",
            },
        )
        assert r3.status_code == 200, r3.text
        assert r3.json()["user"]["email"] == "reset@example.com"

        # Old password no longer works
        r4 = await c.post(
            "/api/auth/login",
            json={
                "email": "reset@example.com",
                "password": "oldpass88",
                "captcha_token": "tok",
            },
        )
        assert r4.status_code == 401

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_forgot_anti_enumeration(db_session, monkeypatch):
    """Forgot returns 202 even for non-existent email (anti-enumeration)."""
    monkeypatch.setenv("WAF_PASETO_KEY", "e" * 64)
    from backend.src.auth import security
    security._cached_key = None

    monkeypatch.setattr(
        "backend.src.auth.email.send_password_reset",
        lambda **kw: None,
    )

    async with _make_client(db_session) as c:
        r = await c.post(
            "/api/auth/password/forgot",
            json={"email": "nobody@nowhere.com", "captcha_token": "tok"},
        )
        assert r.status_code == 202, r.text

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_reset_invalid_token(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "7" * 64)
    from backend.src.auth import security
    security._cached_key = None

    async with _make_client(db_session) as c:
        r = await c.post(
            "/api/auth/password/reset",
            json={"token": "invalidtoken", "new_password": "newpass99"},
        )
        assert r.status_code == 400, r.text

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_reset_token_one_shot(db_session, monkeypatch):
    """Using a reset token twice must fail on the second attempt."""
    monkeypatch.setenv("WAF_PASETO_KEY", "8" * 64)
    from backend.src.auth import security
    security._cached_key = None

    captured = {}

    async def fake_reset_email(*, to_email, display_name, reset_url):
        captured["url"] = reset_url

    monkeypatch.setattr("backend.src.auth.email.send_password_reset", fake_reset_email)

    await _setup_verified_user(
        db_session, email="oneshot@example.com", password="first88"
    )

    async with _make_client(db_session) as c:
        await c.post(
            "/api/auth/password/forgot",
            json={"email": "oneshot@example.com", "captcha_token": "tok"},
        )
        token = captured["url"].split("token=")[1]

        r1 = await c.post(
            "/api/auth/password/reset",
            json={"token": token, "new_password": "second99"},
        )
        assert r1.status_code == 204

        r2 = await c.post(
            "/api/auth/password/reset",
            json={"token": token, "new_password": "thirdpass00"},
        )
        assert r2.status_code == 400

    app.dependency_overrides.clear()
    security._cached_key = None
