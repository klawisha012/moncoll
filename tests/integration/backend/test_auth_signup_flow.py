"""Integration tests for /signup and /verify-email endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.src.auth.dependencies import SESSION_COOKIE
from backend.src.db.session import get_session
from backend.src.main import app


def _make_client(db_session):
    app.dependency_overrides[get_session] = lambda: db_session
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.asyncio
async def test_signup_then_verify(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "a" * 64)
    from backend.src.auth import security
    security._cached_key = None

    captured = {}

    async def fake_send(*, to_email, display_name, verify_url):
        captured["url"] = verify_url

    monkeypatch.setattr("backend.src.auth.email.send_verify_email", fake_send)

    async with _make_client(db_session) as c:
        r = await c.post(
            "/api/auth/signup",
            json={
                "email": "user@example.com",
                "password": "hunter22a",
                "tenant_name": "acme-co",
                "captcha_token": "test-token",
            },
        )
        assert r.status_code == 202, r.text
        assert r.json()["message"] == "check your email"

        assert "url" in captured
        token = captured["url"].split("token=")[1]

        r2 = await c.post("/api/auth/verify-email", json={"token": token})
        assert r2.status_code == 200, r2.text
        data = r2.json()
        assert data["user"]["email"] == "user@example.com"
        assert data["user"]["email_verified"] is True
        assert SESSION_COOKIE in r2.cookies

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_signup_duplicate_email(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "b" * 64)
    from backend.src.auth import security
    security._cached_key = None

    async def fake_send(**kw):
        pass

    monkeypatch.setattr("backend.src.auth.email.send_verify_email", fake_send)

    async with _make_client(db_session) as c:
        payload = {
            "email": "dup@example.com",
            "password": "hunter22a",
            "tenant_name": "tenant-dup1",
            "captcha_token": "tok",
        }
        r1 = await c.post("/api/auth/signup", json=payload)
        assert r1.status_code == 202

        # Same email different tenant name
        payload2 = {**payload, "tenant_name": "tenant-dup2"}
        r2 = await c.post("/api/auth/signup", json=payload2)
        assert r2.status_code == 409
        assert "email" in r2.json()["detail"]

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_signup_duplicate_tenant(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "c" * 64)
    from backend.src.auth import security
    security._cached_key = None

    async def fake_send2(**kw):
        pass

    monkeypatch.setattr("backend.src.auth.email.send_verify_email", fake_send2)

    async with _make_client(db_session) as c:
        payload = {
            "email": "x@example.com",
            "password": "hunter22a",
            "tenant_name": "same-tenant",
            "captcha_token": "tok",
        }
        r1 = await c.post("/api/auth/signup", json=payload)
        assert r1.status_code == 202

        # Different email, same tenant name
        payload2 = {**payload, "email": "y@example.com"}
        r2 = await c.post("/api/auth/signup", json=payload2)
        assert r2.status_code == 409
        assert "tenant" in r2.json()["detail"]

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_verify_invalid_token(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "d" * 64)
    from backend.src.auth import security
    security._cached_key = None

    async with _make_client(db_session) as c:
        r = await c.post("/api/auth/verify-email", json={"token": "notavalidtoken"})
        assert r.status_code == 400

    app.dependency_overrides.clear()
    security._cached_key = None
