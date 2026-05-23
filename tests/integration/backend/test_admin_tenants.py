"""Integration tests for /api/admin/tenants endpoints (Phase 11)."""

import pytest
from datetime import UTC, datetime
from httpx import AsyncClient, ASGITransport

from backend.src.auth import service as auth_service
from backend.src.auth.security import create_session_token
from backend.src.db.session import get_session
from backend.src.main import app
from backend.src.tenants import service as tenants_service


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _make_admin(session, email="admin@waf.local"):
    """Create an admin user with TOTP already enabled (so require_admin passes)."""
    user = await auth_service.create_admin(session, email=email, password="hunter22aa")
    # Simulate TOTP enrolment so require_admin doesn't 403.
    user.totp_enabled_at = datetime.now(UTC)
    user.totp_secret = "AAAAAAAAAAAAAAAA"
    await session.commit()
    await session.refresh(user)
    return user


def _admin_token(user):
    return create_session_token(
        user_id=user.id,
        platform_role="admin",
        tenant_id=None,
        tenant_role=None,
    )


async def _make_client(session, tenant, email="client@example.com"):
    user = await auth_service.create_client_user(
        session,
        email=email,
        password="hunter22bb",
        tenant_id=tenant.id,
        email_verified=True,
    )
    user.totp_enabled_at = datetime.now(UTC)
    user.totp_secret = "BBBBBBBBBBBBBBBB"
    await session.commit()
    await session.refresh(user)
    return user


def _client_token(user, tenant):
    return create_session_token(
        user_id=user.id,
        platform_role="client",
        tenant_id=tenant.id,
        tenant_role=user.tenant_role,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_admin_gets_403(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "a" * 64)
    from backend.src.auth import security
    security._cached_key = None

    tenant = await tenants_service.create_tenant(db_session, name="acme", display_name="Acme")
    client_user = await _make_client(db_session, tenant)
    app.dependency_overrides[get_session] = lambda: db_session
    try:
        token = _client_token(client_user, tenant)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/admin/tenants", cookies={"waf_session": token})
        assert r.status_code == 403
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None


@pytest.mark.asyncio
async def test_unauthenticated_gets_401(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "b" * 64)
    from backend.src.auth import security
    security._cached_key = None
    app.dependency_overrides[get_session] = lambda: db_session
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/admin/tenants")
        assert r.status_code == 401
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None


@pytest.mark.asyncio
async def test_admin_gets_tenant_list(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "c" * 64)
    from backend.src.auth import security
    security._cached_key = None

    admin = await _make_admin(db_session)
    t1 = await tenants_service.create_tenant(db_session, name="alpha", display_name="Alpha")
    t2 = await tenants_service.create_tenant(db_session, name="beta", display_name="Beta")

    app.dependency_overrides[get_session] = lambda: db_session
    try:
        token = _admin_token(admin)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/admin/tenants", cookies={"waf_session": token})
        assert r.status_code == 200
        names = {row["name"] for row in r.json()}
        assert {"alpha", "beta"} == names
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None


@pytest.mark.asyncio
async def test_admin_gets_tenant_detail(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "d" * 64)
    from backend.src.auth import security
    security._cached_key = None

    admin = await _make_admin(db_session)
    tenant = await tenants_service.create_tenant(db_session, name="detail-co", display_name="Detail Co")
    await _make_client(db_session, tenant, email="owner@detail.co")

    app.dependency_overrides[get_session] = lambda: db_session
    try:
        token = _admin_token(admin)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(f"/api/admin/tenants/{tenant.id}", cookies={"waf_session": token})
        assert r.status_code == 200
        data = r.json()
        assert data["tenant"]["name"] == "detail-co"
        assert len(data["users"]) == 1
        assert data["users"][0]["email"] == "owner@detail.co"
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None


@pytest.mark.asyncio
async def test_suspend_and_unsuspend(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "e" * 64)
    from backend.src.auth import security
    security._cached_key = None

    admin = await _make_admin(db_session)
    tenant = await tenants_service.create_tenant(db_session, name="suspendme", display_name="Suspend Me")

    app.dependency_overrides[get_session] = lambda: db_session
    try:
        token = _admin_token(admin)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Suspend
            r = await c.post(f"/api/admin/tenants/{tenant.id}/suspend", cookies={"waf_session": token})
            assert r.status_code == 200
            assert r.json()["suspended_at"] is not None

            # Unsuspend
            r = await c.post(f"/api/admin/tenants/{tenant.id}/unsuspend", cookies={"waf_session": token})
            assert r.status_code == 200
            assert r.json()["suspended_at"] is None
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None


@pytest.mark.asyncio
async def test_delete_requires_confirm_matching_name(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "f" * 64)
    from backend.src.auth import security
    security._cached_key = None

    admin = await _make_admin(db_session)
    tenant = await tenants_service.create_tenant(db_session, name="del-me", display_name="Del Me")

    app.dependency_overrides[get_session] = lambda: db_session
    try:
        token = _admin_token(admin)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Wrong confirm
            r = await c.delete(
                f"/api/admin/tenants/{tenant.id}",
                params={"confirm": "wrong-name"},
                cookies={"waf_session": token},
            )
            assert r.status_code == 400

            # Correct confirm
            r = await c.delete(
                f"/api/admin/tenants/{tenant.id}",
                params={"confirm": "del-me"},
                cookies={"waf_session": token},
            )
            assert r.status_code == 204
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None


@pytest.mark.asyncio
async def test_delete_cascades_users(db_session, monkeypatch):
    """Deleting a tenant removes its rows (DB CASCADE) and the tenant itself."""
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    admin = await _make_admin(db_session)
    tenant = await tenants_service.create_tenant(db_session, name="cascade-co", display_name="Cascade Co")
    await _make_client(db_session, tenant, email="u@cascade.co")

    app.dependency_overrides[get_session] = lambda: db_session
    try:
        token = _admin_token(admin)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.delete(
                f"/api/admin/tenants/{tenant.id}",
                params={"confirm": "cascade-co"},
                cookies={"waf_session": token},
            )
            assert r.status_code == 204

            # Tenant is gone
            r = await c.get(f"/api/admin/tenants/{tenant.id}", cookies={"waf_session": token})
            assert r.status_code == 404
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None


@pytest.mark.asyncio
async def test_detail_returns_404_for_missing_tenant(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "1" * 64)
    from backend.src.auth import security
    security._cached_key = None

    admin = await _make_admin(db_session)
    app.dependency_overrides[get_session] = lambda: db_session
    try:
        token = _admin_token(admin)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/admin/tenants/99999", cookies={"waf_session": token})
        assert r.status_code == 404
    finally:
        app.dependency_overrides.pop(get_session, None)
        security._cached_key = None
