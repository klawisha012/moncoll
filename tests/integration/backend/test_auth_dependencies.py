"""Integration tests for backend/src/auth/dependencies.py — Phase 4."""

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.src.auth.dependencies import (
    SESSION_COOKIE,
    current_tenant,
    get_current_user,
    require_client,
    require_verified,
)
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth_service
from backend.src.db.models import Tenant, User
from backend.src.db.session import get_session
from backend.src.tenants import service as tenants_service


# ---------------------------------------------------------------------------
# Minimal test app — one route per dependency under test.
# ---------------------------------------------------------------------------

def _app(db_session: AsyncSession) -> FastAPI:
    """Build a minimal FastAPI app with test-DB session injected."""
    app = FastAPI()

    async def _get_session():
        yield db_session

    app.dependency_overrides[get_session] = _get_session

    @app.get("/me")
    async def me(user: User = Depends(get_current_user)):
        return {"id": user.id, "email": user.email}

    @app.get("/client")
    async def client_route(user: User = Depends(require_client)):
        return {"id": user.id}

    @app.get("/tenant")
    async def tenant_route(tenant: Tenant = Depends(current_tenant)):
        return {"id": tenant.id, "name": tenant.name}

    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unauthenticated_request_returns_401(db_session):
    """No cookie → 401."""
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logged_in_client_can_access_current_tenant(db_session, monkeypatch):
    """Valid client session → current_tenant returns the tenant."""
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants_service.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth_service.create_client_user(
        db_session,
        email="client@example.com",
        password="hunter22a",
        tenant_id=t.id,
        email_verified=True,
    )

    token = create_session_token(
        user_id=u.id,
        platform_role="client",
        tenant_id=t.id,
        tenant_role="owner",
    )

    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/tenant", cookies={SESSION_COOKIE: token})

    assert r.status_code == 200
    data = r.json()
    assert data["id"] == t.id
    assert data["name"] == "acme"


@pytest.mark.asyncio
async def test_suspended_tenant_blocks_client(db_session, monkeypatch):
    """D3 + 5.2.f: suspended tenant → 403 on any require_verified endpoint."""
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants_service.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth_service.create_client_user(
        db_session,
        email="a@b.com",
        password="hunter22a",
        tenant_id=t.id,
        email_verified=True,
    )
    await tenants_service.suspend(db_session, t.id)

    token = create_session_token(
        user_id=u.id,
        platform_role="client",
        tenant_id=t.id,
        tenant_role="owner",
    )

    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/client", cookies={SESSION_COOKIE: token})

    assert r.status_code == 403
    assert "tenant suspended" in r.text
