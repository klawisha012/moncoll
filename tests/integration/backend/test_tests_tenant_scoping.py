"""Tests module tenant-scoping tests (Phase 5.2.d).

Decision: The tests page runs WAF probe tests. All routes already require
`require_admin`. The `resolve_target` service function queries ConnectionModel
by ID without tenant filter — since only admins can access this module (and
admins see all connections by design), this is correct.

This file asserts:
1. A logged-in client gets 403 on /api/tests/catalog and /api/tests/crowdsec/catalog.
2. An unauthenticated request gets 401.
"""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.src.auth.dependencies import SESSION_COOKIE
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth_service
from backend.src.db.session import get_session
from backend.src.tenants import service as tenants
from backend.src.tests import tests_router


def _app(db_session):
    app = FastAPI()

    async def _get_session():
        yield db_session

    app.dependency_overrides[get_session] = _get_session
    app.include_router(tests_router)
    return app


async def _client_token(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants.create_tenant(db_session, name="acme-tests", display_name="Acme")
    u = await auth_service.create_client_user(
        db_session,
        email="client-tests@example.com",
        password="hunter22e",
        tenant_id=t.id,
        email_verified=True,
    )
    return create_session_token(
        user_id=u.id,
        platform_role="client",
        tenant_id=t.id,
        tenant_role="owner",
    )


@pytest.mark.asyncio
async def test_client_cannot_get_tests_catalog(db_session, monkeypatch):
    """Client user → 403 on GET /api/tests/catalog."""
    token = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/tests/catalog", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_client_cannot_get_crowdsec_catalog(db_session, monkeypatch):
    """Client user → 403 on GET /api/tests/crowdsec/catalog."""
    token = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/tests/crowdsec/catalog", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_cannot_get_tests_catalog(db_session):
    """No session → 401."""
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/tests/catalog")
    assert r.status_code == 401
