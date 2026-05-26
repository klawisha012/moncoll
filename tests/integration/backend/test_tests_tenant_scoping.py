"""Tests-module role/tenant scoping.

The frontend routes /tests as `RequireRole role="client"`, so the backend
must let verified clients through. /run additionally requires a tenant
(via `current_tenant`), and the runner filters `connection_id` by the
caller's tenant so cross-tenant connection IDs fall back to the default
WAF target rather than running probes against another tenant's domain.
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


async def _client_token(db_session, monkeypatch, *, email_suffix="tests"):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants.create_tenant(
        db_session, name=f"acme-{email_suffix}", display_name="Acme"
    )
    u = await auth_service.create_client_user(
        db_session,
        email=f"client-{email_suffix}@example.com",
        password="hunter22e",
        tenant_id=t.id,
        email_verified=True,
    )
    token = create_session_token(
        user_id=u.id,
        platform_role="client",
        tenant_id=t.id,
        tenant_role="owner",
    )
    return token, t


@pytest.mark.asyncio
async def test_client_can_get_tests_catalog(db_session, monkeypatch):
    """Verified client → 200 on GET /api/tests/catalog (no admin gate)."""
    token, _ = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/tests/catalog", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    # Manifest may be empty in test env — only the shape is asserted.
    assert "tests" in r.json()


@pytest.mark.asyncio
async def test_client_can_get_crowdsec_catalog(db_session, monkeypatch):
    """Verified client → 200 on GET /api/tests/crowdsec/catalog."""
    token, _ = await _client_token(db_session, monkeypatch, email_suffix="cs-cat")
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/tests/crowdsec/catalog", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    assert "scenarios" in r.json()


@pytest.mark.asyncio
async def test_unauthenticated_cannot_get_tests_catalog(db_session):
    """No session → 401."""
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/tests/catalog")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_run_resolves_to_default_when_connection_belongs_to_other_tenant(
    db_session, monkeypatch
):
    """Cross-tenant connection_id is dropped silently in resolve_target.

    Service-layer assertion (no HTTP round-trip): proves the tenant_id filter
    on resolve_target makes a foreign connection ID look unset to the runner.
    """
    from tests.integration.backend.conftest import insert_connection_raw
    from backend.src.tests.service import resolve_target

    a = await tenants.create_tenant(db_session, name="tenant-a-scope", display_name="A")
    b = await tenants.create_tenant(db_session, name="tenant-b-scope", display_name="B")
    conn_b = await insert_connection_raw(
        db_session, tenant_id=b.id, domain="b.example.com", name="b1"
    )

    # Tenant A asks for tenant B's connection_id → falls back to default URL,
    # no connection returned.
    url, conn = await resolve_target(db_session, conn_b.id, tenant_id=a.id)
    assert conn is None
    assert url  # default WAF URL

    # Sanity: with the right tenant, the connection IS returned.
    url_b, conn_b_resolved = await resolve_target(
        db_session, conn_b.id, tenant_id=b.id
    )
    assert conn_b_resolved is not None
    assert conn_b_resolved.id == conn_b.id
