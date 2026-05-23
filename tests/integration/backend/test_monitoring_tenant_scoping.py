"""Monitoring tenant-scoping tests (Phase 5.2.e).

Decision: monitoring exposes Docker stats for all containers in the compose
project. This is platform-wide infrastructure data. Every endpoint requires
`require_admin`. This file asserts that a logged-in client user gets 403 on
all /api/monitoring/* routes.
"""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.src.auth.dependencies import SESSION_COOKIE
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth_service
from backend.src.db.session import get_session
from backend.src.tenants import service as tenants
from backend.src.monitoring.router import router as monitoring_router


def _app(db_session):
    app = FastAPI()

    async def _get_session():
        yield db_session

    app.dependency_overrides[get_session] = _get_session
    app.include_router(monitoring_router)
    return app


async def _client_token(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants.create_tenant(db_session, name="acme-mon", display_name="Acme")
    u = await auth_service.create_client_user(
        db_session,
        email="client-mon@example.com",
        password="hunter22d",
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
async def test_client_cannot_get_monitoring_metrics(db_session, monkeypatch):
    """Client user → 403 on GET /api/monitoring/metrics."""
    token = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/monitoring/metrics", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_client_cannot_list_monitoring_containers(db_session, monkeypatch):
    """Client user → 403 on GET /api/monitoring/containers."""
    token = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/monitoring/containers", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_cannot_get_monitoring_metrics(db_session):
    """No session → 401."""
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/monitoring/metrics")
    assert r.status_code == 401
