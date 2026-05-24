"""CrowdSec tenant-scoping tests (Phase 5.2.a).

Decision: CrowdSec is a platform-wide anti-bot layer — decisions, scenarios,
alerts, and service state are global, not per-tenant. Every endpoint requires
`require_admin`. This file asserts that a logged-in client user gets 403 on
all /api/crowdsec/* routes.
"""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from backend.src.auth.dependencies import SESSION_COOKIE, require_verified
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth_service
from backend.src.db.models import User
from backend.src.db.session import get_session
from backend.src.tenants import service as tenants
from backend.src.crowdsec.router import router as crowdsec_router


def _app(db_session):
    app = FastAPI()

    async def _get_session():
        yield db_session

    app.dependency_overrides[get_session] = _get_session
    app.include_router(crowdsec_router)
    return app


async def _client_token(db_session, monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants.create_tenant(db_session, name="acme-cs", display_name="Acme")
    u = await auth_service.create_client_user(
        db_session,
        email="client-cs@example.com",
        password="hunter22b",
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
async def test_client_cannot_get_crowdsec_status(db_session, monkeypatch):
    """Client user → 403 on GET /api/crowdsec/status."""
    token = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/status", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_client_cannot_get_crowdsec_decisions(db_session, monkeypatch):
    """Client user → 403 on GET /api/crowdsec/decisions."""
    token = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/decisions", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_client_cannot_get_crowdsec_alerts(db_session, monkeypatch):
    """Client user → 403 on GET /api/crowdsec/alerts."""
    token = await _client_token(db_session, monkeypatch)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/alerts", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_cannot_get_crowdsec_status(db_session):
    """No session → 401 (not 200)."""
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/status")
    assert r.status_code == 401
