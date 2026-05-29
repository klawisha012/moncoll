"""CrowdSec router role gate.

Scope decision: CrowdSec is a platform-wide anti-bot layer — decisions,
scenarios, alerts, and service state are global, not per-tenant. The frontend
exposes /crowdsec to clients (`RequireRole role="client"`), so the backend
gate must be `require_verified`, not `require_admin`.

These tests assert the auth gate behavior only — the underlying CrowdSec LAPI
calls are monkey-patched to keep the test hermetic.
"""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.src.auth.dependencies import SESSION_COOKIE
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth_service
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


async def _client_token(db_session, monkeypatch, *, suffix="cs"):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants.create_tenant(
        db_session, name=f"acme-{suffix}", display_name="Acme"
    )
    u = await auth_service.create_client_user(
        db_session,
        email=f"client-{suffix}@example.com",
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
async def test_client_can_get_crowdsec_status(db_session, monkeypatch):
    """Verified client → 200 on GET /api/crowdsec/status."""
    from backend.src.crowdsec import service as crowdsec_service
    from backend.src.crowdsec.schemas import CrowdSecStatus

    monkeypatch.setattr(
        crowdsec_service,
        "get_status",
        lambda connection_id=None: CrowdSecStatus(
            running=True,
            version="v1.test",
            decisions_count=0,
            scenarios_count=0,
            alerts_count=0,
        ),
    )

    token = await _client_token(db_session, monkeypatch, suffix="cs-status")
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/status", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    assert r.json()["version"] == "v1.test"


@pytest.mark.asyncio
async def test_client_can_get_crowdsec_decisions(db_session, monkeypatch):
    """Verified client → 200 on GET /api/crowdsec/decisions."""
    from backend.src.crowdsec import service as crowdsec_service

    monkeypatch.setattr(crowdsec_service, "get_decisions", lambda connection_id=None: [])

    token = await _client_token(db_session, monkeypatch, suffix="cs-dec")
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/decisions", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_client_can_get_crowdsec_alerts(db_session, monkeypatch):
    """Verified client → 200 on GET /api/crowdsec/alerts."""
    from backend.src.crowdsec import service as crowdsec_service

    monkeypatch.setattr(crowdsec_service, "get_alerts", lambda hours=None: [])

    token = await _client_token(db_session, monkeypatch, suffix="cs-alerts")
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/alerts", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_unauthenticated_cannot_get_crowdsec_status(db_session):
    """No session → 401 (not 200)."""
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/crowdsec/status")
    assert r.status_code == 401
