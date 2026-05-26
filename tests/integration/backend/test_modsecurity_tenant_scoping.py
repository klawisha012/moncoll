"""ModSecurity router role gate.

Scope decision: ModSecurity rules are global filesystem configs (loaded once
at http scope by Angie). The frontend exposes /config to clients
(`RequireRole role="client"`), so the backend gate must be `require_verified`,
not `require_admin`. Per-connection ModSec state lives on
/api/connections/{id}/security and stays tenant-scoped.

These tests monkey-patch the ModSecurity config service so the assertions
focus on the auth/role gate, not filesystem availability.
"""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.src.auth.dependencies import SESSION_COOKIE
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth_service
from backend.src.db.session import get_session
from backend.src.tenants import service as tenants
from backend.src.modsecurity.router import router as modsecurity_router


def _app(db_session):
    app = FastAPI()

    async def _get_session():
        yield db_session

    app.dependency_overrides[get_session] = _get_session
    app.include_router(modsecurity_router)
    return app


async def _client_token(db_session, monkeypatch, *, suffix="ms"):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants.create_tenant(
        db_session, name=f"acme-{suffix}", display_name="Acme"
    )
    u = await auth_service.create_client_user(
        db_session,
        email=f"client-{suffix}@example.com",
        password="hunter22c",
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
async def test_client_can_get_modsec_config(db_session, monkeypatch):
    """Verified client → 200 on GET /api/modsecurity/config."""
    from backend.src.modsecurity import service as modsecurity_service

    monkeypatch.setattr(
        modsecurity_service.config_service,
        "get_config",
        lambda: ("SecRuleEngine On\n", "/etc/modsec/main.conf"),
    )

    token = await _client_token(db_session, monkeypatch, suffix="ms-cfg")
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/modsecurity/config", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    assert "SecRuleEngine" in r.json()["content"]


@pytest.mark.asyncio
async def test_client_can_list_modsec_rules(db_session, monkeypatch):
    """Verified client → 200 on GET /api/modsecurity/rules/list."""
    from backend.src.modsecurity import service as modsecurity_service

    monkeypatch.setattr(
        modsecurity_service.config_service, "list_rules", lambda: []
    )

    token = await _client_token(db_session, monkeypatch, suffix="ms-rules")
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/modsecurity/rules/list", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_unauthenticated_cannot_get_modsec_config(db_session):
    """No session → 401."""
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/api/modsecurity/config")
    assert r.status_code == 401
