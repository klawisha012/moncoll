"""Suspended-tenant regression test (Phase 5.2.f / spec §8.3).

Tests the full suspend → next-request-blocked → unsuspend → next-request-unblocked
cycle. This is the "users logged out within one request" guarantee.

The test uses a minimal FastAPI app wired to the test DB, so no real session
store is needed — the PASETO token stays valid (it has no expiry gate here)
but the tenant.suspended_at check in require_verified fires every request.
"""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from backend.src.auth.dependencies import SESSION_COOKIE, require_verified
from backend.src.auth.security import create_session_token
from backend.src.auth import service as auth_service
from backend.src.db.models import Tenant, User
from backend.src.db.session import get_session
from backend.src.tenants import service as tenants_service


# ---------------------------------------------------------------------------
# Minimal test app
# ---------------------------------------------------------------------------

def _app(db_session):
    """Minimal app: single authenticated endpoint + overridden DB session."""
    app = FastAPI()

    async def _get_session():
        yield db_session

    app.dependency_overrides[get_session] = _get_session

    @app.get("/ping")
    async def ping(user: User = Depends(require_verified)):
        return {"ok": True, "user_id": user.id}

    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suspend_blocks_active_session_immediately(db_session, monkeypatch):
    """§8.3: after suspend, very next request with an existing token → 403."""
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants_service.create_tenant(db_session, name="suspend-a", display_name="A")
    u = await auth_service.create_client_user(
        db_session,
        email="suspend-a@example.com",
        password="hunter22z",
        tenant_id=t.id,
        email_verified=True,
    )
    token = create_session_token(
        user_id=u.id,
        platform_role="client",
        tenant_id=t.id,
        tenant_role="owner",
    )

    # Before suspension: request succeeds.
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/ping", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200, f"Expected 200 before suspend, got {r.status_code}"

    # Suspend the tenant.
    await tenants_service.suspend(db_session, t.id)

    # Same token, next request → 403.
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/ping", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403, f"Expected 403 after suspend, got {r.status_code}"
    assert "tenant suspended" in r.text


@pytest.mark.asyncio
async def test_unsuspend_restores_access_immediately(db_session, monkeypatch):
    """§8.3 reverse: after unsuspend, same token → 200 again."""
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants_service.create_tenant(db_session, name="suspend-b", display_name="B")
    u = await auth_service.create_client_user(
        db_session,
        email="suspend-b@example.com",
        password="hunter22y",
        tenant_id=t.id,
        email_verified=True,
    )
    token = create_session_token(
        user_id=u.id,
        platform_role="client",
        tenant_id=t.id,
        tenant_role="owner",
    )

    # Suspend → blocked.
    await tenants_service.suspend(db_session, t.id)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/ping", cookies={SESSION_COOKIE: token})
    assert r.status_code == 403

    # Unsuspend → unblocked.
    await tenants_service.unsuspend(db_session, t.id)
    async with AsyncClient(
        transport=ASGITransport(app=_app(db_session)), base_url="http://test"
    ) as c:
        r = await c.get("/ping", cookies={SESSION_COOKIE: token})
    assert r.status_code == 200, f"Expected 200 after unsuspend, got {r.status_code}"
    assert r.json()["user_id"] == u.id


@pytest.mark.asyncio
async def test_full_suspend_unsuspend_cycle(db_session, monkeypatch):
    """Full cycle: active → suspend → blocked → unsuspend → active → suspend again."""
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t = await tenants_service.create_tenant(db_session, name="suspend-c", display_name="C")
    u = await auth_service.create_client_user(
        db_session,
        email="suspend-c@example.com",
        password="hunter22x",
        tenant_id=t.id,
        email_verified=True,
    )
    token = create_session_token(
        user_id=u.id,
        platform_role="client",
        tenant_id=t.id,
        tenant_role="owner",
    )

    app = _app(db_session)

    async def _get(expected_status: int, step: str):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.get("/ping", cookies={SESSION_COOKIE: token})
        assert r.status_code == expected_status, (
            f"Step '{step}': expected {expected_status}, got {r.status_code} — {r.text}"
        )

    # 1. Active — should succeed
    await _get(200, "initial active")

    # 2. Suspend — should block
    await tenants_service.suspend(db_session, t.id)
    await _get(403, "suspended")

    # 3. Unsuspend — should restore
    await tenants_service.unsuspend(db_session, t.id)
    await _get(200, "unsuspended")

    # 4. Suspend again — should block again (idempotent)
    await tenants_service.suspend(db_session, t.id)
    await _get(403, "re-suspended")


@pytest.mark.asyncio
async def test_suspending_one_tenant_does_not_block_other(db_session, monkeypatch):
    """Tenant A's suspension must not affect tenant B's users."""
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    from backend.src.auth import security
    security._cached_key = None

    t_a = await tenants_service.create_tenant(db_session, name="suspend-d", display_name="D")
    t_b = await tenants_service.create_tenant(db_session, name="suspend-e", display_name="E")

    u_a = await auth_service.create_client_user(
        db_session,
        email="suspend-d@example.com",
        password="hunter22w",
        tenant_id=t_a.id,
        email_verified=True,
    )
    u_b = await auth_service.create_client_user(
        db_session,
        email="suspend-e@example.com",
        password="hunter22v",
        tenant_id=t_b.id,
        email_verified=True,
    )

    token_a = create_session_token(
        user_id=u_a.id, platform_role="client", tenant_id=t_a.id, tenant_role="owner"
    )
    token_b = create_session_token(
        user_id=u_b.id, platform_role="client", tenant_id=t_b.id, tenant_role="owner"
    )

    app = _app(db_session)

    # Suspend tenant A
    await tenants_service.suspend(db_session, t_a.id)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        r_a = await c.get("/ping", cookies={SESSION_COOKIE: token_a})
        r_b = await c.get("/ping", cookies={SESSION_COOKIE: token_b})

    assert r_a.status_code == 403, "Tenant A should be blocked"
    assert r_b.status_code == 200, "Tenant B should be unaffected"
