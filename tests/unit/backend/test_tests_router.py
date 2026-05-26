"""Router-level unit tests for /api/tests/*.

Pin the auth contract (verified-user gate + tenant scoping on /run) and the
in-process rate limit. The runner itself is stubbed — we are NOT verifying
that ModSec sees the request, only that the router validates inputs and
dispatches correctly.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.auth.dependencies import current_tenant, require_verified
from src.db.session import get_session
from src.tests import crowdsec_runner
from src.tests import service as tests_service
from src.tests.router import _rate_last, router as _tests_router
from src.tests.schemas import CrowdsecRunResult, RunResult


def _fake_user(user_id: int = 1) -> SimpleNamespace:
    """Duck-typed User stand-in. Router only reads `.id` for rate-limit."""
    return SimpleNamespace(id=user_id, platform_role="client", username="root")


def _fake_tenant(tenant_id: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=tenant_id, name="acme")


@pytest.fixture
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(_tests_router)
    return a


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    # The rate-limit dict is module-global; clear between tests so they don't
    # cross-contaminate (test order would otherwise matter).
    _rate_last.clear()
    yield
    _rate_last.clear()


# ── auth guard ────────────────────────────────────────────────────────


def test_catalog_requires_authenticated_user(app: FastAPI):
    """Without an override the cookie auth chain runs and 401s on no cookie."""
    app.dependency_overrides[get_session] = lambda: None
    try:
        client = TestClient(app)
        resp = client.get("/api/tests/catalog")
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 401


def test_catalog_returns_tests_when_verified(app: FastAPI):
    app.dependency_overrides[require_verified] = lambda: _fake_user()
    try:
        client = TestClient(app)
        resp = client.get("/api/tests/catalog")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["tests"], list)
    # The committed manifest has 246 entries; assert non-empty without pinning count.
    assert body["tests"], "catalog endpoint returned empty tests list"


def test_crowdsec_catalog_returns_scenarios(app: FastAPI):
    app.dependency_overrides[require_verified] = lambda: _fake_user()
    try:
        client = TestClient(app)
        resp = client.get("/api/tests/crowdsec/catalog")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    scenarios = resp.json()["scenarios"]
    assert isinstance(scenarios, list) and scenarios


# ── /run input validation ─────────────────────────────────────────────


def test_run_rejects_unknown_test_id(app: FastAPI):
    app.dependency_overrides[require_verified] = lambda: _fake_user()
    app.dependency_overrides[current_tenant] = lambda: _fake_tenant()
    # /run touches get_session before reaching the find_test check, so override
    # the session dep too so the request doesn't try to hit a real DB.
    app.dependency_overrides[get_session] = lambda: None
    try:
        client = TestClient(app)
        resp = client.post("/api/tests/run", json={"test_id": "does.not.exist"})
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 400
    assert "unknown test_id" in resp.json()["detail"]


def test_run_dispatches_to_runner_for_known_test(app: FastAPI):
    """Happy path: valid test_id → service.run_test is awaited with tenant_id."""
    app.dependency_overrides[require_verified] = lambda: _fake_user()
    app.dependency_overrides[current_tenant] = lambda: _fake_tenant(tenant_id=42)
    app.dependency_overrides[get_session] = lambda: None

    fake_result = RunResult(
        marker="00000000-0000-4000-8000-000000000000",
        status="blocked",
        http_code=403,
        blocked_by="941100",
        latency_ms=42,
        target_url="http://angie",
    )

    async_mock = AsyncMock(return_value=fake_result)
    with patch.object(tests_service, "run_test", new=async_mock):
        try:
            client = TestClient(app)
            # xss.941100 is in the committed manifest.
            resp = client.post("/api/tests/run", json={"test_id": "xss.941100"})
        finally:
            app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "blocked"
    assert body["blocked_by"] == "941100"
    # The router must forward tenant_id from current_tenant into the runner so
    # connection_id resolution stays scoped.
    assert async_mock.await_args.kwargs.get("tenant_id") == 42


# ── rate limit ────────────────────────────────────────────────────────


def test_run_rate_limit_429_on_second_immediate_call(app: FastAPI):
    app.dependency_overrides[require_verified] = lambda: _fake_user(user_id=7)
    app.dependency_overrides[current_tenant] = lambda: _fake_tenant()
    app.dependency_overrides[get_session] = lambda: None

    fake_result = RunResult(
        marker="11111111-1111-4111-8111-111111111111",
        status="passed",
        http_code=200,
        target_url="http://angie",
    )

    with patch.object(tests_service, "run_test", new=AsyncMock(return_value=fake_result)):
        try:
            client = TestClient(app)
            first = client.post("/api/tests/run", json={"test_id": "xss.941100"})
            second = client.post("/api/tests/run", json={"test_id": "xss.941100"})
        finally:
            app.dependency_overrides.clear()

    assert first.status_code == 200, first.text
    assert second.status_code == 429
    assert "rate limit" in second.json()["detail"]


def test_run_rate_limit_is_per_user(app: FastAPI):
    """User A hitting rate limit must not block user B's first request."""
    user_holder = {"current": _fake_user(user_id=10)}

    def _override_user():
        return user_holder["current"]

    app.dependency_overrides[require_verified] = _override_user
    app.dependency_overrides[current_tenant] = lambda: _fake_tenant()
    app.dependency_overrides[get_session] = lambda: None

    fake_result = RunResult(
        marker="22222222-2222-4222-8222-222222222222",
        status="passed",
        http_code=200,
        target_url="http://angie",
    )

    with patch.object(tests_service, "run_test", new=AsyncMock(return_value=fake_result)):
        try:
            client = TestClient(app)
            # User A: two back-to-back → second is 429
            user_holder["current"] = _fake_user(user_id=10)
            r1 = client.post("/api/tests/run", json={"test_id": "xss.941100"})
            r2 = client.post("/api/tests/run", json={"test_id": "xss.941100"})
            # User B: first request after A's 429 → should still be 200
            user_holder["current"] = _fake_user(user_id=11)
            r3 = client.post("/api/tests/run", json={"test_id": "xss.941100"})
        finally:
            app.dependency_overrides.clear()

    assert r1.status_code == 200
    assert r2.status_code == 429
    assert r3.status_code == 200, r3.text


# ── /crowdsec/run input validation ────────────────────────────────────


def test_crowdsec_run_rejects_empty_scenario_id(app: FastAPI):
    app.dependency_overrides[require_verified] = lambda: _fake_user()
    try:
        client = TestClient(app)
        resp = client.post("/api/tests/crowdsec/run", json={"scenario_id": "  "})
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 400
    assert "scenario_id required" in resp.json()["detail"]


def test_crowdsec_run_dispatches_to_runner(app: FastAPI):
    app.dependency_overrides[require_verified] = lambda: _fake_user()
    fake = CrowdsecRunResult(
        scenario="crowdsecurity/http-probing",
        source_ip="self",
        started_at="2026-05-21T20:00:00+00:00",
        decisions_after=["1.2.3.4"],
        bursts_sent=8,
        target_url="http://angie",
    )
    with patch.object(crowdsec_runner, "run_scenario", new=AsyncMock(return_value=fake)):
        try:
            client = TestClient(app)
            resp = client.post(
                "/api/tests/crowdsec/run",
                json={"scenario_id": "crowdsec.http-probing"},
            )
        finally:
            app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert body["bursts_sent"] == 8
    assert body["decisions_after"] == ["1.2.3.4"]
