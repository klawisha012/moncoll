"""Router-level unit tests for /api/ssl/*.

These endpoints are normally driven by the background ACME poller, so the
HTTP surface is rarely exercised. Pin the no-AttributeError contract:
`conn.domain` (singular, from the domain-only Connection schema) must reach
the SAN-aware ssl_service wrapped as a one-element list.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.auth.dependencies import current_tenant, require_verified
from src.certificates import service as ssl_service
from src.certificates.router import certificates_router
from src.connections import service as connection_service
from src.connections.schemas import Connection
from src.db.session import get_session


def _fake_tenant(tenant_id: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=tenant_id, name="acme")


def _fake_connection(connection_id: int = 1, domain: str = "example.com") -> Connection:
    """A domain-only Connection schema instance (singular `domain`, no `.domains`)."""
    now = datetime.now(UTC)
    return Connection.model_validate(
        {
            "id": connection_id,
            "tenant_id": 1,
            "name": "test",
            "domain": domain,
            "origin_hosts": ["127.0.0.1"],
            "origin_port": 443,
            "origin_tls_mode": "strict",
            "verify_token": "x" * 32,
            "verified_at": now,
            "status": "active",
            "status_detail": None,
            "acme_retry_count": 0,
            "acme_next_retry_at": None,
            "next_poll_at": None,
            "dns_ttl_seconds": 60,
            "last_checked_at": None,
            "http_versions": "h1,h2",
            "compression_algo": "auto",
            "enabled": True,
            "modsec_state": "blocking",
            "geoip_denied_countries": [],
            "ssl_cert_path": None,
            "ssl_key_path": None,
            "created_at": now,
            "updated_at": now,
        }
    )


@pytest.fixture
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(certificates_router)
    return a


def test_regenerate_wraps_singular_domain_into_san_list(app: FastAPI):
    """Regression: `conn.domains` raised AttributeError; `[conn.domain]` does not."""
    app.dependency_overrides[require_verified] = lambda: SimpleNamespace(id=1)
    app.dependency_overrides[current_tenant] = lambda: _fake_tenant()
    app.dependency_overrides[get_session] = lambda: None

    fake_conn = _fake_connection(connection_id=42, domain="foo.example.com")
    ssl_result = {"success": True, "message": "ok", "certificate_path": "/x", "key_path": "/y"}

    with (
        patch.object(connection_service, "get_connection", new=AsyncMock(return_value=fake_conn)),
        patch.object(ssl_service, "regenerate_certificate", return_value=ssl_result) as mock_regen,
    ):
        try:
            client = TestClient(app)
            resp = client.post("/api/ssl/regenerate/42")
        finally:
            app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    assert resp.json() == ssl_result
    # The SAN-aware service must receive the singular domain wrapped as a list.
    mock_regen.assert_called_once_with(42, ["foo.example.com"])


def test_request_uses_body_domains_without_touching_conn_domains(app: FastAPI):
    """Happy path: body provides domains, conn.domain is not read — but the
    attribute access in the fallback branch must still be valid (it's `conn.domain`,
    not the broken `conn.domains`).
    """
    app.dependency_overrides[require_verified] = lambda: SimpleNamespace(id=1)
    app.dependency_overrides[current_tenant] = lambda: _fake_tenant()
    app.dependency_overrides[get_session] = lambda: None

    fake_conn = _fake_connection(connection_id=7, domain="bar.example.com")
    ssl_result = {"success": True, "message": "ok"}

    with (
        patch.object(connection_service, "get_connection", new=AsyncMock(return_value=fake_conn)),
        patch.object(ssl_service, "trigger_acme_request", return_value=ssl_result) as mock_acme,
    ):
        try:
            client = TestClient(app)
            resp = client.post(
                "/api/ssl/request/7",
                json={"domains": ["bar.example.com"], "challenge_type": "http"},
            )
        finally:
            app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    mock_acme.assert_called_once_with(7, ["bar.example.com"])
