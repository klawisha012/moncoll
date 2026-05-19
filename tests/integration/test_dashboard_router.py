"""Integration tests for /api/dashboard endpoints with mocked ClickHouse.

These cover task #5 (threat-origins must not 500) at the FastAPI layer —
including the new ``connection_id`` and ``hours`` query parameters.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.dashboard import service as ds
from src.dashboard.router import router as dashboard_router


@pytest.fixture
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.include_router(dashboard_router)
    return test_app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture
def mock_ch():
    ch = MagicMock()
    ch.execute = MagicMock(return_value=[(0,)])
    with patch.object(ds, "_get_client", return_value=ch):
        yield ch


# ── /threat-origins must always be 200, even when nothing is logged ──


def test_threat_origins_returns_200_when_clickhouse_empty(client: TestClient, mock_ch):
    """Reproduces the bug: previously this route 500'd on empty tables."""
    mock_ch.execute.return_value = [(0,)]
    resp = client.get("/api/dashboard/threat-origins")
    assert resp.status_code == 200
    assert resp.json() == []


def test_threat_origins_returns_200_when_clickhouse_unavailable(client: TestClient):
    """When ClickHouse can't be reached, the endpoint should still 200 with []."""
    with patch.object(ds, "_get_client", side_effect=Exception("connection refused")):
        resp = client.get("/api/dashboard/threat-origins")
    assert resp.status_code == 200
    assert resp.json() == []


def test_threat_origins_accepts_hours_param(client: TestClient, mock_ch):
    mock_ch.execute.return_value = [(0,)]
    resp = client.get("/api/dashboard/threat-origins?hours=1")
    assert resp.status_code == 200


def test_threat_origins_rejects_out_of_range_hours(client: TestClient, mock_ch):
    resp = client.get("/api/dashboard/threat-origins?hours=99999")
    assert resp.status_code == 422


def test_threat_origins_accepts_connection_id(client: TestClient, mock_ch):
    mock_ch.execute.return_value = [(0,)]
    with patch.object(ds, "_domains_for_connection", return_value=["a.test"]):
        resp = client.get("/api/dashboard/threat-origins?connection_id=42")
    assert resp.status_code == 200


# ── /metrics resilience ───────────────────────────────────────


def test_metrics_returns_200_when_clickhouse_unavailable(client: TestClient):
    with patch.object(ds, "_get_client", side_effect=Exception("nope")):
        resp = client.get("/api/dashboard/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_requests"] == 0
    assert body["system_health"] == 100.0


def test_metrics_with_connection_id_filters_by_host(client: TestClient, mock_ch):
    """The connection_id param should drive every query through the host filter."""
    mock_ch.execute.return_value = [(0,)]
    with patch.object(ds, "_domains_for_connection", return_value=["a.test", "b.test"]):
        resp = client.get("/api/dashboard/metrics?hours=1&connection_id=3")
    assert resp.status_code == 200
    queries = [c.args[0] for c in mock_ch.execute.call_args_list]
    assert any("host IN ('a.test', 'b.test')" in q for q in queries)
    assert any("request_headers['Host'] IN ('a.test', 'b.test')" in q for q in queries)


# ── /events extended params ───────────────────────────────────


def test_events_accepts_hours_and_connection_id(client: TestClient, mock_ch):
    mock_ch.execute.return_value = []
    with patch.object(ds, "_domains_for_connection", return_value=["x.test"]):
        resp = client.get(
            "/api/dashboard/events?limit=5&severity=high&hours=2&connection_id=9"
        )
    assert resp.status_code == 200
    assert resp.json() == []
