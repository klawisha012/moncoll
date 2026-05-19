"""Unit tests for dashboard.service — focused on resilience and filtering.

These tests mock the ClickHouse client so they run without docker.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.dashboard import service as ds


@pytest.fixture
def mock_ch_client():
    client = MagicMock()
    client.execute = MagicMock(return_value=[])
    with patch.object(ds, "_get_client", return_value=client):
        yield client


# ── helper coverage ──────────────────────────────────────────


def test_quote_domains_empty_returns_sentinel():
    """Empty input must not produce a syntactically empty IN list."""
    assert ds._quote_domains([]) == f"('{ds._NO_DOMAINS_SENTINEL}')"


def test_quote_domains_strips_single_quotes():
    """Defensive escaping — a stray apostrophe must not break the SQL."""
    assert ds._quote_domains(["bad'name.test"]) == "('badname.test')"


def test_quote_domains_renders_in_list():
    assert ds._quote_domains(["a.test", "b.test"]) == "('a.test', 'b.test')"


def test_host_filter_nginx_no_domains_is_empty():
    assert ds._host_filter_nginx([]) == ""


def test_host_filter_nginx_with_domains():
    assert ds._host_filter_nginx(["a.test"]) == " AND host IN ('a.test')"


def test_host_filter_waf_uses_request_headers():
    assert ds._host_filter_waf(["x.test"]) == " AND request_headers['Host'] IN ('x.test')"


def test_clamp_minutes_floor_is_one_minute():
    assert ds._clamp_minutes(0.0001) == 1


def test_clamp_minutes_ceiling_is_one_year():
    assert ds._clamp_minutes(99_999) == 8760 * 60


def test_safe_execute_swallows_clickhouse_error(mock_ch_client):
    from clickhouse_driver.errors import Error as ClickHouseError

    mock_ch_client.execute.side_effect = ClickHouseError("boom")
    assert ds._safe_execute(mock_ch_client, "SELECT 1", default="fallback") == "fallback"


def test_safe_execute_swallows_unexpected_error(mock_ch_client):
    mock_ch_client.execute.side_effect = RuntimeError("kaboom")
    assert ds._safe_execute(mock_ch_client, "SELECT 1", default=[]) == []


def test_scalar_returns_default_on_empty():
    assert ds._scalar([], default=42) == 42


def test_scalar_extracts_first_cell():
    assert ds._scalar([(7,)]) == 7


# ── threat-origins — must never 500 ──────────────────────────


def test_threat_origins_empty_table_returns_empty_list(mock_ch_client):
    mock_ch_client.execute.return_value = [(0,)]  # total_blocks = 0
    assert ds.get_threat_origins() == []


def test_threat_origins_falls_back_when_join_fails(mock_ch_client):
    from clickhouse_driver.errors import Error as ClickHouseError

    # First call (total_blocks) succeeds, second (the JOIN) fails.
    mock_ch_client.execute.side_effect = [
        [(100,)],
        ClickHouseError("JOIN type mismatch"),
    ]
    result = ds.get_threat_origins()
    assert result == [{"country": "UNKNOWN", "country_code": "UNKNOWN", "blocks_percent": 100.0}]


def test_threat_origins_no_client_returns_empty():
    with patch.object(ds, "_get_client", side_effect=Exception("no clickhouse")):
        assert ds.get_threat_origins() == []


def test_threat_origins_unknown_country_code_normalised(mock_ch_client):
    mock_ch_client.execute.side_effect = [
        [(10,)],
        [("", 3), ("US", 7)],
    ]
    result = ds.get_threat_origins()
    assert result[0]["country_code"] == "UNKNOWN"
    assert result[0]["blocks_percent"] == 30.0
    assert result[1]["country_code"] == "US"
    assert result[1]["blocks_percent"] == 70.0


# ── metrics resilience ──────────────────────────────────────


def test_metrics_no_client_returns_zeros():
    with patch.object(ds, "_get_client", side_effect=Exception("nope")):
        m = ds.get_dashboard_metrics()
    assert m["total_requests"] == 0
    assert m["system_health"] == 100.0
    assert m["blocked_threats"] == 0


def test_metrics_with_traffic(mock_ch_client):
    # call order: total_req, prev_total, blocked_threats, high_sev, active_rules, error_responses
    mock_ch_client.execute.side_effect = [
        [(1000,)],
        [(500,)],
        [(20,)],
        [(5,)],
        [(3,)],
        [(10,)],
    ]
    m = ds.get_dashboard_metrics(hours=24)
    assert m["total_requests"] == 1000
    assert m["total_requests_change"] == 100.0
    assert m["blocked_threats"] == 20
    assert m["high_severity_count"] == 5
    assert m["active_rules"] == 3
    assert m["system_health"] == 99.0


# ── per-domain filter wiring ────────────────────────────────


def test_metrics_passes_host_filter_when_connection_id_supplied(mock_ch_client):
    """When _domains_for_connection returns domains, every query must include the AND host IN clause."""
    with patch.object(ds, "_domains_for_connection", return_value=["a.test"]):
        mock_ch_client.execute.return_value = [(0,)]
        ds.get_dashboard_metrics(hours=1, connection_id=42)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert any("host IN ('a.test')" in q for q in seen_queries), seen_queries
    assert any("request_headers['Host'] IN ('a.test')" in q for q in seen_queries), seen_queries
