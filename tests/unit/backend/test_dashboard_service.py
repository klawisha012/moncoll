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
    with ds._cache_lock:
        ds._cache.clear()
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


def test_host_filter_nginx_none_means_no_filter():
    """``None`` is the admin "see everything" sentinel — must be empty string."""
    assert ds._host_filter_nginx(None) == ""


def test_host_filter_nginx_empty_list_matches_nothing():
    """Empty list (client w/ zero domains) must produce a never-match filter,
    NOT the empty string — otherwise the dashboard leaks default-server and
    other-tenant traffic."""
    assert ds._host_filter_nginx([]) == f" AND host IN ('{ds._NO_DOMAINS_SENTINEL}')"


def test_host_filter_nginx_with_domains():
    assert ds._host_filter_nginx(["a.test"]) == " AND host IN ('a.test')"


def test_host_filter_waf_none_means_no_filter():
    assert ds._host_filter_waf(None) == ""


def test_host_filter_waf_empty_list_matches_nothing():
    assert (
        ds._host_filter_waf([])
        == f" AND request_headers['Host'] IN ('{ds._NO_DOMAINS_SENTINEL}')"
    )


def test_host_filter_waf_uses_request_headers():
    assert (
        ds._host_filter_waf(["x.test"]) == " AND request_headers['Host'] IN ('x.test')"
    )


def test_clamp_minutes_floor_is_one_minute():
    assert ds._clamp_minutes(0.0001) == 1


def test_clamp_minutes_ceiling_is_one_year():
    assert ds._clamp_minutes(99_999) == 8760 * 60


def test_safe_execute_swallows_clickhouse_error(mock_ch_client):
    from clickhouse_driver.errors import Error as ClickHouseError

    mock_ch_client.execute.side_effect = ClickHouseError("boom")
    assert (
        ds._safe_execute(mock_ch_client, "SELECT 1", default="fallback") == "fallback"
    )


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
    assert result == [
        {"country": "UNKNOWN", "country_code": "UNKNOWN", "blocks_percent": 100.0}
    ]


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
    assert any("request_headers['Host'] IN ('a.test')" in q for q in seen_queries), (
        seen_queries
    )


# ── tenant-isolation: client w/ zero domains gets a sentinel filter ────────


def test_metrics_client_with_no_domains_filters_to_nothing(mock_ch_client):
    """A client whose tenant has zero enabled connections must NOT see platform-wide
    traffic (default.conf, other tenants). _domains_for_connection returns [] for
    that case; every ClickHouse query must carry the never-match sentinel filter."""
    with patch.object(ds, "_domains_for_connection", return_value=[]):
        mock_ch_client.execute.return_value = [(0,)]
        ds.get_dashboard_metrics(hours=1, connection_id=None, tenant_id=42)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    sentinel = ds._NO_DOMAINS_SENTINEL
    assert all(
        f"host IN ('{sentinel}')" in q or f"request_headers['Host'] IN ('{sentinel}')" in q
        for q in seen_queries
    ), seen_queries


def test_metrics_admin_no_connection_has_no_host_filter(mock_ch_client):
    """Admin (tenant_id=None) viewing all domains (connection_id=None) must see the
    whole platform — no host filter at all."""
    with patch.object(ds, "_domains_for_connection", return_value=None):
        mock_ch_client.execute.return_value = [(0,)]
        ds.get_dashboard_metrics(hours=1, connection_id=None, tenant_id=None)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert all("host IN" not in q for q in seen_queries), seen_queries


def test_top_client_ips_now_applies_host_filter(mock_ch_client):
    """Regression: previously this endpoint ignored connection_id and tenant_id
    entirely, leaking platform-wide client-IP stats to every logged-in client."""
    with patch.object(ds, "_domains_for_connection", return_value=["t.test"]):
        mock_ch_client.execute.return_value = []
        ds.get_top_client_ips(hours=1, connection_id=5, tenant_id=1)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert any("host IN ('t.test')" in q for q in seen_queries), seen_queries


def test_status_codes_now_applies_host_filter(mock_ch_client):
    """Same regression as top_client_ips — status codes also leaked."""
    with patch.object(ds, "_domains_for_connection", return_value=[]):
        mock_ch_client.execute.return_value = []
        ds.get_status_codes_timeline(hours=1, connection_id=None, tenant_id=99)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    sentinel = ds._NO_DOMAINS_SENTINEL
    assert any(f"host IN ('{sentinel}')" in q for q in seen_queries), seen_queries


def test_traffic_volume_now_applies_host_filter(mock_ch_client):
    with patch.object(ds, "_domains_for_connection", return_value=["v.test"]):
        mock_ch_client.execute.return_value = []
        ds.get_traffic_volume(hours=1, connection_id=2, tenant_id=1)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert any("host IN ('v.test')" in q for q in seen_queries), seen_queries


def test_requests_by_country_now_applies_host_filter(mock_ch_client):
    with patch.object(ds, "_domains_for_connection", return_value=[]):
        mock_ch_client.execute.return_value = []
        ds.get_requests_by_country(hours=1, connection_id=None, tenant_id=7)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    sentinel = ds._NO_DOMAINS_SENTINEL
    assert any(f"host IN ('{sentinel}')" in q for q in seen_queries), seen_queries


def test_top_user_agents_now_applies_host_filter(mock_ch_client):
    with patch.object(ds, "_domains_for_connection", return_value=["ua.test"]):
        mock_ch_client.execute.return_value = []
        ds.get_top_user_agents(hours=1, connection_id=3, tenant_id=1)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert any("host IN ('ua.test')" in q for q in seen_queries), seen_queries


def test_requests_per_second_now_applies_host_filter(mock_ch_client):
    with patch.object(ds, "_domains_for_connection", return_value=["r.test"]):
        mock_ch_client.execute.return_value = []
        ds.get_requests_per_second(hours=1, connection_id=4, tenant_id=1)

    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert any("host IN ('r.test')" in q for q in seen_queries), seen_queries


# ── geoip-map and unresolved IPs coverage ────────────────────


def test_get_geoip_map_data_success(mock_ch_client):
    """Test get_geoip_map_data returns formatted coordinates and hits."""
    mock_ch_client.execute.return_value = [
        (37.6173, 55.7558, "RU", "Moscow", 120),
        (-122.4194, 37.7749, "US", "San Francisco", 450),
    ]
    with patch.object(ds, "_domains_for_connection", return_value=["map.test"]):
        result = ds.get_geoip_map_data(hours=2, connection_id=1, tenant_id=2)

    assert len(result) == 2
    assert result[0] == {
        "longitude": 37.6173,
        "latitude": 55.7558,
        "country_code": "RU",
        "city_name": "Moscow",
        "hits": 120,
    }
    assert result[1] == {
        "longitude": -122.4194,
        "latitude": 37.7749,
        "country_code": "US",
        "city_name": "San Francisco",
        "hits": 450,
    }
    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert any("host IN ('map.test')" in q for q in seen_queries), seen_queries


def test_get_geoip_map_data_empty_fallback(mock_ch_client):
    """Test get_geoip_map_data handles empty database returns gracefully."""
    mock_ch_client.execute.return_value = []
    result = ds.get_geoip_map_data()
    assert result == []


def test_get_geoip_map_data_no_client_returns_empty():
    with patch.object(ds, "_get_client", side_effect=Exception("ClickHouse down")):
        assert ds.get_geoip_map_data() == []


def test_get_geoip_unresolved_ips_success(mock_ch_client):
    """Test get_geoip_unresolved_ips returns external-looking IPs without GeoIP."""
    mock_ch_client.execute.return_value = [
        ("192.0.2.1", 15),
        ("198.51.100.5", 42),
    ]
    with patch.object(ds, "_domains_for_connection", return_value=["unresolved.test"]):
        result = ds.get_geoip_unresolved_ips(hours=2, connection_id=3, tenant_id=1)

    assert len(result) == 2
    assert result[0] == {"ip": "192.0.2.1", "hits": 15}
    assert result[1] == {"ip": "198.51.100.5", "hits": 42}
    seen_queries = [call.args[0] for call in mock_ch_client.execute.call_args_list]
    assert any("host IN ('unresolved.test')" in q for q in seen_queries), seen_queries


def test_get_geoip_unresolved_ips_no_client_returns_empty():
    with patch.object(ds, "_get_client", side_effect=Exception("ClickHouse down")):
        assert ds.get_geoip_unresolved_ips() == []

