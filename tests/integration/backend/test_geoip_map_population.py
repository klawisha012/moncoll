"""Integration tests for populating and querying ClickHouse GeoIP map data.

These tests run conditionally — if a live ClickHouse instance is reachable,
they seed realistic global threat coordinates (US, RU, GB, JP, CN, etc.) and
verify the WAF dashboard endpoints correctly scope and aggregate them.
"""

from datetime import datetime, timezone
import pytest

from backend.src.dashboard.service import (
    _get_client,
    get_geoip_map_data,
    get_geoip_unresolved_ips,
)

# Realistic GeoIP coordinates for global cities to populate the 2D/3D map
# Format: (ip, country_code, city_name, latitude, longitude, host, hits_to_insert)
MOCK_LOCATIONS = [
    ("81.177.100.1", "RU", "Moscow", 55.7558, 37.6173, "waf.example.com", 25),
    ("8.8.8.8", "US", "Mountain View", 37.4220, -122.0841, "waf.example.com", 45),
    ("178.62.200.1", "GB", "London", 51.5074, -0.1278, "waf.example.com", 18),
    ("210.140.10.1", "JP", "Tokyo", 35.6762, 139.6503, "waf.example.com", 32),
    ("114.114.114.114", "CN", "Nanjing", 32.0603, 118.7969, "waf.example.com", 15),
    ("1.1.1.1", "AU", "Sydney", -33.8688, 151.2093, "waf.example.com", 21),
    ("163.121.10.1", "EG", "Cairo", 30.0444, 31.2357, "waf.example.com", 9),
    ("186.200.10.1", "BR", "Rio de Janeiro", -22.9068, -43.1729, "waf.example.com", 13),
]

# External-looking IPs that lack GeoIP coordinates to test get_geoip_unresolved_ips
MOCK_UNRESOLVED = [
    ("203.0.113.5", "", "", 0.0, 0.0, "waf.example.com", 8),
    ("198.51.100.10", "", "", 0.0, 0.0, "waf.example.com", 12),
]


def is_clickhouse_available() -> bool:
    """Check if ClickHouse is up and running in the current test environment."""
    try:
        client = _get_client()
        client.execute("SELECT 1")
        return True
    except Exception:
        return False


@pytest.mark.skipif(not is_clickhouse_available(), reason="ClickHouse is unreachable")
def test_clickhouse_geoip_map_population():
    """Verify that seeding ClickHouse populates WAF 2D/3D map and unresolved endpoints."""
    client = _get_client()

    # Clear old test logs from past runs to ensure clean state
    client.execute("TRUNCATE TABLE logs.nginx_access_log")

    now = datetime.now(timezone.utc)
    insert_data = []

    # 1. Populate normal GeoIP mapped data points
    for ip, country, city, lat, lon, host, count in MOCK_LOCATIONS:
        for _ in range(count):
            insert_data.append((
                now,
                ip,
                "",  # remote_user
                "GET",
                "/api/test-geoip",
                "HTTP/1.1",
                200,
                1024,
                "",  # referer
                "pytest-geoip-population",
                country,
                city,
                "Test Org",
                lat,
                lon,
                host
            ))

    # 2. Populate unresolved GeoIP data points
    for ip, country, city, lat, lon, host, count in MOCK_UNRESOLVED:
        for _ in range(count):
            insert_data.append((
                now,
                ip,
                "",  # remote_user
                "GET",
                "/api/test-unresolved",
                "HTTP/1.1",
                404,
                256,
                "",  # referer
                "pytest-unresolved-population",
                country,
                city,
                "",
                lat,
                lon,
                host
            ))

    # Perform batch insert
    client.execute(
        "INSERT INTO logs.nginx_access_log ("
        "  time_local, remote_addr, remote_user, request_method, request_uri, "
        "  server_protocol, status, body_bytes_sent, http_referer, http_user_agent, "
        "  geoip_country_code, geoip_city_name, geoip_organization, "
        "  geoip_latitude, geoip_longitude, host"
        ") VALUES",
        insert_data
    )

    # Allow query cache clearance and run maps fetcher
    map_data = get_geoip_map_data(hours=1, connection_id=None, tenant_id=None)

    # Verify GeoIP 2D/3D map results
    assert len(map_data) >= len(MOCK_LOCATIONS), f"Expected at least {len(MOCK_LOCATIONS)} locations"
    
    # Check that Moscow coordinates are correctly returned
    moscow = next((m for m in map_data if m["country_code"] == "RU" and m["city_name"] == "Moscow"), None)
    assert moscow is not None, "Moscow record missing in GeoIP map output"
    assert abs(moscow["latitude"] - 55.7558) < 0.01
    assert abs(moscow["longitude"] - 37.6173) < 0.01
    assert moscow["hits"] == 25

    # Check Mountain View
    mv = next((m for m in map_data if m["country_code"] == "US" and m["city_name"] == "Mountain View"), None)
    assert mv is not None
    assert mv["hits"] == 45

    # Verify Unresolved IPs
    unresolved_ips = get_geoip_unresolved_ips(hours=1, connection_id=None, tenant_id=None)
    assert len(unresolved_ips) >= len(MOCK_UNRESOLVED)

    ur_1 = next((ip for ip in unresolved_ips if ip["ip"] == "198.51.100.10"), None)
    assert ur_1 is not None
    assert ur_1["hits"] == 12

    ur_2 = next((ip for ip in unresolved_ips if ip["ip"] == "203.0.113.5"), None)
    assert ur_2 is not None
    assert ur_2["hits"] == 8
