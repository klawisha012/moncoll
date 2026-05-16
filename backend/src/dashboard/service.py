import os
from typing import Any

from clickhouse_driver import Client as ClickHouseClient


def _get_client() -> ClickHouseClient:
    """Create a ClickHouse client using the native TCP protocol (port 9000)."""
    # CLICKHOUSE_ENDPOINT is the HTTP endpoint (e.g. http://clickhouse:8123).
    # clickhouse_driver uses the native protocol — default to port 9000 on the same host.
    http_endpoint = os.getenv("CLICKHOUSE_ENDPOINT", "http://clickhouse:8123")
    # Strip protocol prefix if present
    if "://" in http_endpoint:
        http_endpoint = http_endpoint.split("://", 1)[1]
    # Extract hostname (drop HTTP port if present)
    host = http_endpoint.rsplit(":", 1)[0] if ":" in http_endpoint else http_endpoint

    # Native TCP protocol port (may be overridden via CLICKHOUSE_NATIVE_PORT)
    native_port = int(os.getenv("CLICKHOUSE_NATIVE_PORT", "9000"))

    return ClickHouseClient(
        host=host,
        port=native_port,
        user=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DB", "logs"),
        connect_timeout=5,
        send_receive_timeout=10,
    )


def get_dashboard_metrics(hours: int = 24) -> dict[str, Any]:
    """Fetch summary metrics for the dashboard stat cards.

    Args:
        hours: Time window in hours for metric aggregation (default: 24).
    """
    client = _get_client()
    hours = max(1, min(hours, 8760))  # clamp between 1 hour and 1 year

    # Total requests (last N hours from nginx access log)
    total_requests = client.execute(
        f"SELECT count() FROM logs.nginx_access_log "
        f"WHERE time_local >= now() - INTERVAL {hours} HOUR"
    )[0][0]

    # Previous period for change calculation
    prev_total = client.execute(
        f"SELECT count() FROM logs.nginx_access_log "
        f"WHERE time_local >= now() - INTERVAL {hours * 2} HOUR "
        f"AND time_local < now() - INTERVAL {hours} HOUR"
    )[0][0]

    total_requests_change = 0.0
    if prev_total > 0:
        total_requests_change = round(
            ((total_requests - prev_total) / prev_total) * 100, 1
        )

    # Blocked threats (WAF events with anomaly_score > 0)
    blocked_threats = client.execute(
        f"SELECT count() FROM logs.waf_audit_log "
        f"WHERE timestamp >= now() - INTERVAL {hours} HOUR"
    )[0][0]

    # High severity count (severity >= 2 in messages)
    high_severity = client.execute(
        f"SELECT count() FROM logs.waf_audit_log "
        f"ARRAY JOIN messages AS m "
        f"WHERE timestamp >= now() - INTERVAL {hours} HOUR "
        f"AND m.severity >= 2"
    )[0][0]

    # Active rules (distinct ruleIds triggered in last N hours)
    active_rules_result = client.execute(
        f"SELECT count(DISTINCT m.ruleId) FROM logs.waf_audit_log "
        f"ARRAY JOIN messages AS m "
        f"WHERE timestamp >= now() - INTERVAL {hours} HOUR"
    )
    active_rules = active_rules_result[0][0] if active_rules_result else 0

    # System health: percentage of non-5xx responses in the time window
    total_responses = client.execute(
        f"SELECT count() FROM logs.nginx_access_log "
        f"WHERE time_local >= now() - INTERVAL {hours} HOUR"
    )[0][0]

    error_responses = client.execute(
        f"SELECT count() FROM logs.nginx_access_log "
        f"WHERE time_local >= now() - INTERVAL {hours} HOUR "
        f"AND status >= 500"
    )[0][0]

    system_health = 100.0
    if total_responses > 0:
        system_health = round(
            ((total_responses - error_responses) / total_responses) * 100, 1
        )

    # Average latency — not directly stored in current schema.
    # Return 0 as placeholder until request_time is added to the access log schema.
    avg_latency_ms = 0.0

    return {
        "total_requests": total_requests,
        "total_requests_change": total_requests_change,
        "blocked_threats": blocked_threats,
        "high_severity_count": high_severity,
        "system_health": system_health,
        "avg_latency_ms": avg_latency_ms,
        "active_rules": active_rules,
    }


def get_traffic_data(hours: int = 24) -> list[dict[str, Any]]:
    """Get traffic data points for the last N hours, aggregated by hour.

    Args:
        hours: Time window in hours for metric aggregation (default: 24).
    """
    client = _get_client()
    hours = max(1, min(hours, 8760))  # clamp between 1 hour and 1 year

    # Total traffic per hour
    rows = client.execute(
        f"SELECT toStartOfHour(time_local) AS hour, count() AS total "
        f"FROM logs.nginx_access_log "
        f"WHERE time_local >= now() - INTERVAL {hours} HOUR "
        f"GROUP BY hour ORDER BY hour"
    )

    # Malicious traffic per hour (from WAF logs)
    malicious_rows = client.execute(
        f"SELECT toStartOfHour(timestamp) AS hour, count() AS total "
        f"FROM logs.waf_audit_log "
        f"WHERE timestamp >= now() - INTERVAL {hours} HOUR "
        f"GROUP BY hour ORDER BY hour"
    )
    malicious_map = {row[0]: row[1] for row in malicious_rows}

    result = []
    for hour, total in rows:
        malicious = malicious_map.get(hour, 0)
        clean = max(total - malicious, 0)
        result.append(
            {
                "timestamp": hour.isoformat(),
                "clean": clean,
                "malicious": malicious,
            }
        )
    return result


def get_threat_origins() -> list[dict[str, Any]]:
    """Get threat origin distribution by country from WAF logs."""
    client = _get_client()

    total_blocks = client.execute(
        "SELECT count() FROM logs.waf_audit_log "
        "WHERE timestamp >= now() - INTERVAL 24 HOUR"
    )[0][0]

    if total_blocks == 0:
        return []

    rows = client.execute(
        "SELECT a.geoip_country_code AS country_code, count() AS cnt "
        "FROM logs.waf_audit_log AS w "
        "INNER JOIN logs.nginx_access_log AS a "
        "ON w.client_ip = a.remote_addr "
        "WHERE w.timestamp >= now() - INTERVAL 24 HOUR "
        "GROUP BY country_code "
        "ORDER BY cnt DESC "
        "LIMIT 10"
    )

    result = []
    for country_code, cnt in rows:
        if not country_code:
            country_code = "UNKNOWN"
        result.append(
            {
                "country": country_code,
                "country_code": country_code,
                "blocks_percent": round((cnt / total_blocks) * 100, 1),
            }
        )
    return result


def get_geoip_map_data(hours: int = 24) -> list[dict[str, Any]]:
    """Get GeoIP coordinates with hit counts for world map visualization.

    Args:
        hours: Time window in hours (default: 24).
    """
    client = _get_client()
    hours = max(1, min(hours, 8760))

    rows = client.execute(
        f"SELECT geoip_longitude, geoip_latitude, geoip_country_code, "
        f"geoip_city_name, count() AS cnt "
        f"FROM logs.nginx_access_log "
        f"WHERE time_local >= now() - INTERVAL {hours} HOUR "
        f"AND geoip_latitude != 0 AND geoip_longitude != 0 "
        f"AND geoip_country_code != '' "
        f"GROUP BY geoip_longitude, geoip_latitude, geoip_country_code, geoip_city_name "
        f"ORDER BY cnt DESC "
        f"LIMIT 500"
    )

    result = []
    for lng, lat, country_code, city_name, cnt in rows:
        result.append(
            {
                "longitude": float(lng),
                "latitude": float(lat),
                "country_code": country_code or "UNKNOWN",
                "city_name": city_name or "",
                "hits": int(cnt),
            }
        )
    return result


def get_security_events(limit: int = 50, severity: str = "all") -> list[dict[str, Any]]:
    """Get recent security events from WAF audit logs."""
    client = _get_client()

    severity_filter = ""
    if severity == "high":
        severity_filter = "AND m.severity >= 2"
    elif severity == "critical":
        severity_filter = "AND m.severity >= 3"

    query = (
        "SELECT w.timestamp, m.ruleId, w.client_ip, m.severity, "
        "w.request_uri, m.message "
        "FROM logs.waf_audit_log AS w "
        "ARRAY JOIN messages AS m "
        "WHERE w.timestamp >= now() - INTERVAL 24 HOUR "
        f"{severity_filter} "
        "ORDER BY w.timestamp DESC "
        f"LIMIT {int(limit)}"
    )

    rows = client.execute(query)

    severity_labels = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

    result = []
    for ts, rule_id, client_ip, sev, uri, _msg in rows:
        result.append(
            {
                "timestamp": ts.isoformat(),
                "type": rule_id or "unknown",
                "ip": client_ip or "0.0.0.0",
                "country": "",  # Not joined here for performance
                "path": uri or "",
                "severity": severity_labels.get(sev, "info"),
            }
        )
    return result
