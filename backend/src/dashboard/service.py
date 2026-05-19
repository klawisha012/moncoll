"""ClickHouse-backed analytics for the dashboard.

Endpoints are designed to degrade gracefully:
- if ClickHouse is unreachable or the tables/columns don't exist, return
  empty / zeroed payloads instead of raising 500
- a single missing column (e.g. ``host`` before the ALTER lands) should
  not break the whole panel
"""

import logging
import os
from collections.abc import Iterable
from typing import Any

from clickhouse_driver import Client as ClickHouseClient
from clickhouse_driver.errors import Error as ClickHouseError

logger = logging.getLogger(__name__)

_NO_DOMAINS_SENTINEL = "__none__"


def _get_client() -> ClickHouseClient:
    """Create a ClickHouse client using the native TCP protocol (port 9000)."""
    http_endpoint = os.getenv("CLICKHOUSE_ENDPOINT", "http://clickhouse:8123")
    if "://" in http_endpoint:
        http_endpoint = http_endpoint.split("://", 1)[1]
    host = http_endpoint.rsplit(":", 1)[0] if ":" in http_endpoint else http_endpoint
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


def _safe_execute(client: ClickHouseClient, query: str, default: Any = None) -> Any:
    """Run *query* and swallow ClickHouse errors, returning *default* on failure.

    Without this, a missing table during initial bring-up (or an extension
    column added by a newer migration) takes the whole dashboard down with
    a 500.
    """
    try:
        return client.execute(query)
    except ClickHouseError as exc:
        logger.warning("ClickHouse query failed (%s): %s", exc.__class__.__name__, query)
        return default
    except Exception:
        logger.exception("Unexpected error executing ClickHouse query: %s", query)
        return default


def _scalar(rows: Any, default: int = 0) -> int:
    if not rows:
        return default
    try:
        return int(rows[0][0])
    except (IndexError, TypeError, ValueError):
        return default


def _clamp_minutes(hours: float) -> int:
    hours = max(0.0167, min(hours, 8760))
    return max(1, int(hours * 60))


def _domains_for_connection(connection_id: int | None) -> list[str]:
    """Look up enabled domains for a connection.

    Imported lazily to avoid a circular import between dashboard <-> db.
    Returns an empty list if the connection cannot be loaded.
    """
    if connection_id is None:
        return []
    try:
        from sqlalchemy import create_engine, select

        from ..db.models import Connection as ConnectionModel
    except Exception:
        return []

    try:
        db_url = os.getenv("DATABASE_URL", "")
        if not db_url:
            return []
        sync_url = db_url.replace("+asyncpg", "").replace("+aiosqlite", "")
        engine = create_engine(sync_url, future=True)
        with engine.connect() as conn:
            row = conn.execute(
                select(ConnectionModel).where(ConnectionModel.id == connection_id)
            ).first()
        engine.dispose()
        if not row:
            return []
        domains = row[0].domains if hasattr(row[0], "domains") else []
        return [str(d) for d in (domains or [])]
    except Exception:
        logger.exception("Failed to load connection %s for dashboard filter", connection_id)
        return []


def _quote_domains(domains: Iterable[str]) -> str:
    """Render an SQL IN-list, stripping anything that could break ClickHouse string parsing.

    Strips single quotes, backslashes (escape introducer), and NUL bytes.
    Domains come from the admin-controlled ``connections.domains`` JSON
    column, but a stray ``\\`` in a saved domain would still corrupt the
    query — strip defensively here rather than trust the upstream.
    """
    cleaned = [d.replace("'", "").replace("\\", "").replace("\x00", "") for d in domains if d]
    if not cleaned:
        return f"('{_NO_DOMAINS_SENTINEL}')"
    return "(" + ", ".join(f"'{d}'" for d in cleaned) + ")"


def _host_filter_nginx(domains: list[str]) -> str:
    if not domains:
        return ""
    return f" AND host IN {_quote_domains(domains)}"


def _host_filter_waf(domains: list[str]) -> str:
    if not domains:
        return ""
    return f" AND request_headers['Host'] IN {_quote_domains(domains)}"


# ── Public API ──────────────────────────────────────────────────────


def get_dashboard_metrics(hours: float = 24, connection_id: int | None = None) -> dict[str, Any]:
    """Fetch summary metrics for the dashboard stat cards."""
    try:
        client = _get_client()
    except Exception:
        logger.exception("ClickHouse client unavailable")
        return _empty_metrics()

    minutes = _clamp_minutes(hours)
    prev_minutes = max(1, minutes * 2)
    domains = _domains_for_connection(connection_id)
    nginx_filter = _host_filter_nginx(domains)
    waf_filter = _host_filter_waf(domains)

    total_requests = _scalar(
        _safe_execute(
            client,
            "SELECT count() FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE{nginx_filter}",
        )
    )
    prev_total = _scalar(
        _safe_execute(
            client,
            "SELECT count() FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {prev_minutes} MINUTE "
            f"AND time_local < now() - INTERVAL {minutes} MINUTE{nginx_filter}",
        )
    )

    total_requests_change = 0.0
    if prev_total > 0:
        total_requests_change = round(((total_requests - prev_total) / prev_total) * 100, 1)

    blocked_threats = _scalar(
        _safe_execute(
            client,
            "SELECT count() FROM logs.waf_audit_log "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter}",
        )
    )
    high_severity = _scalar(
        _safe_execute(
            client,
            "SELECT count() FROM logs.waf_audit_log "
            "ARRAY JOIN messages AS m "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE "
            f"AND m.severity >= 2{waf_filter}",
        )
    )
    active_rules = _scalar(
        _safe_execute(
            client,
            "SELECT count(DISTINCT m.ruleId) FROM logs.waf_audit_log "
            "ARRAY JOIN messages AS m "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter}",
        )
    )

    total_responses = total_requests
    error_responses = _scalar(
        _safe_execute(
            client,
            "SELECT count() FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            f"AND status >= 500{nginx_filter}",
        )
    )

    system_health = 100.0
    if total_responses > 0:
        system_health = round(((total_responses - error_responses) / total_responses) * 100, 1)

    return {
        "total_requests": total_requests,
        "total_requests_change": total_requests_change,
        "blocked_threats": blocked_threats,
        "high_severity_count": high_severity,
        "system_health": system_health,
        "avg_latency_ms": 0.0,
        "active_rules": active_rules,
    }


def _empty_metrics() -> dict[str, Any]:
    return {
        "total_requests": 0,
        "total_requests_change": 0.0,
        "blocked_threats": 0,
        "high_severity_count": 0,
        "system_health": 100.0,
        "avg_latency_ms": 0.0,
        "active_rules": 0,
    }


def get_traffic_data(hours: float = 24, connection_id: int | None = None) -> list[dict[str, Any]]:
    """Get traffic data points aggregated by hour."""
    try:
        client = _get_client()
    except Exception:
        return []

    minutes = _clamp_minutes(hours)
    domains = _domains_for_connection(connection_id)
    nginx_filter = _host_filter_nginx(domains)
    waf_filter = _host_filter_waf(domains)

    rows = (
        _safe_execute(
            client,
            "SELECT toStartOfHour(time_local) AS hour, count() AS total "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE{nginx_filter} "
            "GROUP BY hour ORDER BY hour",
            default=[],
        )
        or []
    )
    malicious_rows = (
        _safe_execute(
            client,
            "SELECT toStartOfHour(timestamp) AS hour, count() AS total "
            "FROM logs.waf_audit_log "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            "GROUP BY hour ORDER BY hour",
            default=[],
        )
        or []
    )
    malicious_map = {row[0]: row[1] for row in malicious_rows}

    result = []
    for hour, total in rows:
        malicious = malicious_map.get(hour, 0)
        clean = max(total - malicious, 0)
        result.append({"timestamp": hour.isoformat(), "clean": clean, "malicious": malicious})
    return result


def get_threat_origins(hours: float = 24, connection_id: int | None = None) -> list[dict[str, Any]]:
    """Get threat origin distribution by country from WAF logs.

    Always returns a JSON-serialisable list (possibly empty) — never 500s.
    """
    try:
        client = _get_client()
    except Exception:
        return []

    minutes = _clamp_minutes(hours)
    domains = _domains_for_connection(connection_id)
    waf_filter = _host_filter_waf(domains)

    total_blocks = _scalar(
        _safe_execute(
            client,
            "SELECT count() FROM logs.waf_audit_log "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter}",
        )
    )
    if total_blocks == 0:
        return []

    rows = _safe_execute(
        client,
        "SELECT a.geoip_country_code AS country_code, count() AS cnt "
        "FROM logs.waf_audit_log AS w "
        "INNER JOIN logs.nginx_access_log AS a "
        "ON toString(w.client_ip) = toString(a.remote_addr) "
        f"WHERE w.timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
        "GROUP BY country_code "
        "ORDER BY cnt DESC "
        "LIMIT 10",
        default=None,
    )
    if rows is None:
        # JOIN failed (e.g. IP type mismatch) — fall back to a single bucket.
        rows = [("UNKNOWN", total_blocks)]

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


def get_geoip_map_data(hours: float = 24, connection_id: int | None = None) -> list[dict[str, Any]]:
    """Get GeoIP coordinates with hit counts for world map visualization."""
    try:
        client = _get_client()
    except Exception:
        return []

    minutes = _clamp_minutes(hours)
    domains = _domains_for_connection(connection_id)
    nginx_filter = _host_filter_nginx(domains)

    rows = (
        _safe_execute(
            client,
            "SELECT geoip_longitude, geoip_latitude, geoip_country_code, "
            "geoip_city_name, count() AS cnt "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            f"AND geoip_latitude != 0 AND geoip_longitude != 0 "
            f"AND geoip_country_code != ''{nginx_filter} "
            "GROUP BY geoip_longitude, geoip_latitude, geoip_country_code, geoip_city_name "
            "ORDER BY cnt DESC "
            "LIMIT 500",
            default=[],
        )
        or []
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


def get_security_events(
    limit: int = 50,
    severity: str = "all",
    hours: float = 24,
    connection_id: int | None = None,
) -> list[dict[str, Any]]:
    """Get recent security events from WAF audit logs."""
    try:
        client = _get_client()
    except Exception:
        return []

    minutes = _clamp_minutes(hours)
    domains = _domains_for_connection(connection_id)
    waf_filter = _host_filter_waf(domains)

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
        f"WHERE w.timestamp >= now() - INTERVAL {minutes} MINUTE "
        f"{severity_filter}{waf_filter} "
        "ORDER BY w.timestamp DESC "
        f"LIMIT {int(limit)}"
    )

    rows = _safe_execute(client, query, default=[]) or []

    severity_labels = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

    result = []
    for ts, rule_id, client_ip, sev, uri, _msg in rows:
        result.append(
            {
                "timestamp": ts.isoformat(),
                "type": rule_id or "unknown",
                "ip": client_ip or "0.0.0.0",
                "country": "",
                "path": uri or "",
                "severity": severity_labels.get(sev, "info"),
            }
        )
    return result
