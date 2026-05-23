"""ClickHouse-backed analytics for the dashboard.

Endpoints are designed to degrade gracefully:
- if ClickHouse is unreachable or the tables/columns don't exist, return
  empty / zeroed payloads instead of raising 500
- a single missing column (e.g. ``host`` before the ALTER lands) should
  not break the whole panel
"""

import logging
import os
import threading
import time
from collections.abc import Iterable
from typing import Any

from clickhouse_driver import Client as ClickHouseClient
from clickhouse_driver.errors import Error as ClickHouseError

logger = logging.getLogger(__name__)

_NO_DOMAINS_SENTINEL = "__none__"


# ClickHouse connection parameters — resolved once from env vars.
# _get_client() creates a fresh Client per call so concurrent threads never
# share a connection. clickhouse-driver raises PartiallyConsumedQueryError
# when two threads call execute() on the same Client simultaneously.
# The 30 s TTL cache (below) means most calls return before reaching execute(),
# so the per-call connect cost is negligible in practice.
def _get_client() -> ClickHouseClient:
    """Return a fresh ClickHouse client (thread-safe by construction)."""
    http_endpoint = os.getenv("CLICKHOUSE_ENDPOINT", "http://clickhouse:8123")
    if "://" in http_endpoint:
        http_endpoint = http_endpoint.split("://", 1)[1]
    host = http_endpoint.rsplit(":", 1)[0] if ":" in http_endpoint else http_endpoint
    return ClickHouseClient(
        host=host,
        port=int(os.getenv("CLICKHOUSE_NATIVE_PORT", "9000")),
        user=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DB", "logs"),
        connect_timeout=5,
        send_receive_timeout=30,
    )


# Small in-process TTL cache for ClickHouse query results. The dashboard
# polls every 15s * 19 panels — without this, every poll hits ClickHouse
# from scratch and the heaviest queries (joins, ARRAY JOINs over the full
# audit log) drove the container to 30+ cores.
_QUERY_TTL_S = float(os.getenv("DASHBOARD_QUERY_TTL", "30"))
_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, Any]] = {}


def _direct_execute(client: ClickHouseClient, query: str, default: Any = None) -> Any:
    """Run *query* WITHOUT the TTL cache.

    Used by the test-traffic endpoint — we never want a stale cached result
    for a freshly-fired marker, otherwise the chart appears empty when the
    audit row has actually landed.
    """
    try:
        return client.execute(query)
    except ClickHouseError as exc:
        logger.warning("ClickHouse query failed (%s): %s", exc.__class__.__name__, query)
        return default
    except Exception:
        logger.exception("Unexpected error executing ClickHouse query: %s", query)
        return default


def _safe_execute(client: ClickHouseClient, query: str, default: Any = None) -> Any:
    """Run *query* with a short TTL cache and swallow ClickHouse errors."""
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(query)
        if hit is not None and now - hit[0] < _QUERY_TTL_S:
            return hit[1]
    try:
        result = client.execute(query)
    except ClickHouseError as exc:
        logger.warning("ClickHouse query failed (%s): %s", exc.__class__.__name__, query)
        return default
    except Exception:
        logger.exception("Unexpected error executing ClickHouse query: %s", query)
        return default

    with _cache_lock:
        _cache[query] = (now, result)
        # Evict expired entries opportunistically to keep the dict small.
        if len(_cache) > 256:
            cutoff = now - _QUERY_TTL_S
            for k in [k for k, (ts, _) in _cache.items() if ts < cutoff]:
                _cache.pop(k, None)
    return result


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

    # Faster alternative to ANY LEFT JOIN: filter nginx_access_log to only
    # the attacker IPs seen in the WAF log (small set), then join.
    # The original ANY LEFT JOIN scanned all 600K+ nginx rows; this IN-subquery
    # lets ClickHouse prune the scan to just matching IPs.
    rows = _safe_execute(
        client,
        "SELECT any(n.geoip_country_code) AS country_code, count() AS cnt "
        "FROM logs.waf_audit_log AS w "
        "INNER JOIN ("
        "  SELECT toString(remote_addr) AS ip, any(geoip_country_code) AS geoip_country_code "
        "  FROM logs.nginx_access_log "
        f"  WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
        "  AND toString(remote_addr) IN ("
        "    SELECT DISTINCT toString(client_ip) FROM logs.waf_audit_log "
        f"   WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter}"
        "  ) GROUP BY ip"
        ") AS n ON toString(w.client_ip) = n.ip "
        f"WHERE w.timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
        "GROUP BY country_code "
        "ORDER BY cnt DESC "
        "LIMIT 10",
        default=None,
    )
    if rows is None:
        rows = [("UNKNOWN", total_blocks)]

    result = []
    for country_code, cnt in rows or []:
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


def get_geoip_unresolved_ips(
    hours: float = 24,
    connection_id: int | None = None,
) -> list[dict[str, Any]]:
    """Return non-private client IPs that failed GeoIP enrichment.

    Excludes loopback / RFC 1918 / link-local — those are expected to lack
    GeoIP. What remains is IPs that LOOK external but have no coordinates,
    typically RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24), CGNAT (100.64.0.0/10), or real public IPs missing from
    the MaxMind DB.
    """
    try:
        client = _get_client()
    except Exception:
        return []

    minutes = _clamp_minutes(hours)
    domains = _domains_for_connection(connection_id)
    nginx_filter = _host_filter_nginx(domains)

    # remote_addr is typed as IPv4 in ClickHouse — cast directly to UInt32
    # for numeric range comparisons against RFC ranges.
    rows = (
        _safe_execute(
            client,
            "SELECT IPv4NumToString(remote_addr) AS ip, count() AS cnt "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            "AND toUInt32(remote_addr) != 0 "
            "AND (geoip_country_code = '' OR geoip_latitude = 0 OR geoip_longitude = 0) "
            # Exclude loopback 127.0.0.0/8
            "AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('127.0.0.0')) AND toUInt32(toIPv4('127.255.255.255'))) "
            # Exclude RFC 1918 10.0.0.0/8
            "AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('10.0.0.0')) AND toUInt32(toIPv4('10.255.255.255'))) "
            # Exclude RFC 1918 172.16.0.0/12
            "AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('172.16.0.0')) AND toUInt32(toIPv4('172.31.255.255'))) "
            # Exclude RFC 1918 192.168.0.0/16
            "AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('192.168.0.0')) AND toUInt32(toIPv4('192.168.255.255'))) "
            # Exclude link-local 169.254.0.0/16
            "AND NOT (toUInt32(remote_addr) BETWEEN toUInt32(toIPv4('169.254.0.0')) AND toUInt32(toIPv4('169.254.255.255'))) "
            f"{nginx_filter} "
            "GROUP BY remote_addr "
            "ORDER BY cnt DESC "
            "LIMIT 30",
            default=[],
        )
        or []
    )

    return [{"ip": str(ip), "hits": int(cnt)} for ip, cnt in rows]


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


# ── Extended analytics panels ───────────────────────────────────────


_SEVERITY_NAMES = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG",
}


def get_waf_events_timeline(
    hours: float = 24, connection_id: int | None = None
) -> list[dict[str, Any]]:
    """WAF audit events bucketed per minute."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT toStartOfMinute(timestamp) AS t, count() AS hits "
            "FROM logs.waf_audit_log "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            "GROUP BY t ORDER BY t",
            default=[],
        )
        or []
    )
    return [{"timestamp": t.isoformat(), "hits": int(hits)} for t, hits in rows]


def get_top_rules(
    hours: float = 24, connection_id: int | None = None, limit: int = 10
) -> list[dict[str, Any]]:
    """Top WAF rules by trigger count."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT m.ruleId AS rule, count() AS hits FROM logs.waf_audit_log "
            "ARRAY JOIN messages AS m "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            f"GROUP BY rule ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"rule": str(rule or "unknown"), "hits": int(hits)} for rule, hits in rows]


def get_severity_distribution(
    hours: float = 24, connection_id: int | None = None
) -> list[dict[str, Any]]:
    """Severity-level counts across WAF messages."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT m.severity AS sev, count() AS hits FROM logs.waf_audit_log "
            "ARRAY JOIN messages AS m "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            "GROUP BY sev ORDER BY sev",
            default=[],
        )
        or []
    )
    return [
        {"severity": _SEVERITY_NAMES.get(int(sev), str(sev)), "hits": int(hits)}
        for sev, hits in rows
    ]


def get_top_attacking_ips(
    hours: float = 24, connection_id: int | None = None, limit: int = 15
) -> list[dict[str, Any]]:
    """Top attacking IPs (WAF audit log)."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT client_ip, count() AS hits FROM logs.waf_audit_log "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            f"GROUP BY client_ip ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"ip": str(ip or "0.0.0.0"), "hits": int(hits)} for ip, hits in rows]


def get_anomaly_score_timeline(
    hours: float = 24, connection_id: int | None = None
) -> list[dict[str, Any]]:
    """Max anomaly score per minute."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT toStartOfMinute(timestamp) AS t, max(anomaly_score) AS score "
            "FROM logs.waf_audit_log "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            "GROUP BY t ORDER BY t",
            default=[],
        )
        or []
    )
    return [{"timestamp": t.isoformat(), "score": int(score)} for t, score in rows]


def get_top_tags(
    hours: float = 24, connection_id: int | None = None, limit: int = 10
) -> list[dict[str, Any]]:
    """Top WAF tags."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT tag, count() AS hits FROM logs.waf_audit_log "
            "ARRAY JOIN messages_tags AS tags ARRAY JOIN tags AS tag "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            f"GROUP BY tag ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"tag": str(tag), "hits": int(hits)} for tag, hits in rows]


def get_top_uris(
    hours: float = 24, connection_id: int | None = None, limit: int = 10
) -> list[dict[str, Any]]:
    """Top blocked URIs from WAF audit log."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT request_uri AS uri, count() AS hits FROM logs.waf_audit_log "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            f"GROUP BY uri ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"uri": str(uri or "/"), "hits": int(hits)} for uri, hits in rows]


def get_top_rule_files(
    hours: float = 24, connection_id: int | None = None, limit: int = 10
) -> list[dict[str, Any]]:
    """Top rule files involved in WAF events."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    waf_filter = _host_filter_waf(_domains_for_connection(connection_id))
    rows = (
        _safe_execute(
            client,
            "SELECT replaceRegexpOne(replaceRegexpOne(m.file, '\\.conf$', ''), '^.*/', '') AS rf, "
            "count() AS hits FROM logs.waf_audit_log "
            "ARRAY JOIN messages AS m "
            f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE{waf_filter} "
            f"GROUP BY rf ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"file": str(rf or "unknown"), "hits": int(hits)} for rf, hits in rows]


def get_status_codes_timeline(
    hours: float = 24, connection_id: int | None = None
) -> list[dict[str, Any]]:
    """HTTP status-code distribution per minute (nginx access log)."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    rows = (
        _safe_execute(
            client,
            "SELECT toStartOfMinute(time_local) AS t, "
            "countIf(status >= 200 AND status < 300) AS c2xx, "
            "countIf(status >= 300 AND status < 400) AS c3xx, "
            "countIf(status >= 400 AND status < 500) AS c4xx, "
            "countIf(status >= 500) AS c5xx "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            "GROUP BY t ORDER BY t",
            default=[],
        )
        or []
    )
    return [
        {
            "timestamp": t.isoformat(),
            "c2xx": int(a),
            "c3xx": int(b),
            "c4xx": int(c),
            "c5xx": int(d),
        }
        for t, a, b, c, d in rows
    ]


def get_top_user_agents(
    hours: float = 24, connection_id: int | None = None, limit: int = 15
) -> list[dict[str, Any]]:
    """Top user-agents (nginx access log)."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    rows = (
        _safe_execute(
            client,
            "SELECT http_user_agent AS ua, count() AS hits "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            f"GROUP BY ua ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"user_agent": str(ua or "-"), "hits": int(hits)} for ua, hits in rows]


def get_traffic_volume(hours: float = 24, connection_id: int | None = None) -> list[dict[str, Any]]:
    """Bytes sent per minute (nginx access log)."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    rows = (
        _safe_execute(
            client,
            "SELECT toStartOfMinute(time_local) AS t, sum(body_bytes_sent) AS bytes "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            "GROUP BY t ORDER BY t",
            default=[],
        )
        or []
    )
    return [{"timestamp": t.isoformat(), "bytes": int(b or 0)} for t, b in rows]


def get_requests_per_second(
    hours: float = 24, connection_id: int | None = None
) -> list[dict[str, Any]]:
    """Requests per second derived from per-minute counts."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    rows = (
        _safe_execute(
            client,
            "SELECT toStartOfMinute(time_local) AS t, count() / 60.0 AS rps "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            "GROUP BY t ORDER BY t",
            default=[],
        )
        or []
    )
    return [{"timestamp": t.isoformat(), "rps": float(rps)} for t, rps in rows]


def get_requests_by_country(
    hours: float = 24, connection_id: int | None = None, limit: int = 15
) -> list[dict[str, Any]]:
    """Top countries by request count (nginx access log)."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    rows = (
        _safe_execute(
            client,
            "SELECT if(geoip_country_code = '' OR geoip_country_code IS NULL, 'Unknown', geoip_country_code) "
            "AS country, count() AS hits FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            f"GROUP BY country ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"country_code": str(c), "hits": int(hits)} for c, hits in rows]


# ── Test-traffic endpoint (Tests tab) ──────────────────────────────


# Marker header is the contract with the Tests runner (backend/src/tests/service.py).
# Kept in sync via a string constant — if you rename it, update both places.
_TEST_MARKER_HEADER = "X-Test-Marker"


def get_test_traffic_by_marker(marker: str) -> dict[str, Any]:
    """Return the WAF audit rows tagged with this X-Test-Marker.

    The caller (router) MUST validate ``marker`` as a UUID4 before calling
    this — we still single-quote-strip defensively, but the regex check at
    the router layer is the actual SQL-injection barrier.

    Returns ``{"events": [...], "timestamps": [...]}`` — the timestamp list
    is what the frontend chart consumes to draw spike highlight markers.
    """
    try:
        client = _get_client()
    except Exception:
        return {"events": [], "timestamps": []}

    safe_marker = marker.replace("'", "").replace("\\", "").replace("\x00", "")

    query = (
        "SELECT w.timestamp, m.ruleId, w.client_ip, w.request_uri, "
        "w.request_method, m.severity, m.message, w.anomaly_score "
        "FROM logs.waf_audit_log AS w "
        "LEFT ARRAY JOIN messages AS m "
        f"WHERE w.request_headers['{_TEST_MARKER_HEADER}'] = '{safe_marker}' "
        "AND w.timestamp >= now() - INTERVAL 1 HOUR "
        "ORDER BY w.timestamp"
    )
    rows = _direct_execute(client, query, default=[]) or []

    severity_labels = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

    events: list[dict[str, Any]] = []
    timestamps: list[str] = []
    seen_ts: set[str] = set()
    for ts, rule_id, client_ip, uri, method, sev, msg, score in rows:
        iso = ts.isoformat()
        events.append(
            {
                "timestamp": iso,
                "rule_id": rule_id or "unknown",
                "client_ip": client_ip or "0.0.0.0",
                "uri": uri or "",
                "method": method or "",
                "severity": severity_labels.get(int(sev or 0), "info"),
                "message": msg or "",
                "anomaly_score": int(score or 0),
            }
        )
        if iso not in seen_ts:
            seen_ts.add(iso)
            timestamps.append(iso)

    return {"events": events, "timestamps": timestamps}


def get_top_client_ips(
    hours: float = 24, connection_id: int | None = None, limit: int = 15
) -> list[dict[str, Any]]:
    """Top client IPs from nginx access log."""
    try:
        client = _get_client()
    except Exception:
        return []
    minutes = _clamp_minutes(hours)
    rows = (
        _safe_execute(
            client,
            "SELECT toString(remote_addr) AS ip, count() AS hits "
            "FROM logs.nginx_access_log "
            f"WHERE time_local >= now() - INTERVAL {minutes} MINUTE "
            f"GROUP BY ip ORDER BY hits DESC LIMIT {int(limit)}",
            default=[],
        )
        or []
    )
    return [{"ip": str(ip or "0.0.0.0"), "hits": int(hits)} for ip, hits in rows]
