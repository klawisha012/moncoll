"""Dashboard analytics router.

Tenant scoping (Phase 5.2.c):
- Logged-in clients (platform_role == "client") have a tenant_id and only see
  data filtered to their own connections.  When a connection_id is supplied the
  Postgres lookup adds a ``WHERE tenant_id = <id>`` guard so they cannot view
  another tenant's traffic by guessing an ID.
- Admins (platform_role == "admin") have no tenant_id (None) — the service
  layer receives tenant_id=None and returns platform-wide data.

TODO (Phase 13): ClickHouse ``nginx_access_log`` / ``waf_audit_log`` do not
have a ``tenant_id`` column.  Adding it requires extending migration 0006 and
is deferred to a follow-up spec.  The current scoping enforces isolation at the
domain-list level: a wrong-tenant connection lookup returns an empty domain
list, making all ClickHouse filters match nothing.
"""

import asyncio
import functools
import re

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from ..auth.dependencies import require_verified
from ..db.models import User
from .service import (
    get_anomaly_score_timeline,
    get_dashboard_metrics,
    get_geoip_map_data,
    get_geoip_unresolved_ips,
    get_requests_by_country,
    get_requests_per_second,
    get_security_events,
    get_severity_distribution,
    get_status_codes_timeline,
    get_test_traffic_by_marker,
    get_threat_origins,
    get_top_attacking_ips,
    get_top_client_ips,
    get_top_rule_files,
    get_top_rules,
    get_top_tags,
    get_top_uris,
    get_top_user_agents,
    get_traffic_data,
    get_traffic_volume,
    get_waf_events_timeline,
)

# Strict UUID4 regex. We accept the path param ONLY when it matches this
# pattern — anything else (incl. random ASCII, SQL fragments, etc.) returns
# 400 BEFORE the ClickHouse query is built. See design doc decision 6A.
#
# `\Z` (not `$`) is used at the end on purpose — `$` in Python regex would
# accept a trailing newline, which would let `<uuid>\n; DROP …` slip through.
_UUID4_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_HOURS = Query(
    24,
    ge=0.0167,
    le=8760,
    description="Time window in hours (supports fractional, e.g. 0.0167 = 1 min)",
)
_CONNECTION_ID = Query(
    None,
    ge=1,
    description="Scope to a single connection's domains (defaults to all)",
)


async def _run(fn):
    """Run a zero-argument callable in the thread pool.

    All callers use ``functools.partial`` to pre-bind args, which lets us
    pass keyword arguments (e.g. ``tenant_id``) that ``run_in_executor``
    cannot forward on its own.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn)


_U = Depends(require_verified)


@router.get("/metrics")
async def metrics(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
    user: User = _U,
):
    """Return summary metrics for the dashboard stat cards."""
    try:
        return await _run(
            functools.partial(get_dashboard_metrics, hours, connection_id, user.tenant_id)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/traffic")
async def traffic(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
    user: User = _U,
):
    """Return traffic data points (clean vs malicious) for charts."""
    try:
        return await _run(
            functools.partial(get_traffic_data, hours, connection_id, user.tenant_id)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip-map")
async def geoip_map(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
    user: User = _U,
):
    """Return GeoIP coordinates with hit counts for world map visualization."""
    try:
        return await _run(
            functools.partial(get_geoip_map_data, hours, connection_id, user.tenant_id)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip-unresolved")
async def geoip_unresolved(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
    user: User = _U,
):
    """Return external-looking client IPs that lack GeoIP enrichment.

    Useful to explain why the world map is empty when public-looking IPs
    appear elsewhere in the dashboard (e.g. RFC 5737 documentation ranges,
    CGNAT, or addresses missing from the MaxMind database).
    """
    try:
        return await _run(
            functools.partial(get_geoip_unresolved_ips, hours, connection_id, user.tenant_id)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/threat-origins")
async def threat_origins(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
    user: User = _U,
):
    """Return threat origin distribution by country."""
    return await _run(
        functools.partial(get_threat_origins, hours, connection_id, user.tenant_id)
    )


@router.get("/events")
async def events(
    limit: int = Query(50, ge=1, le=500),
    severity: str = Query("all", pattern=r"^(all|high|critical)$"),
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
    user: User = _U,
):
    """Return recent security events from WAF audit logs."""
    try:
        return await _run(
            functools.partial(
                get_security_events, limit, severity, hours, connection_id, user.tenant_id
            )
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# ── Extended analytics panels ────────────────────────────────────


@router.get("/waf-events-timeline")
async def waf_events_timeline(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_waf_events_timeline, hours, connection_id, user.tenant_id)
    )


@router.get("/top-rules")
async def top_rules(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_top_rules, hours, connection_id, 10, user.tenant_id)
    )


@router.get("/severity-distribution")
async def severity_distribution(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_severity_distribution, hours, connection_id, user.tenant_id)
    )


@router.get("/top-attacking-ips")
async def top_attacking_ips(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_top_attacking_ips, hours, connection_id, 15, user.tenant_id)
    )


@router.get("/anomaly-score")
async def anomaly_score(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_anomaly_score_timeline, hours, connection_id, user.tenant_id)
    )


@router.get("/top-tags")
async def top_tags(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_top_tags, hours, connection_id, 10, user.tenant_id)
    )


@router.get("/top-uris")
async def top_uris(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_top_uris, hours, connection_id, 10, user.tenant_id)
    )


@router.get("/top-rule-files")
async def top_rule_files(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_top_rule_files, hours, connection_id, 10, user.tenant_id)
    )


@router.get("/status-codes")
async def status_codes(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(
            get_status_codes_timeline, hours, connection_id, user.tenant_id
        )
    )


@router.get("/top-user-agents")
async def top_user_agents(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_top_user_agents, hours, connection_id, 15, user.tenant_id)
    )


@router.get("/traffic-volume")
async def traffic_volume(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_traffic_volume, hours, connection_id, user.tenant_id)
    )


@router.get("/requests-per-second")
async def requests_per_second(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(get_requests_per_second, hours, connection_id, user.tenant_id)
    )


@router.get("/requests-by-country")
async def requests_by_country(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(
            get_requests_by_country, hours, connection_id, 15, user.tenant_id
        )
    )


@router.get("/top-client-ips")
async def top_client_ips(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID, user: User = _U
):
    return await _run(
        functools.partial(
            get_top_client_ips, hours, connection_id, 15, user.tenant_id
        )
    )


@router.get("/test-traffic/{marker}")
async def test_traffic(
    marker: str = Path(..., min_length=36, max_length=36, description="UUID4 marker"),
    user: User = _U,
):
    """Return all WAF audit rows tagged with this X-Test-Marker.

    Used by the Tests tab to overlay a spike on the traffic chart and list
    individual rule hits. Bypasses the dashboard TTL cache — we never want
    stale results for a freshly-fired marker.

    Path param is strictly validated as UUID4 — non-conforming values return
    400 BEFORE any ClickHouse query is built (SQL-injection barrier).
    """
    if not _UUID4_RE.match(marker):
        raise HTTPException(status_code=400, detail="marker must be a UUID4")
    try:
        return await _run(functools.partial(get_test_traffic_by_marker, marker))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
