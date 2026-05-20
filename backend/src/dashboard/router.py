import asyncio

from fastapi import APIRouter, HTTPException, Query

from .service import (
    get_anomaly_score_timeline,
    get_dashboard_metrics,
    get_geoip_map_data,
    get_requests_by_country,
    get_requests_per_second,
    get_security_events,
    get_severity_distribution,
    get_status_codes_timeline,
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


async def _run(fn, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn, *args)


@router.get("/metrics")
async def metrics(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    """Return summary metrics for the dashboard stat cards."""
    try:
        return await _run(get_dashboard_metrics, hours, connection_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/traffic")
async def traffic(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    """Return traffic data points (clean vs malicious) for charts."""
    try:
        return await _run(get_traffic_data, hours, connection_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip-map")
async def geoip_map(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    """Return GeoIP coordinates with hit counts for world map visualization."""
    try:
        return await _run(get_geoip_map_data, hours, connection_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/threat-origins")
async def threat_origins(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    """Return threat origin distribution by country."""
    return await _run(get_threat_origins, hours, connection_id)


@router.get("/events")
async def events(
    limit: int = Query(50, ge=1, le=500),
    severity: str = Query("all", pattern=r"^(all|high|critical)$"),
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
):
    """Return recent security events from WAF audit logs."""
    try:
        return await _run(get_security_events, limit, severity, hours, connection_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# ── Extended analytics: mirror of Grafana panels ─────────────────


@router.get("/waf-events-timeline")
async def waf_events_timeline(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_waf_events_timeline, hours, connection_id)


@router.get("/top-rules")
async def top_rules(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_top_rules, hours, connection_id, 10)


@router.get("/severity-distribution")
async def severity_distribution(
    hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID
):
    return await _run(get_severity_distribution, hours, connection_id)


@router.get("/top-attacking-ips")
async def top_attacking_ips(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_top_attacking_ips, hours, connection_id, 15)


@router.get("/anomaly-score")
async def anomaly_score(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_anomaly_score_timeline, hours, connection_id)


@router.get("/top-tags")
async def top_tags(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_top_tags, hours, connection_id, 10)


@router.get("/top-uris")
async def top_uris(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_top_uris, hours, connection_id, 10)


@router.get("/top-rule-files")
async def top_rule_files(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_top_rule_files, hours, connection_id, 10)


@router.get("/status-codes")
async def status_codes(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_status_codes_timeline, hours, connection_id)


@router.get("/top-user-agents")
async def top_user_agents(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_top_user_agents, hours, connection_id, 15)


@router.get("/traffic-volume")
async def traffic_volume(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_traffic_volume, hours, connection_id)


@router.get("/requests-per-second")
async def requests_per_second(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_requests_per_second, hours, connection_id)


@router.get("/requests-by-country")
async def requests_by_country(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_requests_by_country, hours, connection_id, 15)


@router.get("/top-client-ips")
async def top_client_ips(hours: float = _HOURS, connection_id: int | None = _CONNECTION_ID):
    return await _run(get_top_client_ips, hours, connection_id, 15)
