import asyncio

from fastapi import APIRouter, HTTPException, Query

from .service import (
    get_dashboard_metrics,
    get_geoip_map_data,
    get_security_events,
    get_threat_origins,
    get_traffic_data,
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


@router.get("/metrics")
async def metrics(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
):
    """Return summary metrics for the dashboard stat cards."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_dashboard_metrics, hours, connection_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/traffic")
async def traffic(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
):
    """Return traffic data points (clean vs malicious) for charts."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_traffic_data, hours, connection_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip-map")
async def geoip_map(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
):
    """Return GeoIP coordinates with hit counts for world map visualization."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_geoip_map_data, hours, connection_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/threat-origins")
async def threat_origins(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
):
    """Return threat origin distribution by country.

    Never returns 500 — degrades to an empty list when ClickHouse is
    unavailable or the relevant tables are empty.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_threat_origins, hours, connection_id)


@router.get("/events")
async def events(
    limit: int = Query(50, ge=1, le=500),
    severity: str = Query("all", pattern=r"^(all|high|critical)$"),
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
):
    """Return recent security events from WAF audit logs."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, get_security_events, limit, severity, hours, connection_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
