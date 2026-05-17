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


@router.get("/metrics")
async def metrics(
    hours: float = Query(24, ge=0.0167, le=8760, description="Time window in hours (supports fractional, e.g. 0.0167 = 1 min)"),
):
    """Return summary metrics for the dashboard stat cards."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_dashboard_metrics, hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/traffic")
async def traffic(
    hours: float = Query(24, ge=0.0167, le=8760, description="Time window in hours (supports fractional, e.g. 0.0167 = 1 min)"),
):
    """Return traffic data points (clean vs malicious) for charts."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_traffic_data, hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/geoip-map")
async def geoip_map(
    hours: float = Query(24, ge=0.0167, le=8760, description="Time window in hours (supports fractional, e.g. 0.0167 = 1 min)"),
):
    """Return GeoIP coordinates with hit counts for world map visualization."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_geoip_map_data, hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/threat-origins")
async def threat_origins():
    """Return threat origin distribution by country."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_threat_origins)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/events")
async def events(
    limit: int = Query(50, ge=1, le=500),
    severity: str = Query("all", pattern=r"^(all|high|critical)$"),
):
    """Return recent security events from WAF audit logs."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, get_security_events, limit, severity
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
