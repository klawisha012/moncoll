"""CrowdSec management router."""

from fastapi import APIRouter, Body, Query

from . import service as crowdsec_service
from .schemas import (
    AlertItem,
    CrowdSecStatus,
    DecisionCreate,
    DecisionItem,
    ScenarioInfo,
    ServiceToggleRequest,
)

router = APIRouter(prefix="/api/crowdsec", tags=["crowdsec"])


# ── Status ─────────────────────────────────────────────────


@router.get("/status", response_model=CrowdSecStatus)
async def get_status():
    """Get CrowdSec overall status (version, counts)."""
    return crowdsec_service.get_status()


# ── Decisions ──────────────────────────────────────────────


@router.get("/decisions", response_model=list[DecisionItem])
async def get_decisions():
    """List all active decisions (blocks)."""
    return crowdsec_service.get_decisions()


@router.post("/decisions")
async def add_decision(req: DecisionCreate):
    """Add a manual block decision for an IP."""
    return crowdsec_service.add_decision(req)


@router.delete("/decisions/{ip}")
async def delete_decision(ip: str):
    """Remove a decision (unblock an IP)."""
    return crowdsec_service.delete_decision(ip)


@router.delete("/decisions")
async def delete_all_decisions():
    """Remove all decisions."""
    return crowdsec_service.delete_all_decisions()


# ── Manual block audit log ─────────────────────────────────


@router.get("/manual-blocks")
async def get_manual_blocks(
    limit: int = Query(default=100, le=1000),
    hours: float | None = Query(
        default=None,
        ge=0.0167,
        le=8760,
        description="Optional time window in hours (omit for no filter)",
    ),
):
    """Get manual block/unblock audit log."""
    return crowdsec_service.get_manual_block_log(limit, hours)


# ── Scenarios ──────────────────────────────────────────────


@router.get("/scenarios", response_model=list[ScenarioInfo])
async def get_scenarios():
    """Get list of available scenarios and their enabled/disabled status."""
    return crowdsec_service.get_scenarios()


@router.get("/scenarios/hub")
async def get_scenario_hub():
    """Get list of scenarios available in the hub."""
    return crowdsec_service.get_scenario_hub_items()


@router.post("/scenarios/install/{name:path}")
async def install_scenario(name: str):
    """Install a scenario from the hub."""
    return crowdsec_service.install_scenario(name)


@router.delete("/scenarios/remove/{name:path}")
async def remove_scenario(name: str):
    """Remove an installed scenario."""
    return crowdsec_service.remove_scenario(name)


# ── Service Toggle ──────────────────────────────────────────


@router.get("/service-status")
async def get_service_status():
    """Get whether CrowdSec service container is running."""
    enabled = crowdsec_service.get_crowdsec_service_enabled()
    return {"enabled": enabled}


@router.post("/toggle")
async def toggle_service(req: ServiceToggleRequest = Body(...)):
    """
    Enable or disable the entire CrowdSec service.
    Body: {"enabled": true} or {"enabled": false}
    """
    return crowdsec_service.toggle_crowdsec_service(req.enabled)


# ── Scenario Toggle ────────────────────────────────────────


@router.post("/scenarios/toggle/{name:path}")
async def toggle_scenario(name: str):
    """Toggle a scenario between enabled and disabled state."""
    # Determine current state by listing scenarios
    scenarios = crowdsec_service.get_scenarios()
    current_enabled = False
    for s in scenarios:
        if s.name == name:
            current_enabled = s.loaded
            break

    target = not current_enabled
    return crowdsec_service.toggle_scenario(name, target)


# ── Alerts ─────────────────────────────────────────────────


@router.get("/alerts", response_model=list[AlertItem])
async def get_alerts(
    hours: float | None = Query(
        default=None,
        ge=0.0167,
        le=8760,
        description="Optional time window in hours (omit for no filter)",
    ),
):
    """Get list of CrowdSec alerts."""
    return crowdsec_service.get_alerts(hours)


# ── Reload ─────────────────────────────────────────────────


@router.post("/reload")
async def reload_crowdsec():
    """Reload CrowdSec (hub update + upgrade)."""
    return crowdsec_service.reload_crowdsec()
