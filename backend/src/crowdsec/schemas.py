"""CrowdSec management schemas."""

from pydantic import BaseModel, Field


class DecisionItem(BaseModel):
    """Single CrowdSec decision."""

    id: int | None = None
    source: str = ""
    scope: str = "Ip"
    value: str = ""
    type: str = "ban"
    reason: str = ""
    duration: str = ""
    until: str = ""
    alert_id: int | None = None
    blocked_on: list[str] = Field(
        default_factory=list,
        description="Names of connections this IP is blocked on (empty = all connections / default server only)",
    )


class DecisionCreate(BaseModel):
    """Request to add a manual block decision."""

    ip: str = Field(..., description="IP address to block")
    duration: str = Field(default="4h", description="Block duration (e.g., 4h, 1d, 30m)")
    reason: str = Field(default="manual block", description="Reason for blocking")
    type: str = Field(default="ban", description="Decision type: ban, captcha")
    connection_ids: list[int] | None = Field(
        default=None,
        description="Specific connection IDs to block this IP on. If empty/null, blocks on all connections.",
    )


class ScenarioInfo(BaseModel):
    """Information about a CrowdSec scenario."""

    name: str = ""
    description: str = ""
    loaded: bool = False
    type: str = ""
    labels: list[str] = Field(default_factory=list)


class ServiceToggleRequest(BaseModel):
    """Request to enable/disable the entire CrowdSec service."""

    enabled: bool = Field(..., description="Whether CrowdSec should be enabled")


class CrowdSecStatus(BaseModel):
    """Overall CrowdSec status."""

    running: bool = False
    version: str = ""
    decisions_count: int = 0
    scenarios_count: int = 0
    alerts_count: int = 0


class AlertItem(BaseModel):
    """Single CrowdSec alert."""

    id: int | None = None
    scenario: str = ""
    message: str = ""
    source_ip: str = ""
    source_scope: str = "Ip"
    start_at: str = ""
    stop_at: str = ""
    capacity: int | None = None
    decisions_count: int = 0
