"""FastAPI endpoints for domain-only connections.

Mounted at /api/connections. Every user-facing endpoint is tenant-scoped via
the `current_tenant` dependency — callers only see / mutate their own rows.

Endpoints (spec §4):

  GET    /edge-info   → per-deploy edge IPv4 the wizard surfaces in step 3
  POST   /            → create row (pending_verification) + TXT instructions
  GET    /            → list connections
  GET    /{id}        → fetch one
  PATCH  /{id}        → mutate name / enabled / TLS-mode / http_versions / compression
  DELETE /{id}        → drop row + Angie config + ACME cert
  POST   /{id}/probe  → kick poller now (manual Verify / Retry)
  POST   /reload      → regenerate every Angie config (operator, cross-tenant)
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.dependencies import current_tenant, require_admin
from ..db.models import Tenant
from ..db.session import get_session
from . import service
from .schemas import (
    Connection,
    ConnectionCreate,
    ConnectionUpdate,
    ModSecState,
    VerifyInstructions,
)

connections_router = APIRouter(prefix="/api/connections", tags=["connections"])


class CreateResponse(BaseModel):
    """POST / response: row + verify-step instructions in one payload."""

    connection: Connection
    instructions: VerifyInstructions


class EdgeInfo(BaseModel):
    """Per-deploy platform config the wizard needs on every step.

    Returned by GET /edge-info so the wizard's Step 3 can show the correct
    A-record value even when the user resumes setup from the list (the
    instructions object isn't re-issued by the backend on resume — only
    on initial create).
    """

    edge_ipv4: str


# Declared BEFORE /{connection_id} so FastAPI doesn't match "edge-info" as
# a connection_id path parameter.
@connections_router.get("/edge-info", response_model=EdgeInfo)
async def get_edge_info():
    return EdgeInfo(edge_ipv4=(os.environ.get("WAF_EDGE_IPV4") or "").strip())


@connections_router.get("/", response_model=list[Connection])
async def list_connections(
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    return await service.list_connections(session, tenant)


@connections_router.get("/{connection_id}", response_model=Connection)
async def get_connection(
    connection_id: int,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    conn = await service.get_connection(session, tenant, connection_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


@connections_router.post("/", response_model=CreateResponse, status_code=201)
async def create_connection(
    body: ConnectionCreate,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    conn, instructions = await service.create_connection(session, tenant, body)
    return CreateResponse(connection=conn, instructions=instructions)


@connections_router.patch("/{connection_id}", response_model=Connection)
async def update_connection(
    connection_id: int,
    body: ConnectionUpdate,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    conn = await service.update_connection(session, tenant, connection_id, body)
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


@connections_router.delete("/{connection_id}", status_code=204)
async def delete_connection(
    connection_id: int,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    ok = await service.delete_connection(session, tenant, connection_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Connection not found")


@connections_router.post("/{connection_id}/probe", response_model=Connection)
async def probe_connection(
    connection_id: int,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    conn = await service.probe_connection(session, tenant, connection_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


@connections_router.post("/reload")
async def reload_connections(
    session: AsyncSession = Depends(get_session),
    _admin=Depends(require_admin),
):
    # Platform-internal: cross-tenant bulk config regeneration; admin-only.
    return await service.reload_connections_config(session)


# ── Per-connection WAF security (ModSecurity state + GeoIP2 denied countries) ──


class SecurityConfig(BaseModel):
    """Per-connection WAF knobs surfaced on the /config page.

    Kept deliberately small: just the ModSecurity rule-engine state and the
    list of ISO 3166-1 alpha-2 country codes to block via GeoIP2. Everything
    else (audit log, PCRE, body limits, mmdb file) stays global on disk.
    """

    modsec_state: ModSecState
    geoip_denied_countries: list[str] = Field(default_factory=list)
    crowdsec_active: bool = True

    @field_validator("geoip_denied_countries")
    @classmethod
    def _validate_iso_codes(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for code in v:
            up = code.strip().upper()
            if len(up) != 2 or not up.isalpha():
                raise ValueError(
                    f"'{code}' is not a valid ISO 3166-1 alpha-2 country code"
                )
            if up not in seen:
                seen.add(up)
                out.append(up)
        return out


@connections_router.get("/{connection_id}/security", response_model=SecurityConfig)
async def get_security(
    connection_id: int,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    conn = await service.get_connection(session, tenant, connection_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return SecurityConfig(
        modsec_state=conn.modsec_state,
        geoip_denied_countries=conn.geoip_denied_countries,
        crowdsec_active=conn.crowdsec_active,
    )


@connections_router.put("/{connection_id}/security", response_model=SecurityConfig)
async def update_security(
    connection_id: int,
    body: SecurityConfig,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    conn = await service.update_security(
        session,
        tenant,
        connection_id,
        modsec_state=body.modsec_state,
        geoip_denied_countries=body.geoip_denied_countries,
        crowdsec_active=body.crowdsec_active,
    )
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return SecurityConfig(
        modsec_state=conn.modsec_state,
        geoip_denied_countries=conn.geoip_denied_countries,
        crowdsec_active=conn.crowdsec_active,
    )
