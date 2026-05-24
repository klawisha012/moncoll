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
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.dependencies import current_tenant, require_admin
from ..db.models import Tenant
from ..db.session import get_session
from . import service
from .schemas import Connection, ConnectionCreate, ConnectionUpdate, VerifyInstructions

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
