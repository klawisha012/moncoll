from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.dependencies import current_tenant
from ..connections import service as connection_service
from ..db.models import Tenant
from ..db.session import get_session
from . import service as ssl_service
from .schemas import CertificateRequest

certificates_router = APIRouter(prefix="/api/ssl", tags=["ssl"])


@certificates_router.get("/status/{connection_id}", response_model=dict)
async def get_certificate_status(
    connection_id: int,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    """Check certificate status for a connection (caller's tenant only)."""
    conn = await connection_service.get_connection(session, tenant, connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")

    status = ssl_service.check_certificate_status(connection_id, tenant_id=tenant.id)
    return status


@certificates_router.post("/request/{connection_id}", response_model=dict)
async def request_certificate(
    connection_id: int,
    request: CertificateRequest,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    """Request ACME certificate for a connection (caller's tenant only)."""
    conn = await connection_service.get_connection(session, tenant, connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")

    domains = request.domains or [conn.domain]
    result = ssl_service.trigger_acme_request(connection_id, domains, tenant_id=tenant.id)
    return result


@certificates_router.post("/regenerate/{connection_id}", response_model=dict)
async def regenerate_certificate(
    connection_id: int,
    session: AsyncSession = Depends(get_session),
    tenant: Tenant = Depends(current_tenant),
):
    """Regenerate certificate for a connection (caller's tenant only)."""
    conn = await connection_service.get_connection(session, tenant, connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")

    result = ssl_service.regenerate_certificate(connection_id, [conn.domain], tenant_id=tenant.id)
    return result
