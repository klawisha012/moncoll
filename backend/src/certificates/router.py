from fastapi import APIRouter, HTTPException
from typing import List

from ..connections import service as connection_service
from . import service as ssl_service
from .schemas import CertificateRequest, CertificateResponse

certificates_router = APIRouter(prefix="/api/ssl", tags=["ssl"])


@certificates_router.get("/status/{connection_id}", response_model=dict)
async def get_certificate_status(connection_id: int):
    """Check certificate status for a connection."""
    conn = connection_service.get_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    status = ssl_service.check_certificate_status(connection_id)
    return status


@certificates_router.post("/request/{connection_id}", response_model=dict)
async def request_certificate(connection_id: int, request: CertificateRequest):
    """Request ACME certificate for a connection."""
    conn = connection_service.get_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    domains = request.domains or conn.domains
    if not domains:
        raise HTTPException(status_code=400, detail="No domains specified")
    
    result = ssl_service.trigger_acme_request(connection_id, domains)
    return result


@certificates_router.post("/regenerate/{connection_id}", response_model=dict)
async def regenerate_certificate(connection_id: int):
    """Regenerate certificate for a connection."""
    conn = connection_service.get_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    domains = conn.domains
    if not domains:
        raise HTTPException(status_code=400, detail="No domains configured for connection")
    
    result = ssl_service.regenerate_certificate(connection_id, domains)
    return result
