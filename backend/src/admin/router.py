import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.dependencies import require_admin
from ..db.session import get_session
from ..tenants import service as tenants_service
from . import service

router = APIRouter(prefix="/api/admin", tags=["admin"])

_TENANTS_BASE = Path("/var/lib/waf/tenants")


def _reload_angie() -> None:
    """Best-effort Angie reload. Import inline to avoid circular dep."""
    try:
        from ..connections.service import _reload_angie as _reload
        _reload()
    except Exception:
        pass


@router.get("/tenants", dependencies=[Depends(require_admin)])
async def list_(session: AsyncSession = Depends(get_session)):
    return await service.list_tenants(session)


@router.get("/tenants/{tenant_id}", dependencies=[Depends(require_admin)])
async def detail(tenant_id: int, session: AsyncSession = Depends(get_session)):
    d = await service.get_tenant_detail(session, tenant_id)
    if not d:
        raise HTTPException(status_code=404, detail="tenant not found")
    return d


@router.post("/tenants/{tenant_id}/suspend", dependencies=[Depends(require_admin)])
async def suspend(tenant_id: int, session: AsyncSession = Depends(get_session)):
    # Rename compose dir so Angie glob stops including its configs.
    compose_dir = _TENANTS_BASE / str(tenant_id) / "compose"
    suspended_dir = _TENANTS_BASE / str(tenant_id) / "compose.suspended"
    if compose_dir.exists() and not suspended_dir.exists():
        compose_dir.rename(suspended_dir)
    _reload_angie()

    t = await tenants_service.suspend(session, tenant_id)
    if not t:
        raise HTTPException(status_code=404)
    return {"suspended_at": t.suspended_at}


@router.post("/tenants/{tenant_id}/unsuspend", dependencies=[Depends(require_admin)])
async def unsuspend(tenant_id: int, session: AsyncSession = Depends(get_session)):
    # Rename compose.suspended back so Angie glob picks it up again.
    compose_dir = _TENANTS_BASE / str(tenant_id) / "compose"
    suspended_dir = _TENANTS_BASE / str(tenant_id) / "compose.suspended"
    if suspended_dir.exists() and not compose_dir.exists():
        suspended_dir.rename(compose_dir)
    _reload_angie()

    t = await tenants_service.unsuspend(session, tenant_id)
    if not t:
        raise HTTPException(status_code=404)
    return {"suspended_at": None}


@router.delete("/tenants/{tenant_id}", status_code=204, dependencies=[Depends(require_admin)])
async def delete_(
    tenant_id: int,
    confirm: str = Query(...),
    session: AsyncSession = Depends(get_session),
):
    t = await tenants_service.get(session, tenant_id)
    if not t:
        raise HTTPException(status_code=404)
    if confirm != t.name:
        raise HTTPException(status_code=400, detail="confirm value must equal tenant name")

    # Remove tenant filesystem tree before DB delete so we don't leave orphaned dirs.
    tenant_dir = _TENANTS_BASE / str(tenant_id)
    shutil.rmtree(tenant_dir, ignore_errors=True)
    _reload_angie()

    await tenants_service.delete(session, tenant_id)
