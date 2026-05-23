import re
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Tenant

# Tenant name: lowercase alphanumeric + hyphens, 3–32 chars, no leading/trailing hyphen.
# Pattern: starts with [a-z0-9], then 1–30 chars of [a-z0-9-], ends with [a-z0-9].
# Minimum length is 3 (one start + one middle + one end).
TENANT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")


class InvalidTenantName(ValueError): ...
class TenantNameTaken(ValueError): ...


def _validate_name(name: str) -> None:
    if not TENANT_NAME_RE.match(name):
        raise InvalidTenantName(name)


async def create_tenant(
    session: AsyncSession, *, name: str, display_name: str
) -> Tenant:
    _validate_name(name)
    existing = await session.execute(select(Tenant).where(Tenant.name == name))
    if existing.scalar_one_or_none():
        raise TenantNameTaken(name)
    t = Tenant(name=name, display_name=display_name or name)
    session.add(t)
    await session.commit()
    await session.refresh(t)
    return t


async def get(session: AsyncSession, tenant_id: int) -> Tenant | None:
    return await session.get(Tenant, tenant_id)


async def get_by_name(session: AsyncSession, name: str) -> Tenant | None:
    result = await session.execute(select(Tenant).where(Tenant.name == name))
    return result.scalar_one_or_none()


async def suspend(session: AsyncSession, tenant_id: int) -> Tenant | None:
    t = await session.get(Tenant, tenant_id)
    if not t:
        return None
    t.suspended_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(t)
    return t


async def unsuspend(session: AsyncSession, tenant_id: int) -> Tenant | None:
    t = await session.get(Tenant, tenant_id)
    if not t:
        return None
    t.suspended_at = None
    await session.commit()
    await session.refresh(t)
    return t


async def delete(session: AsyncSession, tenant_id: int) -> bool:
    t = await session.get(Tenant, tenant_id)
    if not t:
        return False
    await session.delete(t)
    await session.commit()
    return True
