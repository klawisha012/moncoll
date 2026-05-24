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


def _slugify(raw: str) -> str:
    """Turn an arbitrary string (display name, email local-part, etc.) into a
    candidate tenant slug. Replaces non-[a-z0-9] with hyphens, collapses runs,
    strips leading/trailing hyphens. May return an empty string for input with
    no alphanumerics — caller should fall back to a synthetic name in that case.
    """
    lowered = raw.lower()
    out = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    # Collapse multi-hyphen runs (already done by the regex above, but belt+suspenders).
    out = re.sub(r"-{2,}", "-", out)
    # Clamp to 32 chars (regex max), respecting the "must end on [a-z0-9]" rule.
    if len(out) > 32:
        out = out[:32].rstrip("-")
    return out


async def auto_create_tenant_for_user(
    session: AsyncSession, *, email: str, display_name: str = ""
) -> Tenant:
    """Create a tenant with a name derived from display_name or email local-part.
    Used by OAuth signup where the user never picks a tenant slug — we generate
    one for them. Guarantees uniqueness by appending -2, -3, … if the candidate
    is taken or invalid.
    """
    base = _slugify(display_name) or _slugify(email.split("@", 1)[0]) or "ws"
    # Ensure minimum length of 3 (regex requirement).
    if len(base) < 3:
        base = (base + "-ws")[:32].rstrip("-")
    # Try base first, then base-2, base-3, … up to base-99.
    for suffix in [""] + [f"-{i}" for i in range(2, 100)]:
        candidate = f"{base}{suffix}"
        # Re-clamp in case the suffix pushed past 32 chars.
        if len(candidate) > 32:
            candidate = f"{base[: 32 - len(suffix)]}{suffix}".rstrip("-")
        if not TENANT_NAME_RE.match(candidate):
            continue
        existing = await session.execute(select(Tenant).where(Tenant.name == candidate))
        if existing.scalar_one_or_none() is None:
            return await create_tenant(session, name=candidate, display_name=display_name or candidate)
    raise InvalidTenantName(f"cannot derive a unique tenant slug from email={email!r} display={display_name!r}")
