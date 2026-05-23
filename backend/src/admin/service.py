from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Connection, Tenant, User


async def list_tenants(session: AsyncSession) -> list[dict]:
    result = await session.execute(
        select(
            Tenant,
            func.count(User.id).label("user_count"),
            func.max(User.last_login_at).label("last_activity"),
        )
        .outerjoin(User, User.tenant_id == Tenant.id)
        .group_by(Tenant.id)
    )
    rows = []
    for tenant, user_count, last_activity in result.all():
        conn_count = await session.scalar(
            select(func.count(Connection.id)).where(Connection.tenant_id == tenant.id)
        )
        owner = (
            await session.execute(
                select(User).where(
                    User.tenant_id == tenant.id,
                    User.tenant_role == "owner",
                )
            )
        ).scalar_one_or_none()
        rows.append(
            {
                "id": tenant.id,
                "name": tenant.name,
                "display_name": tenant.display_name,
                "owner_email": owner.email if owner else None,
                "user_count": user_count,
                "connection_count": conn_count,
                "created_at": tenant.created_at,
                "suspended_at": tenant.suspended_at,
                "last_activity": last_activity,
            }
        )
    return rows


async def get_tenant_detail(session: AsyncSession, tenant_id: int) -> dict | None:
    t = await session.get(Tenant, tenant_id)
    if not t:
        return None
    users = (
        await session.execute(select(User).where(User.tenant_id == tenant_id))
    ).scalars().all()
    conns = (
        await session.execute(
            select(Connection).where(Connection.tenant_id == tenant_id)
        )
    ).scalars().all()
    return {
        "tenant": {
            "id": t.id,
            "name": t.name,
            "display_name": t.display_name,
            "created_at": t.created_at,
            "suspended_at": t.suspended_at,
        },
        "users": [
            {
                "id": u.id,
                "email": u.email,
                "tenant_role": u.tenant_role,
                "last_login_at": u.last_login_at,
                "email_verified": u.email_verified_at is not None,
                "totp_enabled": u.totp_enabled_at is not None,
            }
            for u in users
        ],
        "connections": [
            {"id": c.id, "name": c.name, "domain": c.domain, "status": c.status}
            for c in conns
        ],
    }
