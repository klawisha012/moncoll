from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import User
from .security import hash_password, verify_password


class EmailTaken(ValueError): ...
class UserNotFound(ValueError): ...


async def get_user(session: AsyncSession, user_id: int) -> User | None:
    return await session.get(User, user_id)


async def get_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()


async def count_admins(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count()).select_from(User).where(User.platform_role == "admin")
    )
    return int(result.scalar_one())


async def create_client_user(
    session: AsyncSession,
    *,
    email: str,
    password: str | None,
    tenant_id: int,
    tenant_role: str = "owner",
    display_name: str = "",
    email_verified: bool = False,
) -> User:
    email = email.lower()
    if await get_by_email(session, email):
        raise EmailTaken(email)
    user = User(
        email=email,
        display_name=display_name or email.split("@")[0],
        password_hash=hash_password(password) if password else None,
        platform_role="client",
        tenant_id=tenant_id,
        tenant_role=tenant_role,
        email_verified_at=datetime.now(UTC) if email_verified else None,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def create_admin(session: AsyncSession, *, email: str, password: str) -> User:
    email = email.lower()
    if await get_by_email(session, email):
        raise EmailTaken(email)
    user = User(
        email=email,
        display_name=email.split("@")[0],
        password_hash=hash_password(password),
        platform_role="admin",
        tenant_id=None,
        tenant_role=None,
        email_verified_at=datetime.now(UTC),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def authenticate(session: AsyncSession, email: str, password: str) -> User | None:
    user = await get_by_email(session, email)
    if not user or not verify_password(password, user.password_hash):
        return None
    return user


async def mark_email_verified(session: AsyncSession, user: User) -> None:
    user.email_verified_at = datetime.now(UTC)
    await session.commit()


async def update_password(session: AsyncSession, user: User, new_password: str) -> None:
    user.password_hash = hash_password(new_password)
    await session.commit()


async def touch_login(session: AsyncSession, user: User) -> None:
    user.last_login_at = datetime.now(UTC)
    await session.commit()

