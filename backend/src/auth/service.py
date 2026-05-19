import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import User
from .schemas import UserCreate, UserUpdate
from .security import hash_password, verify_password

logger = logging.getLogger(__name__)

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"


async def _count_admins(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count()).select_from(User).where(User.role == "admin")
    )
    return int(result.scalar_one())


async def seed_default_admin(session: AsyncSession) -> None:
    """Create default admin/admin user if no users exist."""
    existing = await session.execute(select(func.count()).select_from(User))
    if existing.scalar_one() > 0:
        return
    admin = User(
        username=DEFAULT_ADMIN_USERNAME,
        password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
        role="admin",
        must_change_password=True,
    )
    session.add(admin)
    await session.commit()
    logger.warning(
        "Created default admin user (username=%s, password=%s, must_change_password=true). "
        "Change the password on first login.",
        DEFAULT_ADMIN_USERNAME,
        DEFAULT_ADMIN_PASSWORD,
    )


async def authenticate(session: AsyncSession, username: str, password: str) -> User | None:
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user and verify_password(password, user.password_hash):
        return user
    return None


async def get_user(session: AsyncSession, user_id: int) -> User | None:
    return await session.get(User, user_id)


async def list_users(session: AsyncSession) -> list[User]:
    result = await session.execute(select(User).order_by(User.id))
    return list(result.scalars().all())


async def create_user(session: AsyncSession, payload: UserCreate) -> User:
    existing = await session.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none() is not None:
        raise ValueError("username already exists")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        must_change_password=False,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def update_user(session: AsyncSession, user_id: int, payload: UserUpdate) -> User | None:
    user = await session.get(User, user_id)
    if user is None:
        return None
    if payload.role is not None:
        if user.role == "admin" and payload.role != "admin":
            if await _count_admins(session) <= 1:
                raise ValueError("cannot demote the last admin")
        user.role = payload.role
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
        user.must_change_password = True
    await session.commit()
    await session.refresh(user)
    return user


async def change_password(session: AsyncSession, user_id: int, new_password: str) -> bool:
    user = await session.get(User, user_id)
    if user is None:
        return False
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    await session.commit()
    return True


async def delete_user(session: AsyncSession, user_id: int) -> bool:
    user = await session.get(User, user_id)
    if user is None:
        return False
    if user.role == "admin" and await _count_admins(session) <= 1:
        raise ValueError("cannot delete the last admin")
    await session.delete(user)
    await session.commit()
    return True
