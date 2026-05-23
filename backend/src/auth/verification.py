import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import EmailVerification, User

TTL = {"verify_email": timedelta(hours=24), "reset_password": timedelta(hours=1)}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def issue(session: AsyncSession, user: User, *, purpose: str) -> str:
    token = secrets.token_urlsafe(32)
    row = EmailVerification(
        user_id=user.id,
        purpose=purpose,
        token_hash=_hash(token),
        expires_at=datetime.now(UTC) + TTL[purpose],
    )
    session.add(row)
    await session.commit()
    return token


async def consume(session: AsyncSession, token: str, *, purpose: str) -> User | None:
    result = await session.execute(
        select(EmailVerification).where(
            EmailVerification.token_hash == _hash(token),
            EmailVerification.purpose == purpose,
            EmailVerification.used_at.is_(None),
            EmailVerification.expires_at > datetime.now(UTC),
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        return None
    row.used_at = datetime.now(UTC)
    user = await session.get(User, row.user_id)
    await session.commit()
    return user
