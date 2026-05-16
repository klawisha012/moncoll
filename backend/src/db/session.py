from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from .base import get_sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session
