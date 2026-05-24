import asyncio
import os

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.src.db.base import Base
from backend.src.db.models import (  # noqa: F401 — ensures models are in metadata
    Connection,
    EmailVerification,
    OAuthAccount,
    Tenant,
    User,
)


@pytest_asyncio.fixture(autouse=True)
async def _seed_admin(db_session):
    """Seed one admin user so /login passes the 'system not provisioned' guard.

    Phase 12 added ``if count_admins == 0: raise 503`` to the login endpoint.
    Without an admin row every test that calls /login (or /password/*) would
    get 503 instead of the response it is actually testing.

    autouse=True means this runs for every test in tests/integration/backend/
    without requiring an explicit parameter.  Tests that do not touch /login
    are unaffected — the extra DB row is invisible to them.
    """
    from backend.src.auth import service as auth_service

    await auth_service.create_admin(
        db_session,
        email="seed-admin@test.local",
        password="seedpass1",
    )


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session():
    url = os.environ.get(
        "TEST_DATABASE_URL", "postgresql+asyncpg://waf:waf@localhost:5432/waf_test"
    )
    engine = create_async_engine(url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as session:
        yield session
    await engine.dispose()


# ---------------------------------------------------------------------------
# D4: tenant-scoped resource helpers.
#
# Production service functions (e.g. connections.create_connection) trigger DNS
# resolution and ACME polling, which makes them unsuitable for tenant-isolation
# unit tests. These helpers bypass the service layer and write rows directly so
# tests can focus on enforcement of the tenant_id filter.
# ---------------------------------------------------------------------------


async def insert_connection_raw(
    session,
    *,
    tenant_id: int,
    domain: str,
    name: str = "test",
    origin_hosts: list[str] | None = None,
) -> Connection:
    c = Connection(
        tenant_id=tenant_id,
        name=name,
        domain=domain,
        origin_hosts=origin_hosts or ["127.0.0.1"],
        origin_port=443,
        origin_tls_mode="strict",
        verify_token="x" * 32,
        status="pending_verification",
        http_versions="h1,h2",
        compression_algo="auto",
        enabled=True,
    )
    session.add(c)
    await session.commit()
    await session.refresh(c)
    return c


# Stubs for Phase 5.2 expansion — add insert_crowdsec_raw, insert_modsec_rule_raw, etc.
# as those tables are introduced.
