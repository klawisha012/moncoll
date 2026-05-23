import pytest
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_create_and_get_tenant(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    assert t.id is not None
    assert t.name == "acme"
    got = await tenants.get_by_name(db_session, "acme")
    assert got.id == t.id


@pytest.mark.asyncio
async def test_duplicate_name_raises(db_session):
    await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    with pytest.raises(tenants.TenantNameTaken):
        await tenants.create_tenant(db_session, name="acme", display_name="Other")


@pytest.mark.asyncio
async def test_invalid_name_raises(db_session):
    with pytest.raises(tenants.InvalidTenantName):
        await tenants.create_tenant(db_session, name="No Spaces", display_name="X")
    with pytest.raises(tenants.InvalidTenantName):
        await tenants.create_tenant(db_session, name="ab", display_name="X")


@pytest.mark.asyncio
async def test_suspend_and_unsuspend(db_session):
    t = await tenants.create_tenant(db_session, name="beta-co", display_name="Beta Co")
    assert t.suspended_at is None
    t = await tenants.suspend(db_session, t.id)
    assert t.suspended_at is not None
    t = await tenants.unsuspend(db_session, t.id)
    assert t.suspended_at is None


@pytest.mark.asyncio
async def test_delete(db_session):
    t = await tenants.create_tenant(db_session, name="gamma-io", display_name="Gamma IO")
    ok = await tenants.delete(db_session, t.id)
    assert ok is True
    assert await tenants.get(db_session, t.id) is None


@pytest.mark.asyncio
async def test_delete_nonexistent(db_session):
    ok = await tenants.delete(db_session, 99999)
    assert ok is False
