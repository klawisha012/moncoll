import pytest
from backend.src.auth import service as auth
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_create_client_user(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id)
    assert u.platform_role == "client"
    assert u.tenant_role == "owner"


@pytest.mark.asyncio
async def test_authenticate(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id)
    u = await auth.authenticate(db_session, "a@b.com", "hunter22a")
    assert u is not None
    assert await auth.authenticate(db_session, "a@b.com", "wrong") is None


@pytest.mark.asyncio
async def test_email_taken(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    await auth.create_client_user(db_session, email="a@b.com", password="hunter22a", tenant_id=t.id)
    with pytest.raises(auth.EmailTaken):
        await auth.create_client_user(db_session, email="A@B.com", password="hunter22a", tenant_id=t.id)


@pytest.mark.asyncio
async def test_create_admin(db_session):
    u = await auth.create_admin(db_session, email="admin@example.com", password="strongpass1")
    assert u.platform_role == "admin"
    assert u.tenant_id is None
    assert u.tenant_role is None
    assert u.email_verified_at is not None


@pytest.mark.asyncio
async def test_authenticate_case_insensitive(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    await auth.create_client_user(db_session, email="User@Example.COM", password="pass1234", tenant_id=t.id)
    u = await auth.authenticate(db_session, "user@example.com", "pass1234")
    assert u is not None


@pytest.mark.asyncio
async def test_mark_email_verified(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth.create_client_user(db_session, email="a@b.com", password="pass1234", tenant_id=t.id)
    assert u.email_verified_at is None
    await auth.mark_email_verified(db_session, u)
    assert u.email_verified_at is not None


@pytest.mark.asyncio
async def test_update_password(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth.create_client_user(db_session, email="a@b.com", password="oldpass1", tenant_id=t.id)
    await auth.update_password(db_session, u, "newpass123")
    assert await auth.authenticate(db_session, "a@b.com", "newpass123") is not None
    assert await auth.authenticate(db_session, "a@b.com", "oldpass1") is None


@pytest.mark.asyncio
async def test_touch_login(db_session):
    t = await tenants.create_tenant(db_session, name="acme", display_name="Acme")
    u = await auth.create_client_user(db_session, email="a@b.com", password="pass1234", tenant_id=t.id)
    assert u.last_login_at is None
    await auth.touch_login(db_session, u)
    assert u.last_login_at is not None
