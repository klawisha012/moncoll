"""Two-tenant isolation tests for connections/service.py.

These tests verify that tenant A cannot see, fetch, update, or delete
connections owned by tenant B. They bypass the service-layer DNS logic
by using insert_connection_raw (direct DB insert) so they don't need
network access.
"""

import pytest

from tests.integration.backend.conftest import insert_connection_raw
from backend.src.connections import service as conns
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_tenant_a_cannot_list_b_connections(db_session):
    a = await tenants.create_tenant(db_session, name="tenant-a", display_name="A")
    b = await tenants.create_tenant(db_session, name="tenant-b", display_name="B")
    await insert_connection_raw(db_session, tenant_id=b.id, domain="b.example.com", name="b1")
    listed = await conns.list_connections(db_session, a)
    assert listed == []


@pytest.mark.asyncio
async def test_tenant_a_cannot_get_b_connection_by_id(db_session):
    a = await tenants.create_tenant(db_session, name="tenant-a", display_name="A")
    b = await tenants.create_tenant(db_session, name="tenant-b", display_name="B")
    c = await insert_connection_raw(db_session, tenant_id=b.id, domain="b.example.com", name="b1")
    got = await conns.get_connection(db_session, a, c.id)
    assert got is None


@pytest.mark.asyncio
async def test_tenant_a_cannot_delete_b_connection(db_session):
    a = await tenants.create_tenant(db_session, name="tenant-a", display_name="A")
    b = await tenants.create_tenant(db_session, name="tenant-b", display_name="B")
    c = await insert_connection_raw(db_session, tenant_id=b.id, domain="b.example.com", name="b1")
    deleted = await conns.delete_connection(db_session, a, c.id)
    assert deleted is False
    # B's row still exists
    got_via_b = await conns.get_connection(db_session, b, c.id)
    assert got_via_b is not None


@pytest.mark.asyncio
async def test_tenant_a_sees_own_connections_only(db_session):
    """A's list returns its own rows, not B's."""
    a = await tenants.create_tenant(db_session, name="tenant-a", display_name="A")
    b = await tenants.create_tenant(db_session, name="tenant-b", display_name="B")
    ca = await insert_connection_raw(db_session, tenant_id=a.id, domain="a.example.com", name="a1")
    await insert_connection_raw(db_session, tenant_id=b.id, domain="b.example.com", name="b1")
    listed = await conns.list_connections(db_session, a)
    ids = [c.id for c in listed]
    assert ca.id in ids
    assert all(c.tenant_id == a.id for c in listed)


@pytest.mark.asyncio
async def test_tenant_a_cannot_update_b_connection(db_session):
    from backend.src.connections.schemas import ConnectionUpdate

    a = await tenants.create_tenant(db_session, name="tenant-a", display_name="A")
    b = await tenants.create_tenant(db_session, name="tenant-b", display_name="B")
    c = await insert_connection_raw(db_session, tenant_id=b.id, domain="b.example.com", name="b1")
    result = await conns.update_connection(
        db_session, a, c.id, ConnectionUpdate(name="hacked")
    )
    assert result is None
    # Original name unchanged
    got_via_b = await conns.get_connection(db_session, b, c.id)
    assert got_via_b is not None
    assert got_via_b.name == "b1"
