"""Unit tests for connections.service — create_connection with manual origin hosts & instant verification bypass.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.connections import service as conns_service
from src.connections.schemas import ConnectionCreate
from src.db.models import Tenant


@pytest.fixture
def mock_session():
    session = AsyncMock()

    # Mock duplicate check returning None (no duplicate)
    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_execute_result

    # Mock refresh to populate DB defaults
    async def mock_refresh(r):
        r.id = 42
        r.acme_retry_count = 0
        r.modsec_state = "detection_only"
        r.crowdsec_active = True
        from datetime import datetime, UTC
        r.created_at = datetime.now(UTC)
        r.updated_at = datetime.now(UTC)
    session.refresh = AsyncMock(side_effect=mock_refresh)

    return session


@pytest.mark.asyncio
async def test_create_connection_with_manual_origin_hosts(mock_session):
    tenant = Tenant(id=1, name="test-tenant")
    conn_in = ConnectionCreate(
        name="test-conn",
        domain="manual.example.com",
        origin_hosts=["1.1.1.1", "1.0.0.1"],
        origin_port=443,
    )

    # Mock resolve_a to return not pointed to edge
    with patch.object(conns_service, "resolve_a", AsyncMock(return_value=(["93.184.216.34"], 300))), \
         patch.object(conns_service, "_edge_ipv4", return_value="80.72.24.108"), \
         patch.object(conns_service.angie_config, "write_config"), \
         patch.object(conns_service, "_reload_angie"):

        conn, inst = await conns_service.create_connection(mock_session, tenant, conn_in)

        # Verify manual origin hosts were preserved
        assert conn.origin_hosts == ["1.1.1.1", "1.0.0.1"]
        # Since it did not point to edge, status is pending_verification
        assert conn.status == "pending_verification"
        assert conn.verified_at is None


@pytest.mark.asyncio
async def test_create_connection_manual_origin_blocked_raises(mock_session):
    tenant = Tenant(id=1, name="test-tenant")
    conn_in = ConnectionCreate(
        name="test-conn",
        domain="manual.example.com",
        origin_hosts=["192.168.1.1"],  # Private IP
    )

    with pytest.raises(HTTPException) as exc_info:
        await conns_service.create_connection(mock_session, tenant, conn_in)
    assert exc_info.value.status_code == 422
    assert "private/reserved" in exc_info.value.detail


@pytest.mark.asyncio
async def test_create_connection_instant_bypass_when_pointed_to_edge(mock_session):
    tenant = Tenant(id=1, name="test-tenant")
    conn_in = ConnectionCreate(
        name="test-conn",
        domain="pointed.example.com",
        origin_hosts=["1.1.1.1"],
    )

    # Mock resolve_a returning WAF edge IP
    with patch.object(conns_service, "resolve_a", AsyncMock(return_value=(["80.72.24.108"], 300))), \
         patch.object(conns_service, "_edge_ipv4", return_value="80.72.24.108"), \
         patch.object(conns_service.angie_config, "write_config"), \
         patch.object(conns_service, "_reload_angie"):

        conn, inst = await conns_service.create_connection(mock_session, tenant, conn_in)

        # Verify status is provisioning_cert (verified instantly!)
        assert conn.status == "provisioning_cert"
        assert conn.verified_at is not None
        assert "ownership verified instantly" in conn.status_detail
