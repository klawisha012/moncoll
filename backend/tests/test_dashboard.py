import pytest


@pytest.mark.asyncio
async def test_get_metrics(client):
    resp = await client.get("/dashboard/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "totalRequests" in data
    assert "blockedAttacks" in data


@pytest.mark.asyncio
async def test_get_traffic(client):
    resp = await client.get("/dashboard/traffic")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0


@pytest.mark.asyncio
async def test_get_events(client):
    resp = await client.get("/dashboard/events")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_get_threat_origins(client):
    resp = await client.get("/dashboard/threat-origins")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
