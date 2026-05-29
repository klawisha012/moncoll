"""Subcatalog shape tests for crowdsec_runner.

We do NOT fire scenarios in unit tests (that needs a live Angie + CrowdSec).
This locks in the contract the frontend depends on: id/scenario/description/
burst_size for every entry.
"""

from __future__ import annotations

import pytest

from src.tests.crowdsec_runner import SCENARIO_CATALOG, _find_scenario, list_scenarios


def test_list_scenarios_non_empty():
    scenarios = list_scenarios()
    assert isinstance(scenarios, list) and scenarios


@pytest.mark.parametrize("entry", list_scenarios())
def test_list_scenarios_entry_shape(entry):
    """Each subcatalog entry must carry the fields the frontend renders."""
    assert set(entry.keys()) >= {"id", "category", "scenario", "description", "burst_size"}
    assert isinstance(entry["id"], str) and entry["id"].startswith("crowdsec.")
    assert isinstance(entry["category"], str) and entry["category"] in {"recon", "crawl", "exploit", "traversal"}
    assert isinstance(entry["scenario"], str) and "/" in entry["scenario"]
    assert isinstance(entry["description"], str) and entry["description"]
    assert isinstance(entry["burst_size"], int) and entry["burst_size"] > 0



def test_list_scenarios_ids_are_unique():
    ids = [e["id"] for e in list_scenarios()]
    assert len(ids) == len(set(ids)), f"duplicate scenario ids: {ids}"


def test_burst_size_matches_paths_length():
    """burst_size is computed from len(paths) — wire-up regression guard."""
    by_id = {s["id"]: s for s in SCENARIO_CATALOG}
    for view in list_scenarios():
        assert view["burst_size"] == len(by_id[view["id"]]["paths"])


def test_find_scenario_hit_and_miss():
    known_id = SCENARIO_CATALOG[0]["id"]
    assert _find_scenario(known_id) is SCENARIO_CATALOG[0]
    assert _find_scenario("crowdsec.does-not-exist") is None


def test_scenario_paths_are_relative():
    """A scenario path that escapes to an absolute URL would bypass the WAF."""
    for s in SCENARIO_CATALOG:
        for p in s["paths"]:
            assert p.startswith("/"), f"non-relative path in {s['id']}: {p}"
            assert "://" not in p, f"absolute URL in {s['id']}: {p}"


@pytest.mark.asyncio
async def test_run_scenario_passes_connection_id_to_add_decision():
    from unittest.mock import patch, AsyncMock, MagicMock
    from src.tests.crowdsec_runner import run_scenario
    from src.crowdsec.schemas import DecisionCreate

    # Mock decisions before/after
    mock_get_decisions = MagicMock(return_value=[])
    mock_add_decision = MagicMock(return_value={"success": True})

    # Mock httpx AsyncClient
    class FakeAsyncClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        async def request(self, *args, **kwargs):
            return MagicMock()

    with patch("src.tests.crowdsec_runner.crowdsec_service.get_decisions", mock_get_decisions), \
         patch("src.tests.crowdsec_runner.crowdsec_service.add_decision", mock_add_decision), \
         patch("src.tests.crowdsec_runner.httpx.AsyncClient", return_value=FakeAsyncClient()), \
         patch("src.tests.crowdsec_runner.asyncio.sleep", AsyncMock()):
        
        await run_scenario("crowdsec.http-probing", ip="1.2.3.4", connection_id=456)

    mock_add_decision.assert_called_once()
    decision_arg = mock_add_decision.call_args[0][0]
    assert isinstance(decision_arg, DecisionCreate)
    assert decision_arg.ip == "1.2.3.4"
    assert decision_arg.connection_ids == [456]

