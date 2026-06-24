"""T011 [US1] — two edge nodes converge on a new connection within the budget.

Independent test for User Story 1 (quickstart S1/S2): create a connection via the
API and assert both edges' applied_generation reaches the published generation
within WAF_CONVERGE_BUDGET_S (default 30s, FR-003/SC-002), i.e. both edges serve
the same per-tenant config + certificate.
"""

from __future__ import annotations

import uuid

import pytest

from ._helpers import API_URL, published_generation, wait_converged


def test_two_edges_converge_on_new_connection(edges, session):
    baseline = wait_converged(edges)  # all edges already equal before the change

    domain = f"scale-{uuid.uuid4().hex[:8]}.example.com"
    resp = session.post(f"{API_URL}/api/connections",
                        json={"name": "scale-converge", "domain": domain}, timeout=15)
    if resp.status_code == 422:
        pytest.skip("DNS for the test domain did not resolve on this runner")
    assert resp.status_code == 201, resp.text
    conn_id = resp.json()["connection"]["id"]

    try:
        gen = wait_converged(edges, target=published_generation())
        assert gen > baseline, "publishing a new connection must advance the applied generation"
    finally:
        session.delete(f"{API_URL}/api/connections/{conn_id}")

    # The delete is itself a generation; both edges must converge on it too.
    wait_converged(edges, target=published_generation())
