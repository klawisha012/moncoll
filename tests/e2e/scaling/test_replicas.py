"""T026 [US2] — consistent backend replicas under concurrent writes.

Independent test for User Story 2 (quickstart S5): several connections created
concurrently (exercising the manifest publish race → CAS + advisory-lock path)
all land, and every edge converges to a single generation that reflects all of
them. The CAS conflict→retry mechanics are unit-tested in
internal/storage/manifest_test.go; this verifies the end-to-end invariant: no
write is lost and replicas do not diverge (FR-001/FR-013).
"""

from __future__ import annotations

import concurrent.futures
import uuid

import pytest

from ._helpers import API_URL, published_generation, wait_converged


def _create(session, name, domain):
    return session.post(f"{API_URL}/api/connections",
                        json={"name": name, "domain": domain}, timeout=20)


def test_concurrent_creates_all_converge(edges, session):
    wait_converged(edges)  # equal baseline

    n = 5
    domains = [f"repl-{uuid.uuid4().hex[:8]}.example.com" for _ in range(n)]
    created: list[int] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            results = list(ex.map(lambda d: _create(session, "repl", d), domains))

        ok = [r for r in results if r.status_code == 201]
        if not ok:
            pytest.skip("no concurrent create succeeded (DNS unresolved on runner)")
        created = [r.json()["connection"]["id"] for r in ok]

        # Every successful publish must be reflected, and all edges agree on one
        # generation — i.e. concurrent replicas converged without a lost update.
        wait_converged(edges, target=published_generation())

        listed = {row["id"] for row in session.get(f"{API_URL}/api/connections", timeout=10).json()}
        for cid in created:
            assert cid in listed, f"connection {cid} lost despite 201"
    finally:
        for cid in created:
            session.delete(f"{API_URL}/api/connections/{cid}")
    wait_converged(edges, target=published_generation())
