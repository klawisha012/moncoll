"""Fixtures for horizontal-scaling e2e. Shared helpers live in _helpers.py.

When the s3-mode stack / env is absent (e.g. ordinary local-mode CI) every test
skips cleanly, so collection stays green.
"""

from __future__ import annotations

import pytest
import requests

from ._helpers import (
    ADMIN_PASS,
    ADMIN_USER,
    API_URL,
    APPLIED,
    EDGE_METRICS,
    scrape,
)


@pytest.fixture(scope="session")
def edges() -> list[str]:
    """>=2 reachable edge metrics endpoints, else skip the whole module."""
    if len(EDGE_METRICS) < 2:
        pytest.skip("set WAF_EDGE_METRICS_URLS to >=2 edge /metrics endpoints for scaling e2e")
    for u in EDGE_METRICS:
        if scrape(u, APPLIED) is None:
            pytest.skip(f"edge metrics not reachable: {u}")
    return EDGE_METRICS


@pytest.fixture(scope="module")
def session() -> requests.Session:
    s = requests.Session()
    try:
        resp = s.post(f"{API_URL}/api/auth/login",
                      json={"username": ADMIN_USER, "password": ADMIN_PASS}, timeout=10)
    except requests.RequestException as e:
        pytest.skip(f"API unreachable at {API_URL}: {e}")
    if resp.status_code != 200:
        pytest.skip(f"Could not authenticate against {API_URL} ({resp.status_code})")
    yield s
    s.close()
