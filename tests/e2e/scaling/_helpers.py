"""Helpers + env config for horizontal-scaling e2e (specs/001-horizontal-scaling).

Plain module (not conftest) so tests and conftest can import it without tripping
pytest's conftest double-import. Env:

    WAF_API_URL              backend API base (default http://localhost)
    WAF_EDGE_METRICS_URLS    comma-separated edge /metrics endpoints (>=2)
    WAF_BACKEND_METRICS_URL  backend /metrics (state_published_generation); optional
    WAF_CONVERGE_BUDGET_S    convergence budget, seconds (default 30 — FR-003/SC-002)

The convergence poller is real: it scrapes Prometheus text and waits for every
edge's applied_generation to reach the published target — the externally
observable definition of "converged".
"""

from __future__ import annotations

import os
import time

import pytest
import requests

API_URL = os.environ.get("WAF_API_URL", "http://localhost")
ADMIN_USER = os.environ.get("WAF_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("WAF_ADMIN_PASS", "admin")
EDGE_METRICS = [u.strip() for u in os.environ.get("WAF_EDGE_METRICS_URLS", "").split(",") if u.strip()]
BACKEND_METRICS = os.environ.get("WAF_BACKEND_METRICS_URL", "").strip()
CONVERGE_BUDGET_S = float(os.environ.get("WAF_CONVERGE_BUDGET_S", "30"))

APPLIED = "edge_sync_applied_generation"
PUBLISHED = "state_published_generation"


def metric_value(text: str, name: str) -> float | None:
    """Parse a single unlabelled gauge/counter value from Prometheus text."""
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith(name + " ") or line.startswith(name + "{"):
            try:
                return float(line.rsplit(" ", 1)[1])
            except (ValueError, IndexError):
                return None
    return None


def scrape(url: str, name: str) -> float | None:
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException:
        return None
    return metric_value(r.text, name) if r.status_code == 200 else None


def published_generation() -> float | None:
    return scrape(BACKEND_METRICS, PUBLISHED) if BACKEND_METRICS else None


def wait_converged(edge_urls: list[str], target: float | None = None,
                   budget_s: float = CONVERGE_BUDGET_S) -> float:
    """Poll until every edge's applied_generation is equal and >= target within
    budget. target=None → use the backend's published generation, else the max
    observed. Fails with the last snapshot if the budget elapses."""
    deadline = time.time() + budget_s
    last: dict[str, float | None] = {}
    while time.time() < deadline:
        applied = [scrape(u, APPLIED) for u in edge_urls]
        last = dict(zip(edge_urls, applied))
        if all(a is not None for a in applied):
            tgt = target if target is not None else (published_generation() or max(applied))
            if len(set(applied)) == 1 and applied[0] >= tgt:
                return applied[0]
        time.sleep(1)
    pytest.fail(f"edges did not converge within {budget_s}s; last={last} target={target}")
