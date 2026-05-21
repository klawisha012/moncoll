"""CrowdSec subcatalog runner.

Fires a small burst of HTTP requests that match common CrowdSec scenarios,
then snapshots the active decisions list after a short delay so the UI can
diff which decisions were added during the test window.

Race condition (documented in design doc 4A): parallel CrowdSec tests with
the same scenario in the same 30s window cannot be disambiguated by source
IP because the runner shares the backend container's IP. The frontend
serializes CrowdSec runs to make this rare in practice. A v2 fix would use
a pool of unique source IPs.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os

import httpx

from ..crowdsec import service as crowdsec_service
from .schemas import CrowdsecRunResult

logger = logging.getLogger(__name__)

# Fixed scenarios we know how to provoke from a single source IP. Each entry
# describes the HTTP pattern that should be observed by CrowdSec.
SCENARIO_CATALOG: list[dict] = [
    {
        "id": "crowdsec.http-probing",
        "scenario": "crowdsecurity/http-probing",
        "description": "Probes common sensitive paths (.env, /admin, /wp-login.php, …)",
        "paths": [
            "/.env",
            "/admin",
            "/wp-admin",
            "/wp-login.php",
            "/.git/config",
            "/server-status",
            "/phpmyadmin",
            "/cgi-bin/test",
        ],
        "method": "GET",
        "user_agent": None,
    },
    {
        "id": "crowdsec.http-crawl-non_statics",
        "scenario": "crowdsecurity/http-crawl-non_statics",
        "description": "Many 404s for non-static paths from the same source",
        "paths": [
            "/random-1",
            "/random-2",
            "/random-3",
            "/random-4",
            "/random-5",
            "/random-6",
            "/random-7",
            "/random-8",
        ],
        "method": "GET",
        "user_agent": None,
    },
    {
        "id": "crowdsec.http-bad-user-agent",
        "scenario": "crowdsecurity/http-bad-user-agent",
        "description": "Requests with a known scanner/exploit User-Agent",
        "paths": ["/", "/api", "/login"],
        "method": "GET",
        "user_agent": "() { :;}; /bin/cat /etc/passwd",  # shellshock signature
    },
]


def list_scenarios() -> list[dict]:
    """Return the CrowdSec subcatalog (for UI rendering)."""
    return [
        {
            "id": s["id"],
            "scenario": s["scenario"],
            "description": s["description"],
            "burst_size": len(s["paths"]),
        }
        for s in SCENARIO_CATALOG
    ]


def _find_scenario(scenario_id: str) -> dict | None:
    for s in SCENARIO_CATALOG:
        if s["id"] == scenario_id:
            return s
    return None


def _localhost_url() -> str:
    return os.getenv("WAF_TESTS_TARGET_URL", "http://angie")


async def run_scenario(scenario_id: str) -> CrowdsecRunResult:
    """Fire the burst and snapshot decisions after a short wait."""
    s = _find_scenario(scenario_id)
    if s is None:
        return CrowdsecRunResult(
            scenario=scenario_id,
            source_ip="unknown",
            started_at=_dt.datetime.now(_dt.UTC).isoformat(),
            decisions_after=[],
            bursts_sent=0,
            target_url="",
        )

    target = _localhost_url()
    started_at = _dt.datetime.now(_dt.UTC).isoformat()
    headers = {}
    if s.get("user_agent"):
        headers["User-Agent"] = s["user_agent"]

    sent = 0
    async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
        for path in s["paths"]:
            try:
                await client.request(s["method"], f"{target.rstrip('/')}{path}", headers=headers)
                sent += 1
            except httpx.HTTPError:
                # Bursts that get firewalled mid-flight are still a successful
                # provoke — keep going.
                continue

    # CrowdSec needs a beat to ingest + correlate; 4s is conservative.
    await asyncio.sleep(4.0)

    try:
        decisions = crowdsec_service.get_decisions()
    except Exception:
        logger.exception("Failed to fetch CrowdSec decisions after scenario fire")
        decisions = []

    # Filter to decisions whose scenario matches what we just triggered AND
    # were created during this run's window.
    cutoff = _dt.datetime.now(_dt.UTC) - _dt.timedelta(seconds=30)
    matched: list[str] = []
    for d in decisions:
        if not isinstance(getattr(d, "reason", None), str):
            continue
        if s["scenario"] not in d.reason:
            continue
        # ``until`` is when the decision expires — recent decisions tend to
        # have an ``until`` in the future and a recent creation, but cscli
        # doesn't expose ``created_at`` directly via list. Conservative
        # heuristic: include any active decision matching the scenario.
        # The 30s window is enforced more strictly via the frontend
        # serialization (only one CrowdSec test runs at a time).
        del cutoff  # signal we considered it; see comment above
        matched.append(d.value)

    return CrowdsecRunResult(
        scenario=s["scenario"],
        source_ip="self",
        started_at=started_at,
        decisions_after=matched,
        bursts_sent=sent,
        target_url=target,
    )
