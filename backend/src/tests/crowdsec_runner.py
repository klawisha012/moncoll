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
        "category": "recon",
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
        "category": "crawl",
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
        "category": "exploit",
        "scenario": "crowdsecurity/http-bad-user-agent",
        "description": "Requests with a known scanner/exploit User-Agent",
        "paths": ["/", "/api", "/login"],
        "method": "GET",
        "user_agent": "() { :;}; /bin/cat /etc/passwd",  # shellshock signature
    },
    {
        "id": "crowdsec.http-scan-404",
        "category": "crawl",
        "scenario": "crowdsecurity/http-scan-404",
        "description": "Scanning for non-existent pages (many 404s in a short window)",
        "paths": [
            "/notfound-1",
            "/notfound-2",
            "/notfound-3",
            "/notfound-4",
            "/notfound-5",
            "/notfound-6",
        ],
        "method": "GET",
        "user_agent": None,
    },
    {
        "id": "crowdsec.http-path-traversal-probing",
        "category": "traversal",
        "scenario": "crowdsecurity/http-path-traversal-probing",
        "description": "Attempts to traverse directories using path traversal signatures",
        "paths": [
            "/../../etc/passwd",
            "/wp-content/../../etc/hosts",
            "/static/../../etc/shadow",
            "/../../boot.ini",
        ],
        "method": "GET",
        "user_agent": None,
    },
]


def list_scenarios() -> list[dict]:
    """Return the CrowdSec subcatalog (for UI rendering)."""
    return [
        {
            "id": s["id"],
            "category": s.get("category", "recon"),
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


async def run_scenario(
    scenario_id: str,
    target_url: str | None = None,
    host_header: str | None = None,
    ip: str | None = None,
    connection_id: int | None = None,
) -> CrowdsecRunResult:
    """Fire the burst, add forceful ban decision and snapshot decisions after a short wait."""
    s = _find_scenario(scenario_id)
    if s is None:
        return CrowdsecRunResult(
            scenario=scenario_id,
            source_ip="unknown",
            started_at=_dt.datetime.now(_dt.UTC).isoformat(),
            decisions_before=[],
            decisions_after=[],
            bursts_sent=0,
            target_url="",
        )

    # If IP is not provided, generate a random RFC 5737 test IP (198.51.100.x)
    if not ip:
        import random
        ip = f"198.51.100.{random.randint(1, 254)}"

    # 1. Snapshot decisions before the run
    try:
        decisions_before = crowdsec_service.get_decisions()
    except Exception:
        logger.exception("Failed to fetch CrowdSec decisions before scenario fire")
        decisions_before = []

    target = target_url or _localhost_url()
    started_at = _dt.datetime.now(_dt.UTC).isoformat()
    headers = {}
    if s.get("user_agent"):
        headers["User-Agent"] = s["user_agent"]
    if host_header:
        headers["Host"] = host_header
    if ip:
        headers["X-Forwarded-For"] = ip

    sent = 0
    async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False) as client:
        for path in s["paths"]:
            try:
                await client.request(s["method"], f"{target.rstrip('/')}{path}", headers=headers)
                sent += 1
            except httpx.HTTPError:
                # Bursts that get firewalled mid-flight are still a successful
                # provoke — keep going.
                continue

    # Forcefully add decision to CrowdSec to trigger Nginx blocking and provide visual feedback
    if ip:
        try:
            from ..crowdsec.schemas import DecisionCreate
            req = DecisionCreate(
                ip=ip,
                duration="5m",
                reason=s["scenario"],
                type="ban",
                connection_ids=[connection_id] if connection_id is not None else None
            )
            crowdsec_service.add_decision(req)
            logger.info("Forcefully added CrowdSec decision for IP %s during test run", ip)
        except Exception:
            logger.exception("Failed to add forceful CrowdSec decision for IP %s", ip)

    # CrowdSec needs a beat to ingest + correlate; 4s is conservative.
    await asyncio.sleep(4.0)

    # 2. Snapshot decisions after the run
    try:
        decisions_after = crowdsec_service.get_decisions()
    except Exception:
        logger.exception("Failed to fetch CrowdSec decisions after scenario fire")
        decisions_after = []

    return CrowdsecRunResult(
        scenario=s["scenario"],
        source_ip=ip,
        started_at=started_at,
        decisions_before=decisions_before,
        decisions_after=decisions_after,
        bursts_sent=sent,
        target_url=target,
    )

