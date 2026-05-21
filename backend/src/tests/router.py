"""Admin-only Tests router.

Routes:
- GET  /api/tests/catalog     → catalog manifest
- POST /api/tests/run         → fire one test, return marker + classification

Admin authentication is applied at the app-include level in
``backend/src/main.py``. The router itself only adds an in-process rate
limit (1 req/sec per admin) on the heavy POST endpoint.
"""

from __future__ import annotations

import logging
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.dependencies import require_admin
from ..db.models import User
from ..db.session import get_session
from . import crowdsec_runner
from . import service as test_service
from .manifest import load_catalog
from .schemas import Catalog, CrowdsecRunResult, RunRequest, RunResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tests", tags=["tests"])


# ── In-process rate limit ─────────────────────────────────────────────
# 1 request per second per admin user. The frontend already disables Run
# while polling, so this primarily protects against double-click double-fire
# and accidental scripted abuse from a logged-in admin. A multi-worker
# uvicorn deploy would bypass this; that's documented in the design doc and
# acceptable for pre-product. Redis-backed version is a v2.
_RATE_LIMIT_INTERVAL_S = 1.0
_rate_lock = threading.Lock()
_rate_last: dict[int, float] = {}


def _rate_limit(user: User) -> User:
    now = time.monotonic()
    with _rate_lock:
        last = _rate_last.get(user.id, 0.0)
        if now - last < _RATE_LIMIT_INTERVAL_S:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limit: 1 test per second",
            )
        _rate_last[user.id] = now
    return user


# ── Routes ────────────────────────────────────────────────────────────


@router.get("/catalog", response_model=Catalog)
async def get_catalog(_: User = Depends(require_admin)) -> Catalog:
    """Return the build-time test catalog. Returns empty catalog if missing."""
    return load_catalog()


@router.post("/run", response_model=RunResult)
async def run_test_endpoint(
    body: RunRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin),
) -> RunResult:
    """Run one test from the catalog and classify the result.

    Returns synchronously — the runner fires the HTTP attack, polls the WAF
    audit log for up to 5s, then returns a 4-status classification.
    """
    _rate_limit(user)

    test = test_service.find_test(body.test_id)
    if test is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown test_id: {body.test_id}",
        )

    return await test_service.run_test(session, body)


# ── CrowdSec subcatalog ──────────────────────────────────────────────


@router.get("/crowdsec/catalog")
async def get_crowdsec_catalog(_: User = Depends(require_admin)) -> dict:
    """Return the CrowdSec scenario subcatalog."""
    return {"scenarios": crowdsec_runner.list_scenarios()}


@router.post("/crowdsec/run", response_model=CrowdsecRunResult)
async def run_crowdsec_scenario(
    body: dict,
    user: User = Depends(require_admin),
) -> CrowdsecRunResult:
    """Fire a CrowdSec scenario burst and return the decisions delta."""
    _rate_limit(user)

    scenario_id = str(body.get("scenario_id", "")).strip()
    if not scenario_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scenario_id required",
        )

    return await crowdsec_runner.run_scenario(scenario_id)
