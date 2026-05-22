"""ACME orchestration with exponential backoff.

Thin wrapper over `certificates.service.trigger_acme_request` that adds the
retry state machine called out in spec §1 issue 4. cert_service stays single-
domain-list-friendly (it accepts `domains: list[str]`); we always pass
`[connection.domain]`.

Backoff table: 1m → 5m → 30m → 2h → 12h. ±20% jitter. Max 5 retries before
the row is parked in status='error' for manual /probe to clear.
"""

from __future__ import annotations

import logging
import random
from datetime import UTC, datetime, timedelta

from ..certificates import service as cert_service

logger = logging.getLogger(__name__)

# Seconds between attempts; idx == retry_count (0-based).
_BACKOFF_TABLE_SECONDS = (60, 300, 1800, 7200, 43200)
MAX_RETRIES = len(_BACKOFF_TABLE_SECONDS)


def schedule_next_retry(retry_count: int) -> datetime:
    """Return the UTC timestamp at which the *retry_count*-th retry should fire.

    Caller is responsible for clamping retry_count to MAX_RETRIES (above which
    the row should be transitioned to status='error' instead of re-scheduled).
    """
    idx = min(max(retry_count, 0), len(_BACKOFF_TABLE_SECONDS) - 1)
    base = _BACKOFF_TABLE_SECONDS[idx]
    jitter = base * random.uniform(-0.2, 0.2)
    return datetime.now(UTC) + timedelta(seconds=base + jitter)


class AcmeResult:
    """Discriminated union for trigger() outcomes."""

    __slots__ = ("success", "cert_path", "key_path", "message")

    def __init__(
        self,
        *,
        success: bool,
        cert_path: str | None = None,
        key_path: str | None = None,
        message: str = "",
    ) -> None:
        self.success = success
        self.cert_path = cert_path
        self.key_path = key_path
        self.message = message


def trigger(conn_id: int, domain: str) -> AcmeResult:
    """Single ACME attempt. Does NOT retry — that's the poller's job.

    On success: returns the cert/key paths cert_service wrote to disk.
    On failure: returns success=False with the underlying message; caller
    increments acme_retry_count and reschedules via schedule_next_retry.
    """
    try:
        raw = cert_service.trigger_acme_request(conn_id, [domain])
    except Exception as exc:  # cert_service may raise on infrastructure errors
        logger.exception("Conn %d: ACME request crashed", conn_id)
        return AcmeResult(success=False, message=f"{type(exc).__name__}: {exc}")
    if raw.get("success"):
        return AcmeResult(
            success=True,
            cert_path=raw.get("certificate_path"),
            key_path=raw.get("key_path"),
            message=raw.get("message") or "",
        )
    return AcmeResult(success=False, message=str(raw.get("message") or "ACME failed"))
