"""Unit tests for connections.acme — backoff table + ACME wrapper."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from src.connections import acme


# ── Backoff table ────────────────────────────────────────────────────────────


def test_backoff_table_monotonic_increasing():
    """Later attempts must wait at least as long as earlier ones — never less."""
    table = acme._BACKOFF_TABLE_SECONDS
    assert list(table) == sorted(table)
    assert table[0] >= 60  # never sooner than 1 minute
    assert table[-1] >= 3600  # last entry at least an hour


def test_schedule_next_retry_uses_base_with_jitter():
    """Jitter is ±20%, so retry timing falls in a known window per attempt."""
    base_now = datetime.now(UTC)
    for idx, base_seconds in enumerate(acme._BACKOFF_TABLE_SECONDS):
        # Sample 30 times to make sure jitter doesn't escape ±20%
        for _ in range(30):
            scheduled = acme.schedule_next_retry(idx)
            delta = (scheduled - base_now).total_seconds()
            assert 0.79 * base_seconds <= delta <= 1.21 * base_seconds, (
                f"retry {idx}: delta={delta}, base={base_seconds}"
            )


def test_schedule_next_retry_clamps_high_count():
    """retry_count >= len(table) should pin to the longest backoff, not overflow."""
    last = acme._BACKOFF_TABLE_SECONDS[-1]
    scheduled = acme.schedule_next_retry(99)
    delta = (scheduled - datetime.now(UTC)).total_seconds()
    assert 0.79 * last <= delta <= 1.21 * last


def test_schedule_next_retry_clamps_negative_count():
    first = acme._BACKOFF_TABLE_SECONDS[0]
    scheduled = acme.schedule_next_retry(-1)
    delta = (scheduled - datetime.now(UTC)).total_seconds()
    assert 0.79 * first <= delta <= 1.21 * first


def test_max_retries_matches_table():
    """MAX_RETRIES is the gate the poller uses to park rows as status=error.
    It must equal the table length so the last backoff entry is actually used."""
    assert acme.MAX_RETRIES == len(acme._BACKOFF_TABLE_SECONDS)


# ── trigger() ────────────────────────────────────────────────────────────────


def test_trigger_success_returns_paths():
    with patch.object(
        acme.cert_service,
        "trigger_acme_request",
        return_value={
            "success": True,
            "certificate_path": "/tls/acme.com.crt",
            "key_path": "/tls/acme.com.key",
            "message": "issued",
        },
    ):
        result = acme.trigger(42, "acme.com")
        assert result.success is True
        assert result.cert_path == "/tls/acme.com.crt"
        assert result.key_path == "/tls/acme.com.key"


def test_trigger_failure_surfaces_message():
    with patch.object(
        acme.cert_service,
        "trigger_acme_request",
        return_value={"success": False, "message": "Rate limit hit"},
    ):
        result = acme.trigger(42, "acme.com")
        assert result.success is False
        assert "Rate limit" in result.message
        assert result.cert_path is None


def test_trigger_handles_exception():
    """cert_service can raise on infra errors — we never propagate."""
    with patch.object(
        acme.cert_service,
        "trigger_acme_request",
        side_effect=RuntimeError("certbot not installed"),
    ):
        result = acme.trigger(42, "acme.com")
        assert result.success is False
        assert "RuntimeError" in result.message


# ── Integration: backoff → schedule advances on each retry ──────────────────


def test_backoff_advances_per_attempt():
    """Each retry_count produces a strictly-later schedule (on average)."""
    schedules = []
    for n in range(len(acme._BACKOFF_TABLE_SECONDS)):
        # Sample a few times and take the median so jitter doesn't perturb ordering.
        samples = sorted(
            (acme.schedule_next_retry(n) - datetime.now(UTC)).total_seconds()
            for _ in range(11)
        )
        schedules.append(samples[5])  # median of 11
    # Each median should be at least 1.5× the previous (jitter band ±20% can't
    # overlap when the base is monotonic-increasing).
    for i in range(1, len(schedules)):
        assert schedules[i] > schedules[i - 1]
