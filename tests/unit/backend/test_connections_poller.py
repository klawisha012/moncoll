"""Unit tests for connections.poller — state transitions + TTL respect.

Poller logic is tested at the helper level (_bump_poll, _tick_*) since the
end-to-end async lifecycle is exercised in e2e. These tests catch most
regressions in state-machine wiring without needing a real DB.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.connections import poller


def _fake_row(**overrides):
    """Duck-typed Connection row — only the fields the poller touches."""
    defaults = {
        "id": 1,
        "tenant_id": 1,
        "name": "acme",
        "domain": "acme.com",
        "origin_hosts": ["1.1.1.1"],
        "origin_port": 443,
        "origin_tls_mode": "strict",
        "verify_token": "tok-abc",
        "status": "pending_verification",
        "status_detail": None,
        "dns_ttl_seconds": 60,
        "acme_retry_count": 0,
        "acme_next_retry_at": None,
        "verified_at": None,
        "next_poll_at": None,
        "last_checked_at": None,
        "ssl_cert_path": None,
        "ssl_key_path": None,
        "http_versions": "h1,h2",
        "compression_algo": "auto",
        "enabled": True,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ── _bump_poll: TTL respect ──────────────────────────────────────────────────


def test_bump_poll_floors_at_tick_seconds():
    row = _fake_row(dns_ttl_seconds=10)  # tiny TTL
    poller._bump_poll(row)
    delta = (row.next_poll_at - datetime.now(UTC)).total_seconds()
    # max(TICK_SECONDS, 10) → TICK_SECONDS (60 default)
    assert delta >= poller.TICK_SECONDS - 1


def test_bump_poll_honors_long_ttl():
    row = _fake_row(dns_ttl_seconds=3600)
    poller._bump_poll(row)
    delta = (row.next_poll_at - datetime.now(UTC)).total_seconds()
    assert delta >= 3590


def test_bump_poll_uses_explicit_override():
    row = _fake_row(dns_ttl_seconds=60)
    poller._bump_poll(row, ttl_seconds=900)
    delta = (row.next_poll_at - datetime.now(UTC)).total_seconds()
    assert delta >= 890


# ── _tick_verification: TXT seen → pending_dns ───────────────────────────────


@pytest.mark.asyncio
async def test_tick_verification_advances_on_txt_match():
    row = _fake_row(status="pending_verification", verify_token="tok-abc")
    with patch.object(poller.dns, "verify_txt_token", new=AsyncMock(return_value=True)):
        await poller._tick_verification(row)
    assert row.status == "pending_dns"
    assert row.verified_at is not None


@pytest.mark.asyncio
async def test_tick_verification_no_match_stays_pending():
    row = _fake_row(status="pending_verification")
    with patch.object(poller.dns, "verify_txt_token", new=AsyncMock(return_value=False)):
        await poller._tick_verification(row)
    assert row.status == "pending_verification"
    assert row.verified_at is None
    assert "propagat" in (row.status_detail or "")


# ── _tick_pending_dns: A == edge → provisioning_cert ─────────────────────────


@pytest.mark.asyncio
async def test_tick_pending_dns_detects_flip():
    row = _fake_row(status="pending_dns")
    with patch.object(poller, "EDGE_IPV4", "203.0.113.5"):
        with patch.object(poller.dns, "resolve_a", new=AsyncMock(return_value=(["203.0.113.5"], 300))):
            await poller._tick_pending_dns(row)
    assert row.status == "provisioning_cert"
    assert row.dns_ttl_seconds == 300


@pytest.mark.asyncio
async def test_tick_pending_dns_no_flip_keeps_status():
    row = _fake_row(status="pending_dns")
    with patch.object(poller, "EDGE_IPV4", "203.0.113.5"):
        with patch.object(poller.dns, "resolve_a", new=AsyncMock(return_value=(["198.51.100.7"], 60))):
            await poller._tick_pending_dns(row)
    assert row.status == "pending_dns"
    assert "expecting 203.0.113.5" in (row.status_detail or "")


@pytest.mark.asyncio
async def test_tick_pending_dns_no_edge_ipv4_errors():
    """Without WAF_EDGE_IPV4 we can't tell when DNS flips — the row should
    be flagged as error so the operator notices the missing env var."""
    row = _fake_row(status="pending_dns")
    with patch.object(poller, "EDGE_IPV4", ""):
        await poller._tick_pending_dns(row)
    assert row.status == "error"
    assert "WAF_EDGE_IPV4" in (row.status_detail or "")


# ── _tick_provisioning: ACME outcome ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_provisioning_success_activates():
    row = _fake_row(status="provisioning_cert")
    fake = poller.acme.AcmeResult(
        success=True, cert_path="/tls/a.crt", key_path="/tls/a.key"
    )
    with patch.object(poller.acme, "trigger", return_value=fake):
        await poller._tick_provisioning(row)
    assert row.status == "active"
    assert row.ssl_cert_path == "/tls/a.crt"
    assert row.ssl_key_path == "/tls/a.key"
    assert row.acme_retry_count == 0


@pytest.mark.asyncio
async def test_tick_provisioning_failure_schedules_retry():
    row = _fake_row(status="provisioning_cert", acme_retry_count=0)
    fake = poller.acme.AcmeResult(success=False, message="rate limit")
    with patch.object(poller.acme, "trigger", return_value=fake):
        await poller._tick_provisioning(row)
    assert row.status == "pending_dns"  # bounce back to DNS check
    assert row.acme_retry_count == 1
    assert row.acme_next_retry_at is not None


@pytest.mark.asyncio
async def test_tick_provisioning_exhausts_retries_falls_back_to_self_signed():
    """When ACME has burned through MAX_RETRIES and we are in lenient TLS mode,
    we generate a self-signed cert so the proxy still works. The row
    becomes active, not error, with a status_detail flagging the fallback."""
    row = _fake_row(
        status="provisioning_cert",
        acme_retry_count=poller.acme.MAX_RETRIES - 1,
        origin_tls_mode="lenient",
    )
    acme_fail = poller.acme.AcmeResult(success=False, message="failed again")
    self_signed_ok = poller.acme.AcmeResult(
        success=True,
        cert_path="/tls/ss.crt",
        key_path="/tls/ss.key",
        message="Self-signed cert (ACME unreachable from this network).",
    )
    with patch.object(poller.acme, "trigger", return_value=acme_fail), \
         patch.object(poller.acme, "fallback_self_signed", return_value=self_signed_ok):
        await poller._tick_provisioning(row)
    assert row.status == "active"
    assert row.ssl_cert_path == "/tls/ss.crt"
    assert row.ssl_key_path == "/tls/ss.key"
    assert "Self-signed" in (row.status_detail or "")


@pytest.mark.asyncio
async def test_tick_provisioning_exhausts_retries_strict_mode_goes_error():
    """When ACME has burned through MAX_RETRIES and we are in strict TLS mode,
    we do NOT generate a self-signed cert — it fails straight to error."""
    row = _fake_row(
        status="provisioning_cert",
        acme_retry_count=poller.acme.MAX_RETRIES - 1,
        origin_tls_mode="strict",
    )
    acme_fail = poller.acme.AcmeResult(success=False, message="failed again")
    with patch.object(poller.acme, "trigger", return_value=acme_fail):
        await poller._tick_provisioning(row)
    assert row.status == "error"
    assert "Strict TLS mode prevents self-signed fallback" in (row.status_detail or "")


@pytest.mark.asyncio
async def test_tick_provisioning_self_signed_also_fails_goes_error():
    row = _fake_row(
        status="provisioning_cert",
        acme_retry_count=poller.acme.MAX_RETRIES - 1,
        origin_tls_mode="lenient",
    )
    acme_fail = poller.acme.AcmeResult(success=False, message="ACME nope")
    ss_fail = poller.acme.AcmeResult(success=False, message="openssl missing")
    with patch.object(poller.acme, "trigger", return_value=acme_fail), \
         patch.object(poller.acme, "fallback_self_signed", return_value=ss_fail):
        await poller._tick_provisioning(row)
    assert row.status == "error"
    assert "both failed" in (row.status_detail or "")


@pytest.mark.asyncio
async def test_tick_provisioning_respects_backoff_window():
    """If acme_next_retry_at is in the future, the tick should no-op."""
    future = datetime.now(UTC) + timedelta(minutes=10)
    row = _fake_row(status="provisioning_cert", acme_next_retry_at=future)
    with patch.object(poller.acme, "trigger") as mock_trigger:
        await poller._tick_provisioning(row)
        mock_trigger.assert_not_called()
    assert row.status == "provisioning_cert"  # unchanged
