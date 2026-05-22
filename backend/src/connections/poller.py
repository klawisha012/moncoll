"""Background DNS poller for the domain-only connection lifecycle.

State transitions handled here (spec §3):

  pending_verification → pending_dns       (TXT _waf-verify.<domain> seen)
  pending_dns          → provisioning_cert (A(domain) ⊇ {EDGE_IPV4})
  provisioning_cert    → active            (ACME succeeded)
  provisioning_cert    → pending_dns       (ACME failed, retries left)
  provisioning_cert    → error             (acme_retry_count >= MAX_RETRIES)

Concurrency: rows are processed inside an asyncio.Semaphore(SEM_LIMIT) so a
sudden burst of N connections cannot exhaust the event loop's resolver/CPU
budget (spec §1 issue 4). Each row's next_poll_at honours its DNS TTL — we
never re-resolve a 24-hour-TTL record every 60s.

Wired into FastAPI's lifespan in main.py.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import get_sessionmaker
from ..db.models import Connection
from . import acme, angie_config, dns

logger = logging.getLogger(__name__)

TICK_SECONDS = int(os.environ.get("WAF_POLLER_TICK_SECONDS", "60"))
SEM_LIMIT = int(os.environ.get("WAF_POLLER_CONCURRENCY", "20"))
EDGE_IPV4 = (os.environ.get("WAF_EDGE_IPV4") or "").strip()

_SEM = asyncio.Semaphore(SEM_LIMIT)


def _now() -> datetime:
    return datetime.now(UTC)


async def _select_due_rows(session: AsyncSession) -> list[Connection]:
    """Rows enabled, not 'active' (no need to poll active rows hot), and due."""
    now = _now()
    result = await session.execute(
        select(Connection).where(
            Connection.enabled.is_(True),
            Connection.status.in_(
                ("pending_verification", "pending_dns", "provisioning_cert", "error")
            ),
        )
    )
    rows: list[Connection] = []
    for row in result.scalars().all():
        if row.next_poll_at is None or row.next_poll_at <= now:
            rows.append(row)
    return rows


def _bump_poll(row: Connection, ttl_seconds: int | None = None) -> None:
    """Set next_poll_at = max(60s, dns_ttl) so we honour TTL while keeping a floor."""
    delay = max(TICK_SECONDS, ttl_seconds or row.dns_ttl_seconds or 60)
    row.next_poll_at = _now() + timedelta(seconds=delay)
    row.last_checked_at = _now()


async def _to_dict(row: Connection) -> dict:
    """Shape the row for angie_config.render — keeps render() pure."""
    return {
        "id": row.id,
        "name": row.name,
        "domain": row.domain,
        "origin_hosts": list(row.origin_hosts or []),
        "origin_port": row.origin_port,
        "origin_tls_mode": row.origin_tls_mode,
        "status": row.status,
        "http_versions": row.http_versions,
        "compression_algo": row.compression_algo,
        "ssl_cert_path": row.ssl_cert_path,
        "ssl_key_path": row.ssl_key_path,
    }


async def _tick_verification(row: Connection) -> None:
    found = await dns.verify_txt_token(row.domain, row.verify_token)
    if found:
        row.status = "pending_dns"
        row.verified_at = _now()
        row.status_detail = "Domain ownership verified."
        logger.info("Conn %d: TXT verified, status=pending_dns", row.id)
    else:
        row.status_detail = "Waiting for TXT _waf-verify record to propagate."


async def _tick_pending_dns(row: Connection) -> None:
    if not EDGE_IPV4:
        row.status = "error"
        row.status_detail = "WAF_EDGE_IPV4 env var not set; cannot detect DNS flip."
        return
    try:
        ips, ttl = await dns.resolve_a(row.domain)
    except dns.DnsResolutionError as exc:
        row.status_detail = f"DNS lookup: {exc}"
        return
    row.dns_ttl_seconds = ttl
    if EDGE_IPV4 in ips:
        row.status = "provisioning_cert"
        row.status_detail = "DNS now points to WAF edge; issuing certificate."
        logger.info("Conn %d: DNS flipped to edge, requesting cert", row.id)
    else:
        row.status_detail = f"A-record points to {','.join(ips)}; expecting {EDGE_IPV4}."


async def _tick_provisioning(row: Connection) -> None:
    # Throttle: if backoff window hasn't elapsed, no-op.
    if row.acme_next_retry_at and row.acme_next_retry_at > _now():
        return
    result = await asyncio.to_thread(acme.trigger, row.id, row.domain)
    if result.success:
        row.ssl_cert_path = result.cert_path
        row.ssl_key_path = result.key_path
        row.status = "active"
        row.status_detail = "Certificate issued."
        row.acme_retry_count = 0
        row.acme_next_retry_at = None
        logger.info("Conn %d: ACME succeeded, status=active", row.id)
    else:
        row.acme_retry_count += 1
        row.status_detail = f"ACME failed: {result.message}"
        if row.acme_retry_count >= acme.MAX_RETRIES:
            # ACME exhausted — fall back to self-signed cert so the proxy
            # still works. The operator sees the self-signed status_detail
            # and can manually re-probe later when the upstream issue is
            # fixed; the row's acme_retry_count gets reset on any
            # subsequent successful real-ACME via probe.
            logger.warning(
                "Conn %d: ACME exhausted retries — falling back to self-signed cert",
                row.id,
            )
            fb = await asyncio.to_thread(acme.fallback_self_signed, row.id, row.domain)
            if fb.success:
                row.ssl_cert_path = fb.cert_path
                row.ssl_key_path = fb.key_path
                row.status = "active"
                row.status_detail = fb.message
                row.acme_next_retry_at = None
            else:
                row.status = "error"
                row.acme_next_retry_at = None
                row.status_detail = f"ACME and self-signed both failed: {fb.message}"
        else:
            row.status = "pending_dns"
            row.acme_next_retry_at = acme.schedule_next_retry(row.acme_retry_count)


async def _process_one(row_id: int) -> None:
    """Re-fetch row under its own session so polls don't share transactions."""
    async with _SEM:
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            row = await session.get(Connection, row_id)
            if row is None or not row.enabled:
                return
            prev_status = row.status
            try:
                if row.status == "pending_verification":
                    await _tick_verification(row)
                elif row.status in ("pending_dns", "error"):
                    await _tick_pending_dns(row)
                elif row.status == "provisioning_cert":
                    await _tick_provisioning(row)
            except Exception as exc:
                logger.exception("Conn %d poller tick failed: %s", row_id, exc)
                row.status_detail = f"Poller error: {exc}"
            _bump_poll(row)
            await session.commit()

            # If status flipped, rewrite the Angie config so the upstream + cert
            # paths reflect reality. The reload itself is the orchestrator's
            # concern (service.py / lifespan trigger), not the poller's.
            if row.status != prev_status:
                try:
                    angie_config.write_config(await _to_dict(row))
                except Exception:
                    logger.exception("Conn %d: failed to write Angie config", row_id)


async def tick_once() -> int:
    """Run one poll iteration; return number of rows touched (for tests)."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        rows = await _select_due_rows(session)
    if not rows:
        return 0
    await asyncio.gather(*(_process_one(r.id) for r in rows), return_exceptions=True)
    return len(rows)


async def run_forever(stop_event: asyncio.Event) -> None:
    """Long-running task. Wakes every TICK_SECONDS; exits when *stop_event* is set."""
    logger.info(
        "Connections poller starting (tick=%ds, concurrency=%d, edge_ipv4=%s)",
        TICK_SECONDS,
        SEM_LIMIT,
        EDGE_IPV4 or "<unset>",
    )
    while not stop_event.is_set():
        try:
            count = await tick_once()
            if count:
                logger.debug("Poller tick: processed %d rows", count)
        except Exception:
            logger.exception("Poller tick crashed; sleeping and continuing")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=TICK_SECONDS)
        except asyncio.TimeoutError:
            pass
    logger.info("Connections poller stopped")
