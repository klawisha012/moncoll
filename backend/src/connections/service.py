"""CRUD orchestration for domain-only connections.

This module is the public surface for `router.py`. It validates input,
resolves origin, gates SSRF, persists rows, writes Angie configs, and
triggers reloads. The heavy lifting (DNS, Angie rendering, ACME, polling)
lives in the sibling modules — service.py is only orchestration.

State machine, schema, and decisions are documented in
`docs/superpowers/specs/2026-05-22-connections-domain-only-design.md`.
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import UTC, datetime

import docker
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Connection as ConnectionModel
from . import angie_config
from .dns import (
    DnsResolutionError,
    is_blocked_ip,
    resolve_a,
    validate_domain,
    verify_txt_token,
)
from .schemas import Connection, ConnectionCreate, ConnectionUpdate, VerifyInstructions

logger = logging.getLogger(__name__)

ANGIE_CONTAINER_NAME = "waf-angie-1"


def _edge_ipv4() -> str:
    return (os.environ.get("WAF_EDGE_IPV4") or "").strip()


def _now() -> datetime:
    return datetime.now(UTC)


def _to_dict(row: ConnectionModel) -> dict:
    return {
        "id": row.id,
        "user_id": row.user_id,
        "name": row.name,
        "domain": row.domain,
        "origin_hosts": list(row.origin_hosts or []),
        "origin_port": row.origin_port,
        "origin_tls_mode": row.origin_tls_mode,
        "verify_token": row.verify_token,
        "verified_at": row.verified_at,
        "status": row.status,
        "status_detail": row.status_detail,
        "acme_retry_count": row.acme_retry_count,
        "acme_next_retry_at": row.acme_next_retry_at,
        "next_poll_at": row.next_poll_at,
        "dns_ttl_seconds": row.dns_ttl_seconds,
        "last_checked_at": row.last_checked_at,
        "http_versions": row.http_versions,
        "compression_algo": row.compression_algo,
        "enabled": row.enabled,
        "ssl_cert_path": row.ssl_cert_path,
        "ssl_key_path": row.ssl_key_path,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _reload_angie() -> None:
    """Best-effort `angie -s reload`. Errors are logged, never raised."""
    try:
        client = docker.from_env()
        container = client.containers.get(ANGIE_CONTAINER_NAME)
        code, out = container.exec_run(["angie", "-t"])
        if code != 0:
            logger.warning("Angie config test failed: %s", out.decode(errors="replace"))
            return
        code, out = container.exec_run(["angie", "-s", "reload"])
        if code != 0:
            logger.warning("Angie reload failed: %s", out.decode(errors="replace"))
    except Exception:
        logger.exception("Failed to reload Angie")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


async def list_connections(
    session: AsyncSession, *, user_id: int | None = None
) -> list[Connection]:
    """List all connections (admin) or just the user's (when user_id provided)."""
    stmt = select(ConnectionModel).order_by(ConnectionModel.id)
    if user_id is not None:
        stmt = stmt.where(ConnectionModel.user_id == user_id)
    result = await session.execute(stmt)
    return [Connection.model_validate(_to_dict(r)) for r in result.scalars().all()]


async def get_connection(session: AsyncSession, conn_id: int) -> Connection | None:
    row = await session.get(ConnectionModel, conn_id)
    return Connection.model_validate(_to_dict(row)) if row else None


async def _resolve_and_validate_origin(domain: str) -> tuple[list[str], int]:
    """Resolve A records → (public_ips, dns_ttl_seconds). Raises HTTPException on failure."""
    try:
        ips, ttl = await resolve_a(domain)
    except DnsResolutionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    edge = _edge_ipv4()
    if edge and edge in ips:
        raise HTTPException(
            status_code=422,
            detail="Domain already points to the WAF edge — there's nothing for us to proxy. "
            "Remove the A-record pointing at us first, then re-add the domain.",
        )
    # Belt-and-braces — dns.resolve_a already filters, but reject on race.
    safe = [ip for ip in ips if not is_blocked_ip(ip)]
    if not safe:
        raise HTTPException(
            status_code=422,
            detail="Origin resolves to private/internal addresses; cannot proxy.",
        )
    return safe, ttl


async def create_connection(
    session: AsyncSession,
    conn_in: ConnectionCreate,
    *,
    user_id: int | None = None,
) -> tuple[Connection, VerifyInstructions]:
    """Create a row in pending_verification state and return wizard instructions.

    Resolves the *current* A records eagerly so the user gets immediate feedback
    if their domain is broken / behind a CDN / DNS-blocked. The verify_token
    must be exposed via TXT before the poller will advance to pending_dns.
    """
    try:
        domain = validate_domain(conn_in.domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Duplicate check up front for a clean 409 (UNIQUE constraint would fire
    # at commit but with a less helpful message).
    existing = await session.execute(
        select(ConnectionModel).where(ConnectionModel.domain == domain)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail=f"Domain {domain} is already onboarded")

    origin_ips, ttl = await _resolve_and_validate_origin(domain)

    verify_token = secrets.token_urlsafe(24)
    row = ConnectionModel(
        user_id=user_id,
        name=conn_in.name,
        domain=domain,
        origin_hosts=origin_ips,
        origin_port=conn_in.origin_port or 443,
        origin_tls_mode=conn_in.origin_tls_mode,
        verify_token=verify_token,
        status="pending_verification",
        status_detail="Add the TXT record shown to verify ownership.",
        dns_ttl_seconds=ttl,
        http_versions=conn_in.http_versions or "h1,h2",
        compression_algo=conn_in.compression_algo or "auto",
        enabled=True,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)

    # Write the HTTP-only Angie config immediately so the site is reachable
    # the instant DNS flips, even before TXT verification — the proxy still
    # works because state ∈ {pending_verification, pending_dns} both render
    # the same HTTP-only block.
    try:
        angie_config.write_config(_to_dict(row))
        _reload_angie()
    except Exception:
        logger.exception("Conn %d: failed to write/reload Angie config on create", row.id)

    instructions = VerifyInstructions(
        txt_record_name=f"_waf-verify.{domain}",
        txt_record_value=verify_token,
        edge_ipv4=_edge_ipv4(),
    )
    return Connection.model_validate(_to_dict(row)), instructions


async def update_connection(
    session: AsyncSession, conn_id: int, conn_in: ConnectionUpdate
) -> Connection | None:
    row = await session.get(ConnectionModel, conn_id)
    if row is None:
        return None
    data = conn_in.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(row, k, v)
    await session.commit()
    await session.refresh(row)
    try:
        if row.enabled:
            angie_config.write_config(_to_dict(row))
        else:
            angie_config.delete_config(conn_id)
        _reload_angie()
    except Exception:
        logger.exception("Conn %d: failed to apply Angie config on update", conn_id)
    return Connection.model_validate(_to_dict(row))


async def delete_connection(session: AsyncSession, conn_id: int) -> bool:
    row = await session.get(ConnectionModel, conn_id)
    if row is None:
        return False
    await session.delete(row)
    await session.commit()
    angie_config.delete_config(conn_id)
    _reload_angie()
    return True


async def probe_connection(session: AsyncSession, conn_id: int) -> Connection | None:
    """Probe a connection NOW and return the updated row.

    Synchronous for the two states the wizard cares about:

      * ``pending_verification`` — does the TXT record exist? If yes,
        flip to ``pending_dns``. Otherwise update ``status_detail`` so the
        UI can render a clear "TXT not found yet" message.
      * ``pending_dns`` — does the domain's current A record point at
        the WAF edge? If yes, flip to ``provisioning_cert`` so the
        background poller picks it up and runs ACME on its next tick.

    For all other states (or when the synchronous check raises), we just
    zero ``next_poll_at`` and let the background poller handle it on its
    next iteration. Synchronous work matters here because the user is
    actively waiting on a wizard button — surfacing the real outcome in
    the response keeps the UX honest.
    """
    import os

    row = await session.get(ConnectionModel, conn_id)
    if row is None:
        return None

    row.last_checked_at = _now()

    if row.status == "pending_verification" and row.verify_token:
        try:
            found = await verify_txt_token(row.domain, row.verify_token)
        except Exception as exc:  # DNS infra error — surface, don't crash
            logger.warning("Conn %d probe: TXT lookup failed: %s", conn_id, exc)
            found = False
        if found:
            row.status = "pending_dns"
            row.verified_at = _now()
            row.status_detail = "Domain ownership verified."
        else:
            row.status_detail = (
                "TXT record not found yet — DNS propagation can take 5-30 minutes."
            )
    elif row.status == "pending_dns":
        edge = (os.environ.get("WAF_EDGE_IPV4") or "").strip()
        if edge:
            try:
                ips, ttl = await resolve_a(row.domain)
                row.dns_ttl_seconds = ttl
                if edge in ips:
                    row.status = "provisioning_cert"
                    row.status_detail = "DNS now points to WAF edge; issuing certificate."
                else:
                    row.status_detail = (
                        f"A-record points to {','.join(ips)}; expecting {edge}."
                    )
            except DnsResolutionError as exc:
                row.status_detail = f"DNS lookup: {exc}"
        else:
            row.status_detail = "WAF_EDGE_IPV4 env var not set; ask the operator."

    # Always wake the poller for follow-up work (ACME, periodic re-resolve).
    row.next_poll_at = _now()
    row.acme_next_retry_at = None  # un-park error retries

    await session.commit()
    await session.refresh(row)
    return Connection.model_validate(_to_dict(row))


async def reload_connections_config(session: AsyncSession) -> dict:
    """Operator endpoint: regenerate every enabled connection's Angie conf.

    Useful after edge IP rotation or template updates. Idempotent — never
    touches DB state, only filesystem + Angie reload.
    """
    result = await session.execute(
        select(ConnectionModel).where(ConnectionModel.enabled.is_(True))
    )
    rows = list(result.scalars().all())
    for row in rows:
        try:
            angie_config.write_config(_to_dict(row))
        except Exception:
            logger.exception("Conn %d: failed to write Angie config during reload", row.id)
    _reload_angie()
    return {"success": True, "message": f"Regenerated {len(rows)} connection configs"}
