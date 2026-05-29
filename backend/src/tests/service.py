"""Test runner — fires an HTTP request tagged with ``X-Test-Marker`` and
polls the WAF audit log in ClickHouse to classify the outcome.

The marker pattern (UUID4 sent as a request header, then looked up in
``waf_audit_log.request_headers``) means we can isolate one test's traffic on
the dashboard without touching the schema. See the design doc for the
4-status taxonomy returned to the frontend.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..dashboard.service import _get_client as _ch_client
from ..db.models import Connection as ConnectionModel
from .manifest import load_catalog
from .schemas import RunRequest, RunResult, TestCase, TestResultStatus

logger = logging.getLogger(__name__)

# X-Test-Marker header is the contract between the runner and the WAF.
# ModSecurity captures full request headers into ``waf_audit_log.request_headers``
# (a Map(String, String) ClickHouse column — see configs/clickhouse/init.sql).
MARKER_HEADER = "X-Test-Marker"

# Polling window after the request before giving up and reporting "timeout".
# Vector batches into ClickHouse every ~100ms in this stack, so 5s is generous.
_DEFAULT_POLL_TIMEOUT_S = float(os.getenv("WAF_TESTS_POLL_TIMEOUT", "5.0"))
_POLL_INTERVAL_S = 0.5

# httpx request timeout when firing the test attack. Smaller than the poll
# window — even unreachable targets must return fast so we can show a status.
_HTTP_TIMEOUT_S = 3.0


def find_test(test_id: str) -> TestCase | None:
    catalog = load_catalog()
    for t in catalog.tests:
        if t.id == test_id:
            return t
    return None


async def resolve_target(
    session: AsyncSession,
    connection_id: int | None,
    tenant_id: int | None = None,
) -> tuple[str, ConnectionModel | None]:
    """Pick the URL the test request will be sent to.

    Returns ``(base_url, connection_or_None)``. The connection is included so
    the caller can carry through context (e.g. Host header, log scoping).
    Falls back to ``http://angie/`` (the Angie container on the docker
    network) when no connection is selected — the default vhost still goes
    through the full WAF pipeline.

    ``tenant_id`` enforces tenant scoping: when set, a connection owned by a
    different tenant is treated as missing (fall-through to the default
    target). Admins can pass ``None`` to skip the filter; the per-route
    dependency wiring decides which mode applies.
    """
    if connection_id is not None:
        stmt = select(ConnectionModel).where(ConnectionModel.id == connection_id)
        if tenant_id is not None:
            stmt = stmt.where(ConnectionModel.tenant_id == tenant_id)
        result = await session.execute(stmt)
        conn = result.scalar_one_or_none()
        if conn is None:
            return _localhost_url(), None
        return _connection_url(conn), conn

    return _localhost_url(), None


def _localhost_url() -> str:
    """URL for the loopback test target.

    Inside the backend container the Angie service is reachable as ``angie``
    on the compose network. ``WAF_TESTS_TARGET_URL`` lets ops override.
    """
    return os.getenv("WAF_TESTS_TARGET_URL", "http://angie")


def _connection_url(conn: ConnectionModel) -> str:
    """Pick a URL that lands on the WAF for the given connection.

    We do NOT resolve to the public hostname — that would route through DNS
    and possibly fail inside the compose network. Instead we hit Angie
    directly and let the Host header trigger the right vhost.
    """
    if conn.status == "active" and conn.ssl_cert_path and conn.ssl_key_path:
        return os.getenv("WAF_TESTS_TARGET_URL_HTTPS", "https://angie")
    return _localhost_url()


def _host_header_for(conn: ConnectionModel | None) -> str | None:
    if conn is None:
        return None
    return conn.domain or None


def build_request(test: TestCase, target_url: str, marker: str, client_ip: str | None = None) -> dict[str, Any]:
    """Translate a TestCase into kwargs for ``httpx.AsyncClient.request``."""
    headers = dict(test.headers or {})
    headers[MARKER_HEADER] = marker
    if client_ip:
        headers["X-Forwarded-For"] = client_ip
    return {
        "method": test.method,
        "url": target_url.rstrip("/") + test.path,
        "params": test.query or None,
        "headers": headers,
        "content": test.body,
    }


async def run_test(
    session: AsyncSession, req: RunRequest, tenant_id: int | None = None
) -> RunResult:
    """Execute one test against the WAF and classify the result.

    ``tenant_id`` scopes the connection_id lookup: when set, cross-tenant
    connection IDs fall back to the default target rather than running the
    test against another tenant's domain.
    """
    test = find_test(req.test_id)
    if test is None:
        # Caller (router) should have already 400'd, but be defensive.
        return RunResult(
            marker="",
            status="timeout",
            target_url="",
            error=f"unknown test_id: {req.test_id}",
        )

    # Determine connections to probe. If connection_id is None, probe all active tenant connections.
    conns = []
    if req.connection_id is None and tenant_id is not None:
        stmt = select(ConnectionModel).where(
            ConnectionModel.tenant_id == tenant_id,
            ConnectionModel.enabled.is_(True)
        )
        result = await session.execute(stmt)
        conns = list(result.scalars().all())

    # Build target execution list
    targets = []
    if conns:
        for conn in conns:
            target_url = _localhost_url()
            targets.append((target_url, conn))
    else:
        target_url, conn = await resolve_target(session, req.connection_id, tenant_id)
        targets.append((target_url, conn))

    marker = str(uuid.uuid4())
    started_ns = time.monotonic_ns()

    async def fire_one(target_url_str: str, conn_obj: ConnectionModel | None) -> tuple[int | None, str | None, str | None, str | None]:
        request_kwargs = build_request(test, target_url_str, marker, client_ip=req.ip)
        host_override = _host_header_for(conn_obj)
        if host_override:
            request_kwargs["headers"]["Host"] = host_override

        # Construct raw request representation
        try:
            req_method = request_kwargs["method"]
            req_url = request_kwargs["url"]
            from urllib.parse import urlencode, urlparse
            parsed = urlparse(req_url)
            path_with_query = parsed.path or "/"
            if parsed.query:
                path_with_query += f"?{parsed.query}"
            elif request_kwargs.get("params"):
                path_with_query += f"?{urlencode(request_kwargs['params'])}"

            req_lines = [f"{req_method} {path_with_query} HTTP/1.1"]
            for k, v in request_kwargs["headers"].items():
                req_lines.append(f"{k}: {v}")
            req_lines.append("")
            if request_kwargs.get("content"):
                req_lines.append(str(request_kwargs["content"]))
            request_raw = "\n".join(req_lines)
        except Exception as exc:
            request_raw = f"Error formatting request: {exc}"

        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S, verify=False, follow_redirects=False) as client:
                resp = await client.request(**request_kwargs)
                
                # Format raw response
                try:
                    resp_lines = [f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}"]
                    for k, v in resp.headers.items():
                        resp_lines.append(f"{k}: {v}")
                    resp_lines.append("")
                    resp_body = resp.text
                    if len(resp_body) > 2000:
                        resp_body = resp_body[:2000] + "\n... [truncated]"
                    resp_lines.append(resp_body)
                    response_raw = "\n".join(resp_lines)
                except Exception as exc:
                    response_raw = f"Error formatting response: {exc}"

                return resp.status_code, None, request_raw, response_raw
        except httpx.TimeoutException as exc:
            return None, f"target timeout: {exc}", request_raw, f"Error: Timeout connecting to target\n{exc}"
        except httpx.HTTPError as exc:
            return None, f"transport error: {exc}", request_raw, f"Error: Transport error\n{exc}"
        except OSError as exc:
            return None, f"socket error: {exc}", request_raw, f"Error: Socket error\n{exc}"

    import asyncio
    fire_tasks = [fire_one(t_url, cn) for t_url, cn in targets]
    fire_results = await asyncio.gather(*fire_tasks)
    latency_ms = int((time.monotonic_ns() - started_ns) / 1_000_000)

    http_codes = [code for code, err, _, _ in fire_results if code is not None]
    errors = [err for code, err, _, _ in fire_results if err is not None]
    
    first_req_raw = fire_results[0][2] if fire_results else None
    first_resp_raw = fire_results[0][3] if fire_results else None

    # If all fired targets errored out/timed out
    if len(errors) == len(targets):
        return RunResult(
            marker=marker,
            status="timeout",
            http_code=http_codes[0] if http_codes else None,
            target_url=", ".join(t_url for t_url, _ in targets),
            latency_ms=latency_ms,
            error=errors[0],
            request_raw=first_req_raw,
            response_raw=first_resp_raw,
        )

    # Pick the most relevant HTTP code: 403 if blocked on any, else the first success code
    http_code = 403 if 403 in http_codes else (http_codes[0] if http_codes else None)

    # Poll the WAF audit log for the marker. If it lands, ModSec inspected
    # the request (rule fired). If it does not, ModSec either skipped the
    # request or allowed it without logging.
    marker_landed, blocked_by = await _wait_for_marker(marker)

    status = _classify(http_code=http_code, marker_landed=marker_landed)

    return RunResult(
        marker=marker,
        status=status,
        http_code=http_code,
        blocked_by=blocked_by,
        latency_ms=latency_ms,
        target_url=", ".join(t_url for t_url, _ in targets),
        request_raw=first_req_raw,
        response_raw=first_resp_raw,
    )


def _classify(*, http_code: int | None, marker_landed: bool) -> TestResultStatus:
    if marker_landed and http_code == 403:
        return "blocked"
    if marker_landed:
        return "fired-but-not-blocked"
    if http_code is not None and http_code < 500:
        return "passed"
    return "timeout"


async def _wait_for_marker(marker: str) -> tuple[bool, str | None]:
    """Poll ClickHouse for a row whose ``request_headers`` Map contains the marker.

    Returns ``(landed, blocked_by_rule_id_or_None)``.
    """
    import asyncio

    deadline = time.monotonic() + _DEFAULT_POLL_TIMEOUT_S
    while time.monotonic() < deadline:
        landed, blocked_by = _query_marker(marker)
        if landed:
            return True, blocked_by
        await asyncio.sleep(_POLL_INTERVAL_S)
    return False, None


def _query_marker(marker: str) -> tuple[bool, str | None]:
    """One-shot lookup. Returns whether a row exists and which rule blocked, if any.

    Defensive against ClickHouse being unreachable — returns (False, None) so
    the poller can keep trying / time out cleanly.
    """
    try:
        client = _ch_client()
    except Exception:
        logger.exception("ClickHouse client unavailable while polling test marker")
        return False, None

    # request_headers is Map(String, String); ClickHouse Map subscript with a
    # static key is index-friendly. The marker is server-generated UUID4 so
    # we can safely interpolate it.
    query = (
        "SELECT any(m.ruleId) AS rid "
        "FROM logs.waf_audit_log AS w "
        "LEFT ARRAY JOIN messages AS m "
        f"WHERE request_headers['{MARKER_HEADER}'] = '{marker}' "
        "AND timestamp >= now() - INTERVAL 1 MINUTE "
        "LIMIT 1"
    )
    try:
        rows = client.execute(query)
    except Exception:
        logger.exception("Marker query failed")
        return False, None

    if not rows:
        return False, None

    rule_id = rows[0][0]
    return True, (str(rule_id) if rule_id else None)
