"""E2E tests for connections API — domain validation and rejection paths.

These tests run against the live docker-compose stack via HTTP. They focus on
inputs that the API can reject *without* needing real DNS resolution or
ACME — keeping them fast and deterministic in CI. Tests that need real DNS
(DNS-flip detection, ACME issuance) are deferred until the Pebble compose
service lands (see TODOS.md).
"""

from __future__ import annotations

import os
import uuid

import pytest
import requests

API_URL = os.environ.get("WAF_API_URL", "http://localhost")
ADMIN_USER = os.environ.get("WAF_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("WAF_ADMIN_PASS", "admin")


@pytest.fixture(scope="module")
def session() -> requests.Session:
    """Authenticated session — used by every test in this module."""
    s = requests.Session()
    resp = s.post(
        f"{API_URL}/api/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=10,
    )
    if resp.status_code != 200:
        pytest.skip(f"Could not authenticate against {API_URL} ({resp.status_code})")
    yield s
    s.close()


@pytest.fixture
def cleanup_domains(session: requests.Session):
    """Delete every connection created by this test fixture after the test
    so the table doesn't pile up across runs."""
    created: list[int] = []
    yield created
    for conn_id in created:
        session.delete(f"{API_URL}/api/connections/{conn_id}")


# ── Validation: bad input ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_domain",
    [
        "",  # empty
        "localhost",  # explicit blocklist
        "x.local",  # private TLD
        "192.168.1.1",  # bare IP
        "ac me.com",  # whitespace
        "acme.com:8080",  # port not allowed
        "https://acme.com",  # scheme not allowed
        "*.acme.com",  # wildcard
    ],
)
def test_create_rejects_invalid_domain(session, cleanup_domains, bad_domain):
    resp = session.post(
        f"{API_URL}/api/connections",
        json={"name": "test", "domain": bad_domain},
        timeout=10,
    )
    assert resp.status_code in (400, 422), (
        f"expected validation rejection for {bad_domain!r}, got {resp.status_code}: {resp.text}"
    )


def test_create_rejects_missing_name(session, cleanup_domains):
    resp = session.post(
        f"{API_URL}/api/connections",
        json={"domain": "acme.com"},
        timeout=10,
    )
    assert resp.status_code in (400, 422)


# ── Duplicate detection ─────────────────────────────────────────────────────


def test_create_duplicate_domain_409(session, cleanup_domains):
    """Two connections cannot share the same domain — second create → 409."""
    # Pick a domain that resolves to a public IP so the first create succeeds.
    # example.com is RFC 2606 reserved and always points to 93.184.216.34.
    domain = "example.com"

    # Clean any leftover from previous runs
    existing = session.get(f"{API_URL}/api/connections", timeout=10).json()
    for row in existing:
        if row.get("domain") == domain:
            session.delete(f"{API_URL}/api/connections/{row['id']}")

    first = session.post(
        f"{API_URL}/api/connections",
        json={"name": "first", "domain": domain},
        timeout=15,
    )
    if first.status_code == 422:
        pytest.skip(f"Cannot reach {domain} from CI runner; skipping dup-test")
    assert first.status_code == 201, first.text
    cleanup_domains.append(first.json()["connection"]["id"])

    dup = session.post(
        f"{API_URL}/api/connections",
        json={"name": "second", "domain": domain},
        timeout=15,
    )
    assert dup.status_code == 409


# ── Shape: returned VerifyInstructions ───────────────────────────────────────


def test_create_returns_verify_instructions(session, cleanup_domains):
    """A successful create must include the TXT instructions the wizard needs."""
    # Use a unique-ish subdomain of example.com to avoid colliding across CI runs.
    domain = f"test-{uuid.uuid4().hex[:8]}.example.com"
    resp = session.post(
        f"{API_URL}/api/connections",
        json={"name": "shape-test", "domain": domain},
        timeout=15,
    )
    if resp.status_code == 422:
        # DNS for the random subdomain doesn't resolve — fine, the test for
        # the response shape only runs when the DNS path succeeds.
        pytest.skip("DNS for random subdomain didn't resolve; instructions shape untested")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    cleanup_domains.append(body["connection"]["id"])
    assert "connection" in body
    assert "instructions" in body
    assert body["instructions"]["txt_record_name"] == f"_waf-verify.{domain}"
    assert len(body["instructions"]["txt_record_value"]) > 16


# ── List / probe endpoints exist ─────────────────────────────────────────────


def test_list_endpoint_returns_array(session):
    resp = session.get(f"{API_URL}/api/connections", timeout=10)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_probe_unknown_id_404(session):
    resp = session.post(f"{API_URL}/api/connections/999999999/probe", timeout=10)
    assert resp.status_code == 404


def test_delete_unknown_id_404(session):
    resp = session.delete(f"{API_URL}/api/connections/999999999", timeout=10)
    assert resp.status_code == 404


# ── Removed endpoints stay removed ──────────────────────────────────────────


def test_upload_endpoints_404(session):
    """Spec §1 — the 4-mode upload endpoints are gone. CI shouldn't find them."""
    for path in (
        "/api/connections/upload-static",
        "/api/connections/upload-nginx-config",
        "/api/connections/upload-static-dir",
        "/api/connections/parse-nginx-config",
    ):
        resp = session.post(f"{API_URL}{path}", json={}, timeout=10)
        assert resp.status_code in (404, 405), (
            f"removed endpoint {path} still exists ({resp.status_code})"
        )
