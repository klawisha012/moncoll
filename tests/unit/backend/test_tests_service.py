"""Pure-function unit tests for tests/service.py.

Covers the parts that never touch the network: the 4-status classifier,
the request builder (X-Test-Marker invariant + Host override), and the
manifest lookup helper. The HTTP/ClickHouse-touching paths are exercised
by the e2e suite, not here.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.tests.service import (
    MARKER_HEADER,
    _classify,
    _connection_url,
    _host_header_for,
    _localhost_url,
    build_request,
    find_test,
)
from src.tests.schemas import TestCase as _TestCase  # rename: avoid pytest collection


# ── _classify: 4-status truth table ───────────────────────────────────

# (http_code, marker_landed, expected_status)
_CASES = [
    (403, True, "blocked"),
    (200, True, "fired-but-not-blocked"),
    (404, True, "fired-but-not-blocked"),
    (500, True, "fired-but-not-blocked"),
    (200, False, "passed"),
    (404, False, "passed"),
    (None, False, "timeout"),
    (None, True, "fired-but-not-blocked"),  # marker landed even if HTTP errored
    (502, False, "timeout"),  # 5xx without marker reads as upstream broke before ModSec
]


@pytest.mark.parametrize("http_code,marker_landed,expected", _CASES)
def test_classify_truth_table(http_code, marker_landed, expected):
    assert _classify(http_code=http_code, marker_landed=marker_landed) == expected


# ── build_request: marker header invariant + Host override ────────────


def _tc(**overrides) -> _TestCase:
    base = {
        "id": "xss.test",
        "family": "xss",
        "rule_id": "941100",
        "description": "",
        "method": "GET",
        "path": "/foo",
        "query": {},
        "headers": {},
        "body": None,
    }
    base.update(overrides)
    return _TestCase(**base)


def test_build_request_stamps_marker_header():
    req = build_request(_tc(), "http://angie", "marker-uuid")
    assert req["headers"][MARKER_HEADER] == "marker-uuid"


def test_build_request_preserves_custom_headers():
    req = build_request(
        _tc(headers={"X-Custom": "v"}), "http://angie", "marker-1"
    )
    assert req["headers"]["X-Custom"] == "v"
    assert req["headers"][MARKER_HEADER] == "marker-1"


def test_build_request_strips_trailing_slash_from_base():
    req = build_request(_tc(path="/x"), "http://angie/", "m")
    assert req["url"] == "http://angie/x"


def test_build_request_uses_method_and_path_from_testcase():
    req = build_request(_tc(method="POST", path="/api/v1"), "http://angie", "m")
    assert req["method"] == "POST"
    assert req["url"].endswith("/api/v1")


def test_build_request_passes_query_through():
    req = build_request(_tc(query={"q": "<script>"}), "http://angie", "m")
    assert req["params"] == {"q": "<script>"}


def test_build_request_does_not_mutate_testcase_headers():
    """Regression guard: build_request must copy the headers dict; otherwise
    parallel runs would race on the same dict and bleed markers between tests."""
    tc = _tc(headers={"X-Custom": "v"})
    build_request(tc, "http://angie", "m1")
    build_request(tc, "http://angie", "m2")
    assert tc.headers == {"X-Custom": "v"}, "TestCase.headers was mutated by build_request"


# ── _host_header_for ──────────────────────────────────────────────────


def test_host_header_for_returns_none_when_no_connection():
    assert _host_header_for(None) is None


def test_host_header_for_returns_none_when_no_domains():
    conn = SimpleNamespace(domains=[])
    assert _host_header_for(conn) is None


def test_host_header_for_returns_first_domain():
    conn = SimpleNamespace(domains=["a.test", "b.test"])
    assert _host_header_for(conn) == "a.test"


# ── _localhost_url / _connection_url ──────────────────────────────────


def test_localhost_url_default():
    # Default — no env override — must point inside the compose network.
    assert _localhost_url() == "http://angie"


def test_localhost_url_respects_env(monkeypatch):
    monkeypatch.setenv("WAF_TESTS_TARGET_URL", "http://other:8080")
    assert _localhost_url() == "http://other:8080"


def test_connection_url_with_domains_still_targets_internal():
    """Smoke: with or without domains, the URL stays internal — Host header
    is what selects the vhost, not the URL host."""
    conn_with = SimpleNamespace(domains=["x.test"])
    conn_without = SimpleNamespace(domains=[])
    assert _connection_url(conn_with) == _connection_url(conn_without)


# ── find_test ─────────────────────────────────────────────────────────


def test_find_test_returns_known_id():
    tc = find_test("xss.941100")
    assert tc is not None
    assert tc.id == "xss.941100"
    assert tc.family == "xss"


def test_find_test_returns_none_for_unknown():
    assert find_test("does.not.exist") is None
