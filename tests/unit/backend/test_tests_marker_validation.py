"""CRITICAL [security]: marker UUID validation on /api/dashboard/test-traffic.

The path param is interpolated into a ClickHouse query. If the regex slips,
that's a SQL-injection foothold. These tests pin the regex directly — the
endpoint applies the same regex via FastAPI's Path dependency before calling
the service layer.
"""

from __future__ import annotations

import re
import uuid

import pytest


def test_uuid4_regex_accepts_real_uuid4():
    from src.dashboard.router import _UUID4_RE

    for _ in range(20):
        assert _UUID4_RE.match(str(uuid.uuid4())) is not None


@pytest.mark.parametrize(
    "good",
    [
        "00000000-0000-4000-8000-000000000000",
        "ffffffff-ffff-4fff-bfff-ffffffffffff",
        "12345678-9abc-4def-8123-456789abcdef",
        # Mixed-case input — the regex is case-insensitive
        "12345678-9ABC-4DEF-8123-456789ABCDEF",
    ],
)
def test_uuid4_regex_accepts_canonical_forms(good: str):
    from src.dashboard.router import _UUID4_RE

    assert _UUID4_RE.match(good) is not None


@pytest.mark.parametrize(
    "bad",
    [
        # SQL injection attempts
        "'; DROP TABLE waf_audit_log; --",
        "00000000-0000-4000-8000-000000000000' OR '1'='1",
        # Wrong length
        "abc",
        "a" * 36,
        # UUID v1 / v3 / v5 — version field must be 4
        "00000000-0000-1000-8000-000000000000",
        "00000000-0000-3000-8000-000000000000",
        "00000000-0000-5000-8000-000000000000",
        # Wrong variant — must be 8/9/a/b
        "00000000-0000-4000-0000-000000000000",
        "00000000-0000-4000-c000-000000000000",
        # Empty / whitespace
        "",
        "   ",
        # Path traversal
        "../../../../etc/passwd",
        # Non-hex digit inside an otherwise-correct shape
        "00000000-0000-4000-80g0-000000000000",
        # Wrong dash placement
        "0000000000000000000000000000000000000",
        "00000000-00000-4000-8000-000000000000",
        # Trailing newline / null byte tricks
        "12345678-9abc-4def-8123-456789abcdef\n",
        "12345678-9abc-4def-8123-456789abcdef\x00",
    ],
)
def test_uuid4_regex_rejects_bad_input(bad: str):
    from src.dashboard.router import _UUID4_RE

    assert _UUID4_RE.match(bad) is None, f"regex incorrectly accepted {bad!r}"


def test_uuid4_regex_is_full_match_only():
    """``match`` (used by the endpoint) must anchor; verify our regex does too."""
    from src.dashboard.router import _UUID4_RE

    # A valid UUID4 followed by garbage must NOT match — the trailing
    # `;DROP TABLE` would be appended to the SQL otherwise.
    valid = str(uuid.uuid4())
    assert _UUID4_RE.match(valid + ";DROP TABLE") is None, (
        "regex must anchor end — UUID followed by extra chars is an injection vector"
    )


def test_uuid4_regex_pattern_matches_documented_shape():
    """Sanity check: the regex pattern is the documented UUID4 grammar."""
    from src.dashboard.router import _UUID4_RE

    pattern = _UUID4_RE.pattern
    # 4 in the version position, 8/9/a/b in the variant position
    assert "4[0-9a-f]" in pattern, f"missing version-4 anchor: {pattern}"
    assert "[89ab]" in pattern, f"missing variant anchor: {pattern}"
    # `\Z` anchors strictly at end-of-string; `$` would let a trailing
    # newline slip through and is unsafe.
    assert pattern.endswith(r"\Z"), f"missing strict end anchor: {pattern}"


def test_endpoint_regex_re_ignorecase_flag_set():
    """The compiled regex must be case-insensitive — UUIDs may arrive uppercased."""
    from src.dashboard.router import _UUID4_RE

    assert _UUID4_RE.flags & re.IGNORECASE
