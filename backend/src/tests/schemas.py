from typing import Any, Literal

from pydantic import BaseModel, Field

# Result status of a single test run.
# - blocked: WAF (ModSecurity) returned a block (403) AND the marker landed in audit log
# - fired-but-not-blocked: marker landed in audit log, but HTTP status != 403
#   (rule(s) fired, but anomaly score under block threshold)
# - passed: HTTP code 200 from upstream, no marker row in audit log
#   (ModSec didn't inspect or didn't fire — a valid result for tests that
#   target rules disabled / out-of-scope for the chosen connection)
# - timeout: no row landed in the audit log within the polling window
TestResultStatus = Literal["blocked", "fired-but-not-blocked", "passed", "timeout"]

CatalogFamily = Literal[
    "xss",
    "sqli",
    "rce",
    "rfi",
    "lfi",
    "scanner",
    "java",
    "php",
    "session_fixation",
    "multipart",
    "method",
    "protocol_attack",
    "protocol_enforce",
    "generic",
    "blocking",
    "crowdsec",
]


class TestCase(BaseModel):
    """One catalog entry — the payload a single Run button will fire."""

    id: str = Field(..., description="Stable id, '{family}.{rule_id}' or '{family}.{n}'")
    family: CatalogFamily
    rule_id: str = Field(..., description="OWASP CRS rule id or scenario name")
    description: str = Field("", description="Human-readable description of the payload")
    method: Literal["GET", "POST"] = "GET"
    path: str = "/"
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class Catalog(BaseModel):
    """Full catalog returned to the frontend."""

    tests: list[TestCase]
    generated_at: str | None = None


class RunRequest(BaseModel):
    """Frontend → backend: which test to run, and against what."""

    test_id: str = Field(..., min_length=1, max_length=128)
    connection_id: int | None = Field(
        default=None,
        description=(
            "Active connection to target. If null, the runner falls back to "
            "localhost (default Angie vhost)."
        ),
    )
    ip: str | None = Field(
        default=None,
        min_length=1,
        max_length=45,
        description="Optional client IP to emulate for the request (sent as X-Forwarded-For)"
    )



class RunResult(BaseModel):
    """Backend → frontend: synchronous response from POST /api/tests/run."""

    marker: str = Field(..., description="UUID4 used as X-Test-Marker on the request")
    status: TestResultStatus
    http_code: int | None = Field(
        default=None,
        description="HTTP status code returned by the WAF — None if the request errored",
    )
    blocked_by: str | None = Field(
        default=None,
        description="ModSec rule id that returned the block, if known",
    )
    latency_ms: int | None = None
    target_url: str
    error: str | None = Field(
        default=None,
        description="Transport-level error string, if the HTTP request failed",
    )
    request_raw: str | None = Field(default=None, description="Raw HTTP request sent")
    response_raw: str | None = Field(default=None, description="Raw HTTP response received")


class CrowdsecRunResult(BaseModel):
    """CrowdSec subcatalog run result.

    CrowdSec works on bans/decisions, not headers, so the marker is replaced
    with a (scenario, source_ip, time_window) tuple.
    """

    scenario: str
    source_ip: str
    started_at: str
    decisions_before: list[Any] = Field(default_factory=list, description="Active decisions before the run")
    decisions_after: list[Any] = Field(default_factory=list, description="Active decisions after the run")
    bursts_sent: int = 0
    target_url: str
