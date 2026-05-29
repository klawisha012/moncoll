"""Pydantic schemas for the domain-only Connection API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

OriginTlsMode = Literal["strict", "lenient"]
ConnectionStatus = Literal[
    "pending_verification", "pending_dns", "provisioning_cert", "active", "error"
]
HttpVersions = str  # comma-separated subset of {h1,h2,h3}
CompressionAlgo = Literal["auto", "gzip", "brotli", "zstd", "none"]
ModSecState = Literal["off", "detection_only", "blocking"]


class ConnectionCreate(BaseModel):
    """Body for POST /api/connections. Only fields the user controls."""

    name: str = Field(..., min_length=1, max_length=128)
    domain: str = Field(..., min_length=3, max_length=253)
    origin_hosts: list[str] | None = None
    # Defaults to 443 — the convention for HTTPS origins. Override when the
    # origin serves on a non-standard port (e.g. dev/staging, or when 443
    # on the origin server is already taken by another service like a VPN).
    origin_port: int = Field(443, ge=1, le=65535)
    origin_tls_mode: OriginTlsMode = "strict"
    http_versions: HttpVersions = "h1,h2"
    compression_algo: CompressionAlgo = "auto"


class ConnectionUpdate(BaseModel):
    """Body for PATCH /api/connections/{id}. domain is immutable — delete+create."""

    name: str | None = Field(None, min_length=1, max_length=128)
    enabled: bool | None = None
    origin_port: int | None = Field(None, ge=1, le=65535)
    origin_tls_mode: OriginTlsMode | None = None
    http_versions: HttpVersions | None = None
    compression_algo: CompressionAlgo | None = None


class Connection(BaseModel):
    """Full row returned by GET endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    name: str
    domain: str
    origin_hosts: list[str]
    origin_port: int
    origin_tls_mode: OriginTlsMode
    verify_token: str
    verified_at: datetime | None
    status: ConnectionStatus
    status_detail: str | None
    acme_retry_count: int
    acme_next_retry_at: datetime | None
    next_poll_at: datetime | None
    dns_ttl_seconds: int
    last_checked_at: datetime | None
    http_versions: str
    compression_algo: str
    enabled: bool
    modsec_state: ModSecState
    geoip_denied_countries: list[str]
    crowdsec_active: bool
    ssl_cert_path: str | None
    ssl_key_path: str | None
    created_at: datetime
    updated_at: datetime


class VerifyInstructions(BaseModel):
    """Returned alongside Connection on POST /api/connections.

    The wizard's step 2 reads these to display "add TXT _waf-verify.<domain>
    with value <token>". Also includes the edge IP for step 3.
    """

    txt_record_name: str
    txt_record_value: str
    edge_ipv4: str
