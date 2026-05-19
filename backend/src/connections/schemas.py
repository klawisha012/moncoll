from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SourceType = Literal["nginx_config", "static_generate", "container", "docker_compose"]

HttpVersion = Literal["h1", "h2", "h3"]
CompressionAlgo = Literal["auto", "gzip", "brotli", "zstd", "none"]

_ALLOWED_HTTP_VERSIONS: set[str] = {"h1", "h2", "h3"}


def _normalize_http_versions(value: object) -> str:
    """Coerce a string or sequence into a comma-separated canonical form.

    Accepted inputs: ``"h1,h2"``, ``["h1","h2"]``, ``("h2","h3")``, ``""``.
    Order is preserved, duplicates are dropped, unknown tokens are rejected.
    """
    if value is None:
        return "h1,h2"
    if isinstance(value, str):
        tokens = [t.strip() for t in value.split(",") if t.strip()]
    elif isinstance(value, (list, tuple, set)):
        tokens = [str(t).strip() for t in value if str(t).strip()]
    else:
        raise ValueError(f"http_versions must be string or list, got {type(value).__name__}")
    seen: set[str] = set()
    out: list[str] = []
    for t in tokens:
        if t not in _ALLOWED_HTTP_VERSIONS:
            raise ValueError(f"Unknown HTTP version '{t}'. Allowed: h1, h2, h3")
        if t not in seen:
            seen.add(t)
            out.append(t)
    if not out:
        # Empty → keep default rather than emit an unreachable server.
        return "h1,h2"
    return ",".join(out)


class ConnectionBase(BaseModel):
    """Base connection model with common fields."""

    name: str = Field(
        ..., min_length=1, max_length=128, description="Human-readable name for this connection"
    )
    domains: list[str] = Field(
        default_factory=list, description="List of domain names (server_name directives)"
    )
    source_type: SourceType = Field(
        default="static_generate",
        description=(
            "How this connection is sourced: "
            "'nginx_config' = deploy an existing nginx config (with includes); "
            "'static_generate' = generate config from index.html + domains; "
            "'container' = reverse-proxy to a container/service host:port; "
            "'docker_compose' = bring up a user-supplied docker-compose file "
            "and reverse-proxy to one of its services."
        ),
    )
    nginx_config_path: str | None = Field(
        default=None,
        description="Path inside the backend container to an existing nginx .conf file. "
        "Used only when source_type='nginx_config'. Includes are resolved recursively "
        "relative to the config's directory.",
    )
    static_dir: str | None = Field(
        default=None,
        description="Path to a directory (or index.html) used to generate a static site. "
        "Used only when source_type='static_generate'.",
    )
    backend_url: str = Field(
        default="",
        description="Backend target (e.g. 'myservice:8080' or 'http://myservice:8080'). "
        "Used only when source_type='container' or 'docker_compose'.",
    )
    compose_yaml: str | None = Field(
        default=None,
        description="Inline docker-compose YAML body. Used only when "
        "source_type='docker_compose'. The backend writes it to a project "
        "directory and runs 'docker compose up -d' against it.",
    )
    compose_service: str | None = Field(
        default=None,
        description="Name of the compose service to reverse-proxy to. "
        "Used only when source_type='docker_compose'.",
    )
    compose_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Port on the compose service to proxy to. Used only when "
        "source_type='docker_compose'.",
    )
    http_versions: str = Field(
        default="h1,h2",
        description=(
            "Comma-separated subset of {h1,h2,h3} this connection accepts. "
            "'h1' = plain HTTP/1.1 on port 80, 'h2' = HTTP/2 over TLS on 443, "
            "'h3' = HTTP/3 (QUIC) on UDP/443. Defaults to 'h1,h2'."
        ),
    )
    compression_algo: CompressionAlgo = Field(
        default="auto",
        description=(
            "Compression strategy: 'auto' lets Angie negotiate via "
            "Accept-Encoding (zstd > brotli > gzip), or pin a single algo: "
            "'gzip', 'brotli', 'zstd', or 'none' to disable."
        ),
    )
    enabled: bool = Field(default=True, description="Whether this connection is active")
    ssl_enabled: bool = Field(default=False, description="Enable SSL/TLS for this site")
    ssl_cert_path: str | None = Field(default=None, description="Path to SSL certificate file")
    ssl_key_path: str | None = Field(default=None, description="Path to SSL private key file")
    preserve_host: bool = Field(
        default=True, description="Preserve original Host header when proxying"
    )
    custom_nginx_config: str | None = Field(
        default=None, description="Additional custom Nginx directives"
    )


class ConnectionCreate(ConnectionBase):
    """Schema for creating a new connection."""

    @field_validator("http_versions", mode="before")
    @classmethod
    def _validate_http_versions(cls, value: object) -> str:
        return _normalize_http_versions(value)


class ConnectionUpdate(BaseModel):
    """Schema for updating an existing connection."""

    name: str | None = Field(None, min_length=1, max_length=128)
    domains: list[str] | None = None
    source_type: SourceType | None = None
    nginx_config_path: str | None = None
    static_dir: str | None = None
    backend_url: str | None = None
    compose_yaml: str | None = None
    compose_service: str | None = None
    compose_port: int | None = Field(None, ge=1, le=65535)
    http_versions: str | None = None
    compression_algo: CompressionAlgo | None = None
    enabled: bool | None = None

    @field_validator("http_versions", mode="before")
    @classmethod
    def _validate_http_versions(cls, value: object) -> str | None:
        if value is None:
            return None
        return _normalize_http_versions(value)

    ssl_enabled: bool | None = None
    ssl_cert_path: str | None = None
    ssl_key_path: str | None = None
    preserve_host: bool | None = None
    custom_nginx_config: str | None = None


class Connection(ConnectionBase):
    """Full connection model with id and timestamps."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
