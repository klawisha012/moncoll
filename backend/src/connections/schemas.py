from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SourceType = Literal["nginx_config", "static_generate", "container"]


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
            "'container' = reverse-proxy to a container/service host:port."
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
        "Used only when source_type='container'.",
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

    pass


class ConnectionUpdate(BaseModel):
    """Schema for updating an existing connection."""

    name: str | None = Field(None, min_length=1, max_length=128)
    domains: list[str] | None = None
    source_type: SourceType | None = None
    nginx_config_path: str | None = None
    static_dir: str | None = None
    backend_url: str | None = None
    enabled: bool | None = None
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
