from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ConnectionBase(BaseModel):
    """Base connection model with common fields."""

    name: str = Field(
        ..., min_length=1, max_length=128, description="Human-readable name for this connection"
    )
    domains: list[str] = Field(
        default_factory=list, description="List of domain names (server_name directives)"
    )
    mode: Literal["proxy", "static"] = Field(
        default="proxy", description="Connection mode: proxy to backend or serve static files"
    )
    backend_url: str = Field(
        default="", description="Backend target URL (proxy_pass destination) — required for proxy mode"
    )
    static_dir: str | None = Field(
        default=None, description="Source directory for static site (backend-accessible path, e.g. 'examples' → /app/site-templates/examples). Content is copied into http.d/conn_<id>/site/ on creation."
    )
    enabled: bool = Field(default=True, description="Whether this proxy rule is active")
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
    mode: Literal["proxy", "static"] | None = None
    backend_url: str | None = None
    static_dir: str | None = None
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
