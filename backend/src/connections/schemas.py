from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ConnectionBase(BaseModel):
    """Base connection model with common fields."""

    name: str = Field(
        ..., min_length=1, max_length=128, description="Human-readable name for this connection"
    )
    domains: list[str] = Field(
        default_factory=list, description="List of domain names (server_name directives)"
    )
    backend_url: str = Field(..., description="Backend target URL (proxy_pass destination)")
    enabled: bool = Field(default=True, description="Whether this proxy rule is active")
    ssl_enabled: bool = Field(default=False, description="Enable SSL/TLS for this site")
    ssl_cert_path: Optional[str] = Field(default=None, description="Path to SSL certificate file")
    ssl_key_path: Optional[str] = Field(default=None, description="Path to SSL private key file")
    preserve_host: bool = Field(
        default=True, description="Preserve original Host header when proxying"
    )
    custom_nginx_config: Optional[str] = Field(
        default=None, description="Additional custom Nginx directives"
    )


class ConnectionCreate(ConnectionBase):
    """Schema for creating a new connection."""

    pass


class ConnectionUpdate(BaseModel):
    """Schema for updating an existing connection."""

    name: Optional[str] = Field(None, min_length=1, max_length=128)
    domains: Optional[list[str]] = None
    backend_url: Optional[str] = None
    enabled: Optional[bool] = None
    ssl_enabled: Optional[bool] = None
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    preserve_host: Optional[bool] = None
    custom_nginx_config: Optional[str] = None


class Connection(ConnectionBase):
    """Full connection model with id and timestamps."""

    id: int = Field(..., description="Unique identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True
