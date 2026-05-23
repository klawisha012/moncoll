from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "(platform_role = 'admin' AND tenant_id IS NULL AND tenant_role IS NULL) "
            "OR (platform_role = 'client' AND tenant_id IS NOT NULL AND tenant_role IS NOT NULL)",
            name="users_platform_tenant_consistency",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform_role: Mapped[str] = mapped_column(
        Enum("admin", "client", name="platform_role"), nullable=False
    )
    tenant_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    tenant_role: Mapped[str | None] = mapped_column(
        Enum("owner", "member", name="tenant_role"), nullable=True
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    recovery_codes_hash: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(64)), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_account_id", name="uq_oauth_provider_account"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(
        Enum("google", "github", name="oauth_provider"), nullable=False
    )
    provider_account_id: Mapped[str] = mapped_column(String(128), nullable=False)
    email_at_provider: Mapped[str] = mapped_column(String(254), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    purpose: Mapped[str] = mapped_column(
        Enum("verify_email", "reset_password", name="email_verification_purpose"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class Connection(Base):
    """Domain-only reverse-proxy connection.

    Each row is one (domain, tenant) pair. The platform reverse-proxies
    https://domain → https://origin_hosts[*]:origin_port. State machine:
    pending_verification → pending_dns → provisioning_cert → active. See
    docs/superpowers/specs/2026-05-22-connections-domain-only-design.md.
    """

    __tablename__ = "connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Single domain per row, lowercase + IDNA-normalised, UNIQUE across the table.
    domain: Mapped[str] = mapped_column(String(253), nullable=False, unique=True)
    # List of resolved A/AAAA values at create time (multi-A → upstream pool).
    origin_hosts: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    origin_port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    # 'strict' = verify origin TLS cert against system CA bundle;
    # 'lenient' = HTTPS to origin but no cert verification (matches Cloudflare 'Full').
    origin_tls_mode: Mapped[str] = mapped_column(
        Enum("strict", "lenient", name="origin_tls_mode"),
        nullable=False,
        default="strict",
    )
    # Random token shown to user as TXT _waf-verify.<domain> value during onboarding.
    verify_token: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # State machine; see spec §3.
    status: Mapped[str] = mapped_column(
        Enum(
            "pending_verification",
            "pending_dns",
            "provisioning_cert",
            "active",
            "error",
            name="connection_status",
        ),
        nullable=False,
        default="pending_verification",
    )
    status_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    acme_retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    acme_next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Next time the background poller should evaluate this row.
    next_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dns_ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Edge presentation knobs.
    http_versions: Mapped[str] = mapped_column(String(32), nullable=False, default="h1,h2")
    compression_algo: Mapped[str] = mapped_column(String(16), nullable=False, default="auto")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # ACME-managed cert paths; populated once status transitions to 'active'.
    ssl_cert_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ssl_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
