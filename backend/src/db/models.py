from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


class Connection(Base):
    """Domain-only reverse-proxy connection.

    Each row is one (domain, owner) pair. The platform reverse-proxies
    https://domain → https://origin_hosts[*]:origin_port. State machine:
    pending_verification → pending_dns → provisioning_cert → active. See
    docs/superpowers/specs/2026-05-22-connections-domain-only-design.md.
    """

    __tablename__ = "connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True
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
    # Next time the background poller should evaluate this row. Set to
    # max(60s, dns_ttl_seconds) after each tick so we honour DNS TTL while
    # never busy-looping.
    next_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dns_ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Edge presentation knobs (kept from pre-rewrite schema; not origin-related).
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
