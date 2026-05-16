from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
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
    __tablename__ = "connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    # One of: "nginx_config" (deploy from existing nginx config with includes),
    # "static_generate" (generate config from an index.html + domains),
    # "container" (reverse-proxy to a container/service host:port).
    source_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="static_generate"
    )
    nginx_config_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    backend_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    static_dir: Mapped[str | None] = mapped_column(String(512), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ssl_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ssl_cert_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ssl_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    preserve_host: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    custom_nginx_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
