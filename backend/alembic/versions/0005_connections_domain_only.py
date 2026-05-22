"""connections: domain-only rewrite (drop 4-mode source_type machinery)

Revision ID: 0005_connections_domain_only
Revises: 0004_conn_http_compression
Create Date: 2026-05-22

Replaces the legacy 4-mode connection schema (nginx_config / static_generate /
container / docker_compose) with a single domain-only reverse-proxy model.

Drops: source_type, nginx_config_path, static_dir, backend_url, compose_yaml,
compose_service, compose_port, preserve_host, custom_nginx_config, ssl_enabled,
domains.

Adds: user_id FK, domain (UNIQUE), origin_hosts (JSON list), origin_port,
origin_tls_mode, verify_token, verified_at, status, status_detail,
acme_retry_count, acme_next_retry_at, next_poll_at, dns_ttl_seconds,
last_checked_at.

Existing rows from legacy modes are marked status='error' with a detail
explaining the migration — operator deletes and recreates them.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_connections_domain_only"
down_revision: Union[str, None] = "0004_conn_http_compression"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_STATUS_ENUM = sa.Enum(
    "pending_verification",
    "pending_dns",
    "provisioning_cert",
    "active",
    "error",
    name="connection_status",
)

_TLS_MODE_ENUM = sa.Enum("strict", "lenient", name="origin_tls_mode")


def upgrade() -> None:
    # ── New columns (nullable=False with server_default so they backfill cleanly
    #    on existing rows that will be marked status='error' below) ──
    op.add_column(
        "connections",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.add_column(
        "connections",
        sa.Column("domain", sa.String(length=253), nullable=True),
    )
    op.add_column(
        "connections",
        sa.Column(
            "origin_hosts", sa.JSON(), nullable=False, server_default=sa.text("'[]'")
        ),
    )
    op.add_column(
        "connections",
        sa.Column(
            "origin_port", sa.Integer(), nullable=False, server_default=sa.text("443")
        ),
    )
    _TLS_MODE_ENUM.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "connections",
        sa.Column(
            "origin_tls_mode",
            _TLS_MODE_ENUM,
            nullable=False,
            server_default="strict",
        ),
    )
    op.add_column(
        "connections",
        sa.Column("verify_token", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "connections",
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    _STATUS_ENUM.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "connections",
        sa.Column("status", _STATUS_ENUM, nullable=False, server_default="error"),
    )
    op.add_column(
        "connections",
        sa.Column("status_detail", sa.Text(), nullable=True),
    )
    op.add_column(
        "connections",
        sa.Column(
            "acme_retry_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "connections",
        sa.Column("acme_next_retry_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "connections",
        sa.Column("next_poll_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "connections",
        sa.Column(
            "dns_ttl_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
    )
    op.add_column(
        "connections",
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── Backfill: try to migrate domains[0] → domain so legacy rows keep
    #    something usable in the new column; mark them errored so the operator
    #    knows to recreate them through the new wizard. ──
    op.execute(
        """
        UPDATE connections
        SET domain = COALESCE(
                NULLIF(json_extract(domains, '$[0]'), ''),
                'legacy-row-' || id || '.invalid'
            ),
            status = 'error',
            status_detail = 'Migrated from legacy source_type; please recreate via domain-only wizard.'
        WHERE domain IS NULL
        """
    )

    # ── Tighten constraints now that data is in place ──
    op.alter_column("connections", "domain", existing_type=sa.String(length=253), nullable=False)
    op.create_unique_constraint("uq_connections_domain", "connections", ["domain"])

    # ── Drop legacy columns ──
    for col in (
        "source_type",
        "nginx_config_path",
        "static_dir",
        "backend_url",
        "compose_yaml",
        "compose_service",
        "compose_port",
        "preserve_host",
        "custom_nginx_config",
        "ssl_enabled",
        "domains",
    ):
        op.drop_column("connections", col)


def downgrade() -> None:
    op.add_column(
        "connections",
        sa.Column("domains", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "connections",
        sa.Column(
            "source_type",
            sa.String(length=32),
            nullable=False,
            server_default="static_generate",
        ),
    )
    op.add_column("connections", sa.Column("nginx_config_path", sa.String(length=512), nullable=True))
    op.add_column("connections", sa.Column("static_dir", sa.String(length=512), nullable=True))
    op.add_column(
        "connections",
        sa.Column("backend_url", sa.String(length=512), nullable=False, server_default=""),
    )
    op.add_column("connections", sa.Column("compose_yaml", sa.Text(), nullable=True))
    op.add_column("connections", sa.Column("compose_service", sa.String(length=128), nullable=True))
    op.add_column("connections", sa.Column("compose_port", sa.Integer(), nullable=True))
    op.add_column(
        "connections",
        sa.Column("preserve_host", sa.Boolean(), nullable=False, server_default=sa.text("1")),
    )
    op.add_column("connections", sa.Column("custom_nginx_config", sa.Text(), nullable=True))
    op.add_column(
        "connections",
        sa.Column("ssl_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
    )

    op.drop_constraint("uq_connections_domain", "connections", type_="unique")
    for col in (
        "last_checked_at",
        "dns_ttl_seconds",
        "next_poll_at",
        "acme_next_retry_at",
        "acme_retry_count",
        "status_detail",
        "status",
        "verified_at",
        "verify_token",
        "origin_tls_mode",
        "origin_port",
        "origin_hosts",
        "domain",
        "user_id",
    ):
        op.drop_column("connections", col)
    _STATUS_ENUM.drop(op.get_bind(), checkfirst=True)
    _TLS_MODE_ENUM.drop(op.get_bind(), checkfirst=True)
