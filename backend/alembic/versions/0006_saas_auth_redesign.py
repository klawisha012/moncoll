"""saas_auth_redesign: wipe users/connections and recreate with multi-tenant schema

Revision ID: 0006
Revises: 0005_connections_domain_only
Create Date: 2026-05-23

Wipe-and-restart migration per spec §10. Not reversible.
Task 1.3 audit: grep -rn "__tablename__" backend/src/ found only users + connections.
No other tenant-scoped tables exist — no additional ALTER TABLE calls needed.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005_connections_domain_only"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop legacy auth state. Wipe-and-restart per spec §10.
    op.execute("DROP TABLE IF EXISTS connections CASCADE")
    op.execute("DROP TABLE IF EXISTS users CASCADE")
    op.execute("DROP TYPE IF EXISTS origin_tls_mode CASCADE")
    op.execute("DROP TYPE IF EXISTS connection_status CASCADE")

    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(32), nullable=False, unique=True),
        sa.Column("display_name", sa.String(64), nullable=False),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_tenants_name", "tenants", ["name"])

    platform_role = postgresql.ENUM("admin", "client", name="platform_role")
    tenant_role = postgresql.ENUM("owner", "member", name="tenant_role")
    platform_role.create(op.get_bind(), checkfirst=True)
    tenant_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False, unique=True),
        sa.Column("display_name", sa.String(64), nullable=False, server_default=""),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("platform_role", postgresql.ENUM("admin", "client", name="platform_role", create_type=False), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("tenant_role", postgresql.ENUM("owner", "member", name="tenant_role", create_type=False), nullable=True),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totp_secret", sa.String(64), nullable=True),
        sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovery_codes_hash", postgresql.ARRAY(sa.String(64)), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "(platform_role = 'admin' AND tenant_id IS NULL AND tenant_role IS NULL) "
            "OR (platform_role = 'client' AND tenant_id IS NOT NULL AND tenant_role IS NOT NULL)",
            name="users_platform_tenant_consistency",
        ),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    oauth_provider = postgresql.ENUM("google", "github", name="oauth_provider")
    oauth_provider.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "oauth_accounts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", postgresql.ENUM("google", "github", name="oauth_provider", create_type=False), nullable=False),
        sa.Column("provider_account_id", sa.String(128), nullable=False),
        sa.Column("email_at_provider", sa.String(254), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("provider", "provider_account_id", name="uq_oauth_provider_account"),
    )
    op.create_index("ix_oauth_accounts_user_id", "oauth_accounts", ["user_id"])

    email_verification_purpose = postgresql.ENUM("verify_email", "reset_password", name="email_verification_purpose")
    email_verification_purpose.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "email_verifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", postgresql.ENUM("verify_email", "reset_password", name="email_verification_purpose", create_type=False), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_email_verifications_token_hash", "email_verifications", ["token_hash"])
    op.create_index("ix_email_verifications_user_id", "email_verifications", ["user_id"])

    origin_tls_mode = postgresql.ENUM("strict", "lenient", name="origin_tls_mode")
    connection_status = postgresql.ENUM(
        "pending_verification", "pending_dns", "provisioning_cert", "active", "error", name="connection_status"
    )
    origin_tls_mode.create(op.get_bind(), checkfirst=True)
    connection_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False, unique=True),
        sa.Column("origin_hosts", sa.JSON(), nullable=False),
        sa.Column("origin_port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("origin_tls_mode", postgresql.ENUM("strict", "lenient", name="origin_tls_mode", create_type=False), nullable=False, server_default="strict"),
        sa.Column("verify_token", sa.String(64), nullable=False, server_default=""),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", postgresql.ENUM("pending_verification", "pending_dns", "provisioning_cert", "active", "error", name="connection_status", create_type=False), nullable=False, server_default="pending_verification"),
        sa.Column("status_detail", sa.Text(), nullable=True),
        sa.Column("acme_retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("acme_next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dns_ttl_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("http_versions", sa.String(32), nullable=False, server_default="h1,h2"),
        sa.Column("compression_algo", sa.String(16), nullable=False, server_default="auto"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("ssl_cert_path", sa.String(512), nullable=True),
        sa.Column("ssl_key_path", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_connections_tenant_id", "connections", ["tenant_id"])


def downgrade() -> None:
    raise RuntimeError("wipe-and-restart migration is not reversible")
