"""connections: replace mode with source_type, add nginx_config_path

Revision ID: 0002_connection_source_type
Revises: 0001_initial
Create Date: 2026-05-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_connection_source_type"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "connections",
        sa.Column(
            "source_type",
            sa.String(length=32),
            nullable=False,
            server_default="static_generate",
        ),
    )
    op.add_column(
        "connections",
        sa.Column("nginx_config_path", sa.String(length=512), nullable=True),
    )

    op.execute(
        "UPDATE connections SET source_type = 'container' WHERE mode = 'proxy'"
    )
    op.execute(
        "UPDATE connections SET source_type = 'static_generate' WHERE mode = 'static'"
    )

    op.drop_column("connections", "mode")


def downgrade() -> None:
    op.add_column(
        "connections",
        sa.Column(
            "mode",
            sa.String(length=16),
            nullable=False,
            server_default="proxy",
        ),
    )
    op.execute(
        "UPDATE connections SET mode = 'proxy' WHERE source_type = 'container'"
    )
    op.execute(
        "UPDATE connections SET mode = 'static' "
        "WHERE source_type IN ('static_generate', 'nginx_config')"
    )
    op.drop_column("connections", "nginx_config_path")
    op.drop_column("connections", "source_type")
