"""connections: add http_versions + compression_algo fields

Revision ID: 0004_conn_http_compression
Revises: 0003_connection_docker_compose
Create Date: 2026-05-19

Note: revision ID kept short (<= 32 chars) because alembic_version.version_num
is a VARCHAR(32) and longer IDs raise StringDataRightTruncationError.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_conn_http_compression"
down_revision: Union[str, None] = "0003_connection_docker_compose"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "connections",
        sa.Column(
            "http_versions",
            sa.String(length=32),
            nullable=False,
            server_default="h1,h2",
        ),
    )
    op.add_column(
        "connections",
        sa.Column(
            "compression_algo",
            sa.String(length=16),
            nullable=False,
            server_default="auto",
        ),
    )


def downgrade() -> None:
    op.drop_column("connections", "compression_algo")
    op.drop_column("connections", "http_versions")
