"""connections: add docker_compose fields (compose_yaml, compose_service, compose_port)

Revision ID: 0003_connection_docker_compose
Revises: 0002_connection_source_type
Create Date: 2026-05-19
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_connection_docker_compose"
down_revision: Union[str, None] = "0002_connection_source_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "connections",
        sa.Column("compose_yaml", sa.Text(), nullable=True),
    )
    op.add_column(
        "connections",
        sa.Column("compose_service", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "connections",
        sa.Column("compose_port", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("connections", "compose_port")
    op.drop_column("connections", "compose_service")
    op.drop_column("connections", "compose_yaml")
