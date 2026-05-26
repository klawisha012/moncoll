"""connections: add crowdsec_active column

Revision ID: 0008_connection_crowdsec
Revises: 0007_per_connection_security
Create Date: 2026-05-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_connection_crowdsec"
down_revision: Union[str, None] = "0007_per_connection_security"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "connections",
        sa.Column(
            "crowdsec_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )


def downgrade() -> None:
    op.drop_column("connections", "crowdsec_active")
