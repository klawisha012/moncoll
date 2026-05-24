"""connections: per-connection ModSecurity state + GeoIP2 denied countries

Revision ID: 0006_per_connection_security
Revises: 0005_connections_domain_only
Create Date: 2026-05-24

Adds two columns to `connections` so each domain owns its own WAF state:

  - modsec_state  (enum off/detection_only/blocking, default detection_only)
  - geoip_denied_countries  (JSON list of ISO 3166-1 alpha-2 codes, default [])

Existing rows get `detection_only` + `[]`. This is a deliberate downgrade
from the pre-migration global blocking default — the operator opts back
into blocking per-connection through the rewritten /config UI.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_per_connection_security"
down_revision: Union[str, None] = "0005_connections_domain_only"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_MODSEC_STATE_ENUM = sa.Enum(
    "off", "detection_only", "blocking", name="modsec_state"
)


def upgrade() -> None:
    _MODSEC_STATE_ENUM.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "connections",
        sa.Column(
            "modsec_state",
            _MODSEC_STATE_ENUM,
            nullable=False,
            server_default="detection_only",
        ),
    )
    op.add_column(
        "connections",
        sa.Column(
            "geoip_denied_countries",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("connections", "geoip_denied_countries")
    op.drop_column("connections", "modsec_state")
    _MODSEC_STATE_ENUM.drop(op.get_bind(), checkfirst=True)
