"""ClickHouse views that depend on PostgreSQL tables.

Anything that references `postgresql(...)` table function must be created
AFTER Alembic provisions the PG schema — putting it in init.sql aborts
ClickHouse boot with UNKNOWN_TABLE. See configs/clickhouse/init.sql for
the matching note.
"""

import logging

from .service import _get_client

logger = logging.getLogger(__name__)


# View of all enabled connection domains, sourced from PostgreSQL. Used by
# the Grafana dashboard `connection` templating variable (label: "Domain")
# so the dropdown lists only domains belonging to active WAF connections —
# not every Host header ever seen in waf_audit_log (which leaks Docker
# bridge IPs, "angie", "localhost").
#
# ClickHouse reads `connections.domains` (PG JSON column) as text via the
# postgresql() table function; JSONExtract unpacks it into an Array(String),
# and arrayJoin fans it out to one row per domain. Credentials come from
# configs/clickhouse/config.d/named_collections.xml (the `postgres_waf`
# named collection reads POSTGRES_USER/PASSWORD/DB via from_env).
_CONNECTION_DOMAINS_VIEW_SQL = """
CREATE OR REPLACE VIEW logs.connection_domains AS
SELECT DISTINCT
    arrayJoin(JSONExtract(toString(domains), 'Array(String)')) AS domain
FROM postgresql(postgres_waf, table='connections')
WHERE enabled = true
  AND length(toString(domains)) > 2
ORDER BY domain
"""


def ensure_views() -> None:
    """Create (or replace) ClickHouse views that depend on PG tables.

    Best-effort: errors are logged but never raised. The dashboard will
    still work for non-domain panels even if this fails (e.g. ClickHouse
    unreachable on startup).
    """
    try:
        client = _get_client()
        client.execute(_CONNECTION_DOMAINS_VIEW_SQL)
        logger.info("ClickHouse view logs.connection_domains is up to date")
    except Exception:
        logger.exception("Failed to create logs.connection_domains VIEW")
