"""ModSecurity / CrowdSec test runner module.

Exposes an admin-only API used by the Tests tab of the frontend to:
- enumerate parametrised attack payloads (catalog from a build-time manifest)
- trigger a single test (HTTP request tagged with X-Test-Marker)
- correlate the marker back to the WAF audit log so the chart can highlight
  the resulting spike

See docs/design/zwarder-main-design-tests-tab-20260521.md for the design.
"""

from .router import router as tests_router

__all__ = ["tests_router"]
