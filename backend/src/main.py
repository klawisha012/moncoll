import asyncio
import logging
import os
from contextlib import asynccontextmanager

# Без basicConfig logging.getLogger(__name__) пишет на root logger которого
# uvicorn не настраивает — наши module-level INFO-сообщения молча
# теряются. Явно выставляем INFO чтобы видеть lifecycle от poller и
# realtime consumer'а.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from .admin.router import router as admin_router
from .auth import auth_router
from .auth.dependencies import require_admin, require_verified
from .certificates import certificates_router
from .connections import poller as connections_poller
from .connections.router import connections_router
from .crowdsec.router import router as crowdsec_router
from .dashboard.router import router as dashboard_router
from .modsecurity import router as modsecurity_router
from .monitoring import router as monitoring_router
from .realtime import realtime_router
from .realtime import consumer as realtime_consumer
from .tests import tests_router

logger = logging.getLogger(__name__)


def _allowed_origins() -> list[str]:
    """Allowed CORS origins. Override via WAF_ALLOWED_ORIGINS (comma-separated)."""
    raw = os.environ.get("WAF_ALLOWED_ORIGINS")
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Connections poller (spec §5 poller.py): single asyncio task that
    #    walks pending rows, verifies TXT ownership, detects DNS-flip onto
    #    the WAF edge, and triggers ACME. Started under lifespan so it
    #    shares the API server's event loop and dies cleanly on shutdown.
    poller_stop = asyncio.Event()
    poller_task = asyncio.create_task(connections_poller.run_forever(poller_stop))

    # ── Realtime consumer (see backend/src/realtime/__init__.py):
    #    subscribes to Redis pub/sub `attacks:raw` (Vector publishes there),
    #    aggregates geoip events 500ms-batched, publishes deltas to
    #    Centrifugo channel `dashboard:map`. Single-instance assumption —
    #    horizontal scale-out must run this as a separate worker process.
    realtime_stop = asyncio.Event()
    realtime_task = asyncio.create_task(realtime_consumer.run_forever(realtime_stop))

    try:
        yield
    finally:
        poller_stop.set()
        realtime_stop.set()
        for name, task in (("poller", poller_task), ("realtime", realtime_task)):
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except (TimeoutError, asyncio.TimeoutError):
                logger.warning("lifespan: %s task did not stop in time, cancelling", name)
                task.cancel()


def create_app() -> FastAPI:
    app = FastAPI(title="WAF API", version="1.0.0", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Auth router is public (login/logout/me/change-password). User-management
    # endpoints inside it are individually guarded by require_admin.
    app.include_router(auth_router)

    # Admin router — all routes require admin + TOTP via require_admin dep.
    app.include_router(admin_router)

    # Verified-user gate covers every client-facing surface. Tenant scoping is
    # enforced per-route via `current_tenant` (e.g. connections, certificates)
    # so this app-level dep only confirms the session is authenticated and the
    # email is verified.
    viewer = [Depends(require_verified)]
    app.include_router(dashboard_router, dependencies=viewer)
    app.include_router(realtime_router, dependencies=viewer)
    app.include_router(connections_router, dependencies=viewer)
    app.include_router(certificates_router, dependencies=viewer)
    # CrowdSec + ModSecurity expose global (not tenant-scoped) configuration.
    # The frontend gates these pages with `RequireRole role="client"`, so the
    # backend gate must let verified clients through. Admins still pass since
    # require_admin → require_verified.
    app.include_router(modsecurity_router, dependencies=viewer)
    app.include_router(crowdsec_router, dependencies=viewer)

    # Monitoring stays admin-only — Docker stats are platform-wide infra data,
    # not exposed to clients. Per-route require_admin keeps it belt-and-braces.
    admin = [Depends(require_admin)]
    app.include_router(monitoring_router, dependencies=admin)

    # Tests router is wired without app-level deps — POST /run needs the User
    # identity for in-process rate-limiting plus the Tenant for connection_id
    # scoping, both injected per-route.
    app.include_router(tests_router)

    # Expose Prometheus metrics endpoint (intentionally unauthenticated so the
    # Prometheus scraper inside the docker-compose stack keeps working).
    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    return app


app = create_app()
