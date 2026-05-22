import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from .angie import router as angie_router
from .auth import auth_router
from .auth import service as auth_service
from .auth.dependencies import require_admin, require_password_changed
from .certificates import certificates_router
from .connections import poller as connections_poller
from .connections.router import connections_router
from .crowdsec.router import router as crowdsec_router
from .dashboard import clickhouse_init
from .dashboard.router import router as dashboard_router
from .db.base import get_sessionmaker
from .modsecurity import router as modsecurity_router
from .monitoring import router as monitoring_router
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
    try:
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            await auth_service.seed_default_admin(session)
    except Exception as exc:
        logger.exception("Failed to seed default admin user: %s", exc)
    # Re-create the ClickHouse → PG bridge VIEW now that Alembic has run.
    # init.sql can't do this — the connections table doesn't exist yet at
    # ClickHouse boot. See dashboard/clickhouse_init.py.
    clickhouse_init.ensure_views()

    # ── Connections poller (spec §5 poller.py): single asyncio task that
    #    walks pending rows, verifies TXT ownership, detects DNS-flip onto
    #    the WAF edge, and triggers ACME. Started under lifespan so it
    #    shares the API server's event loop and dies cleanly on shutdown.
    poller_stop = asyncio.Event()
    poller_task = asyncio.create_task(connections_poller.run_forever(poller_stop))
    try:
        yield
    finally:
        poller_stop.set()
        try:
            await asyncio.wait_for(poller_task, timeout=5.0)
        except (TimeoutError, asyncio.TimeoutError):
            poller_task.cancel()


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

    # Dashboard & Monitoring — accessible to both admin and viewer roles.
    viewer = [Depends(require_password_changed)]
    app.include_router(dashboard_router, dependencies=viewer)
    app.include_router(monitoring_router, dependencies=viewer)

    # Admin-only routers — viewer role cannot access configuration or security.
    admin = [Depends(require_admin)]
    app.include_router(modsecurity_router, dependencies=admin)
    app.include_router(angie_router, dependencies=admin)
    app.include_router(connections_router, dependencies=admin)
    app.include_router(certificates_router, dependencies=admin)
    app.include_router(crowdsec_router, dependencies=admin)
    # Tests router is wired with its own require_admin dep per-route — the
    # POST /run endpoint needs the User identity for in-process rate-limiting,
    # which the app-level `dependencies=admin` pattern can't expose.
    app.include_router(tests_router)

    # Expose Prometheus metrics endpoint (intentionally unauthenticated so the
    # Prometheus scraper inside the docker-compose stack keeps working).
    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    return app


app = create_app()
