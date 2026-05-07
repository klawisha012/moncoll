from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse
from prometheus_fastapi_instrumentator import Instrumentator

from .angie import router as angie_router
from .modsecurity import router as modsecurity_router
from .connections.router import connections_router
from .certificates import certificates_router
from .monitoring import router as monitoring_router
from .crowdsec.router import router as crowdsec_router
from .dashboard.router import router as dashboard_router


def create_app() -> FastAPI:
    app = FastAPI(title="WAF API", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(modsecurity_router)
    app.include_router(angie_router)
    app.include_router(connections_router)
    app.include_router(certificates_router)
    app.include_router(monitoring_router)
    app.include_router(crowdsec_router)
    app.include_router(dashboard_router)

    # Expose Prometheus metrics endpoint
    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    return app


app = create_app()
