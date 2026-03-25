from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .modsecurity import router as modsecurity_router
from .dashboard import router as dashboard_router
from .angie import router as angie_router


def create_app() -> FastAPI:
    app = FastAPI(title="WAF API", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(modsecurity_router)
    app.include_router(dashboard_router)
    app.include_router(angie_router)

    return app


app = create_app()
