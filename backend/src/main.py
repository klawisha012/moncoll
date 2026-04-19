from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse

from .angie import router as angie_router
from .modsecurity import router as modsecurity_router
from .connections.router import connections_router


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
    app.include_router(angie_router)
    app.include_router(connections_router)

    return app


app = create_app()
