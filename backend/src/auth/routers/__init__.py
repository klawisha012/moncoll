from fastapi import APIRouter

from . import password, totp

auth_router = APIRouter(prefix="/api/auth")
auth_router.include_router(password.router)
auth_router.include_router(totp.router)

__all__ = ["auth_router"]
