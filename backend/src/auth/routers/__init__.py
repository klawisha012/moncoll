from fastapi import APIRouter

from .password import router as _password_router

auth_router = APIRouter(prefix="/api/auth")
auth_router.include_router(_password_router)

__all__ = ["auth_router"]
