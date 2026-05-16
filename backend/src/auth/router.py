import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import User
from ..db.session import get_session
from . import service as auth_service
from .dependencies import COOKIE_NAME, get_current_user, require_admin
from .schemas import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    UserCreate,
    UserPublic,
    UserUpdate,
)
from .security import JWT_TTL_SECONDS, create_access_token, verify_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _cookie_secure() -> bool:
    """Whether to set the Secure flag on the session cookie.

    Defaults to False so the panel works on plain-HTTP dev (localhost). In
    production set WAF_COOKIE_SECURE=true so the cookie is only sent over HTTPS.
    """
    return os.environ.get("WAF_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=JWT_TTL_SECONDS,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    try:
        await auth_service.seed_default_admin(session)
    except Exception:
        logger.exception("seed_default_admin failed during login")

    user = await auth_service.authenticate(session, payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )
    token = create_access_token(user_id=user.id, username=user.username, role=user.role)
    _set_session_cookie(response, token)
    return LoginResponse(
        user=UserPublic.model_validate(user),
        must_change_password=user.must_change_password,
    )


@router.post("/logout", status_code=204)
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return None


@router.get("/me", response_model=UserPublic)
async def me(user: User = Depends(get_current_user)):
    return UserPublic.model_validate(user)


@router.post("/change-password", response_model=UserPublic)
async def change_password(
    payload: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="current password is incorrect",
        )
    if not await auth_service.change_password(session, user.id, payload.new_password):
        raise HTTPException(status_code=500, detail="failed to update password")
    updated = await auth_service.get_user(session, user.id)
    return UserPublic.model_validate(updated)


@router.get("/users", response_model=list[UserPublic])
async def list_users(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    users = await auth_service.list_users(session)
    return [UserPublic.model_validate(u) for u in users]


@router.post("/users", response_model=UserPublic, status_code=201)
async def create_user(
    payload: UserCreate,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    try:
        user = await auth_service.create_user(session, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return UserPublic.model_validate(user)


@router.put("/users/{user_id}", response_model=UserPublic)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    try:
        result = await auth_service.update_user(session, user_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="user not found")
    return UserPublic.model_validate(result)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    try:
        ok = await auth_service.delete_user(session, user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=404, detail="user not found")
    return None
