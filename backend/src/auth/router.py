import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Response, status

from . import service as auth_service

logger = logging.getLogger(__name__)
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
def login(payload: LoginRequest, response: Response):
    # Ensure default admin exists (fallback if lifespan seeding failed)
    try:
        auth_service.seed_default_admin()
    except Exception:
        logger.exception("seed_default_admin failed during login")

    user = auth_service.authenticate(payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )
    token = create_access_token(
        user_id=user["id"], username=user["username"], role=user["role"]
    )
    _set_session_cookie(response, token)
    return LoginResponse(
        user=UserPublic(**user),
        must_change_password=user.get("must_change_password", False),
    )


@router.post("/logout", status_code=204)
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return None


@router.get("/me", response_model=UserPublic)
def me(user: dict = Depends(get_current_user)):
    return UserPublic(**user)


@router.post("/change-password", response_model=UserPublic)
def change_password(
    payload: ChangePasswordRequest,
    user: dict = Depends(get_current_user),
):
    if not verify_password(payload.current_password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="current password is incorrect",
        )
    if not auth_service.change_password(user["id"], payload.new_password):
        raise HTTPException(status_code=500, detail="failed to update password")
    updated = auth_service.get_user(user["id"])
    return UserPublic(**updated)


@router.get("/users", response_model=list[UserPublic])
def list_users(_: dict = Depends(require_admin)):
    return auth_service.list_users()


@router.post("/users", response_model=UserPublic, status_code=201)
def create_user(payload: UserCreate, _: dict = Depends(require_admin)):
    try:
        return auth_service.create_user(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put("/users/{user_id}", response_model=UserPublic)
def update_user(
    user_id: int,
    payload: UserUpdate,
    _: dict = Depends(require_admin),
):
    try:
        result = auth_service.update_user(user_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail="user not found")
    return result


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, _: dict = Depends(require_admin)):
    try:
        ok = auth_service.delete_user(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=404, detail="user not found")
    return None
