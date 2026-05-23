from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Tenant, User
from ..db.session import get_session
from . import service as auth_service
from .security import decode_session_token

SESSION_COOKIE = "waf_session"
TOTP_ENROL_COOKIE = "waf_totp_enrol"


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
        )
    payload = decode_session_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired session",
        )
    try:
        user_id = int(payload.get("sub", "0"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid session",
        ) from exc
    user = await auth_service.get_user(session, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user no longer exists",
        )
    return user


async def require_verified(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Verified email + (if client) tenant not suspended.

    Suspension check lives here so every authenticated endpoint inherits it,
    not only those that go through require_client. Admin has no tenant_id so
    the suspension branch is a no-op for them.
    """
    if user.email_verified_at is None:
        raise HTTPException(status_code=403, detail="email not verified")
    if user.tenant_id is not None:
        tenant = await session.get(Tenant, user.tenant_id)
        if tenant and tenant.suspended_at is not None:
            raise HTTPException(status_code=403, detail="tenant suspended")
    return user


async def require_admin(user: User = Depends(require_verified)) -> User:
    if user.platform_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required",
        )
    if user.totp_enabled_at is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TOTP enrolment required for admin access",
        )
    return user


async def require_client(user: User = Depends(require_verified)) -> User:
    if user.platform_role != "client":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="client role required",
        )
    return user


async def require_tenant_owner(user: User = Depends(require_verified)) -> User:
    if user.tenant_role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tenant owner role required",
        )
    return user


async def current_tenant(
    user: User = Depends(require_verified),
    session: AsyncSession = Depends(get_session),
) -> Tenant:
    if user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="user has no tenant",
        )
    tenant = await session.get(Tenant, user.tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="tenant not found",
        )
    return tenant


# ---------------------------------------------------------------------------
# Backwards-compat shims — removed in Phase 8 when router.py is rewritten.
# ---------------------------------------------------------------------------

# Legacy router.py imports COOKIE_NAME.
COOKIE_NAME = SESSION_COOKIE

# Legacy main.py and realtime/router.py import require_password_changed.
# The new model has no must_change_password concept; map to require_verified.
require_password_changed = require_verified
