"""TOTP enrolment endpoints: /totp/setup and /totp/confirm."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ...db.session import get_session
from .. import service as auth_service
from .. import totp
from ..dependencies import SESSION_COOKIE, TOTP_ENROL_COOKIE, get_current_user
from ..schemas import TotpConfirmRequest, UserPublic
from ..security import SESSION_TTL_SECONDS, create_session_token, verify_short_lived

router = APIRouter(tags=["totp"])


def _set_session_cookie(response: Response, token: str) -> None:
    from ...config import get_settings as _get_settings

    s = _get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
    )


async def _resolve_user(request: Request, session: AsyncSession):
    """Return user from session cookie or TOTP enrol cookie, or None."""
    # Try session cookie first (logged-in user adding 2FA)
    sess_token = request.cookies.get(SESSION_COOKIE)
    if sess_token:
        try:
            return await get_current_user(request, session)
        except HTTPException:
            pass

    # Fall back to short-lived enrol cookie (admin first-login flow)
    enrol = request.cookies.get(TOTP_ENROL_COOKIE)
    if enrol:
        payload = verify_short_lived(enrol, purpose="totp_enrol")
        if payload:
            return await auth_service.get_user(session, payload["user_id"])

    return None


@router.post("/totp/setup")
async def totp_setup(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Generate a new TOTP secret + recovery codes for the authenticated user.

    Accepts either a live session cookie (profile flow) or the short-lived
    ``waf_totp_enrol`` cookie issued on admin first-login.
    """
    user = await _resolve_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="not authorized for totp enrol")

    secret = totp.generate_secret()
    plain, hashes = totp.generate_recovery_codes()
    user.totp_secret = secret
    user.recovery_codes_hash = hashes
    await session.commit()

    uri = totp.provisioning_uri(secret, account_label=user.email)
    return {
        "secret_base32": secret,
        "qr_code_data_uri": totp.qr_data_uri(uri),
        "recovery_codes": plain,
    }


@router.post("/totp/confirm")
async def totp_confirm(
    payload: TotpConfirmRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    """Confirm a TOTP code, activate TOTP, and issue a full session cookie.

    Accepts either a live session cookie (profile flow) or the short-lived
    ``waf_totp_enrol`` cookie issued on admin first-login.
    """
    user = await _resolve_user(request, session)
    if user is None or not user.totp_secret:
        raise HTTPException(status_code=401, detail="not enrolled")

    if not totp.verify_code(user.totp_secret, payload.code):
        raise HTTPException(status_code=400, detail="invalid code")

    await totp.activate(session, user)

    # Clear the enrol cookie and issue a real session
    response.delete_cookie(TOTP_ENROL_COOKIE, path="/")
    session_token = create_session_token(
        user_id=user.id,
        platform_role=user.platform_role,
        tenant_id=user.tenant_id,
        tenant_role=user.tenant_role,
    )
    _set_session_cookie(response, session_token)
    return {"ok": True, "user": UserPublic.from_user(user).model_dump()}
