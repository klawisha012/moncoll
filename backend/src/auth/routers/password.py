"""Password-based auth endpoints: signup, verify-email, login, logout, me, forgot/reset."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...db.models import User
from ...db.session import get_session
from ...tenants import service as tenants_service
from .. import captcha, email as mailer
from .. import service as auth_service
from .. import verification
from ..dependencies import SESSION_COOKIE, TOTP_ENROL_COOKIE, get_current_user
from ..schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    ResetPasswordRequest,
    SignupRequest,
    UserPublic,
    VerifyEmailRequest,
)
from ..security import SESSION_TTL_SECONDS, create_session_token, sign_short_lived

from ..totp import verify_code, verify_recovery

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


def _set_session_cookie(response: Response, token: str) -> None:
    s = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
    )


# Cloudflare Turnstile test site key — always passes verification. Used when
# WAF_TURNSTILE_SITE_KEY is not configured, so the captcha widget remains
# visible in dev/staging without requiring a real Cloudflare account.
# See https://developers.cloudflare.com/turnstile/troubleshooting/testing/
_TURNSTILE_DEV_SITE_KEY = "1x00000000000000000000AA"


@router.get("/providers")
async def providers():
    s = get_settings()
    return {
        "google": s.oauth_google_enabled,
        "github": s.oauth_github_enabled,
        # Fall back to the dev/test key so the widget renders. The companion
        # _SECRET_KEY is intentionally left unset — captcha.verify() short-
        # circuits to True when the secret is absent (see captcha.py), which
        # matches the test key's "always pass" behaviour. To enforce captcha
        # in production set both WAF_TURNSTILE_SITE_KEY and _SECRET_KEY.
        "captcha_site_key": s.turnstile_site_key or _TURNSTILE_DEV_SITE_KEY,
        "captcha_dev_mode": not s.turnstile_site_key,
        "smtp_dev_mode": not s.smtp_host,
    }


@router.post("/signup", status_code=202)
async def signup(
    payload: SignupRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    await captcha.verify_or_raise(payload.captcha_token, request)

    try:
        tenant = await tenants_service.create_tenant(
            session,
            name=payload.tenant_name,
            display_name=payload.tenant_name,
        )
    except tenants_service.InvalidTenantName:
        raise HTTPException(status_code=400, detail="invalid tenant name") from None
    except tenants_service.TenantNameTaken:
        raise HTTPException(status_code=409, detail="tenant name taken") from None

    try:
        user = await auth_service.create_client_user(
            session,
            email=payload.email,
            password=payload.password,
            tenant_id=tenant.id,
            tenant_role="owner",
            display_name=payload.display_name or "",
            email_verified=False,
        )
    except auth_service.EmailTaken:
        raise HTTPException(status_code=409, detail="email already in use") from None

    token = await verification.issue(session, user, purpose="verify_email")
    s = get_settings()
    verify_url = f"{s.public_base_url}/verify-email?token={token}"
    await mailer.send_verify_email(
        to_email=user.email,
        display_name=user.display_name,
        verify_url=verify_url,
    )
    body: dict = {"message": "check your email"}
    # Dev mode: SMTP not configured → email was logged, not sent. Include the
    # verify URL in the response so the UI can show it directly. This is gated
    # on smtp_host being absent so production never leaks tokens via the API.
    if not s.smtp_host:
        body["dev_verify_url"] = verify_url
    return body


@router.post("/verify-email", response_model=LoginResponse)
async def verify_email(
    payload: VerifyEmailRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    user = await verification.consume(session, payload.token, purpose="verify_email")
    if not user:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    await auth_service.mark_email_verified(session, user)
    token = create_session_token(
        user_id=user.id,
        platform_role=user.platform_role,
        tenant_id=user.tenant_id,
        tenant_role=user.tenant_role,
    )
    _set_session_cookie(response, token)
    return LoginResponse(user=UserPublic.from_user(user))


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    if await auth_service.count_admins(session) == 0:
        raise HTTPException(status_code=503, detail="system not provisioned")

    await captcha.verify_or_raise(payload.captcha_token, request)

    user = await auth_service.authenticate(session, payload.email.lower(), payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")
    if user.email_verified_at is None:
        raise HTTPException(status_code=403, detail="email not verified")

    needs_totp = user.platform_role == "admin" or (
        user.platform_role == "client" and user.totp_enabled_at is not None
    )
    if needs_totp:
        if user.totp_secret is None:
            # Admin first-login — need TOTP enrolment.
            # Must return a JSONResponse (not raise HTTPException) so that the
            # Set-Cookie header is preserved in the error response; FastAPI's
            # exception handler discards the response object.
            enrol_cookie = sign_short_lived(
                {"user_id": user.id}, ttl_seconds=600, purpose="totp_enrol"
            )
            s = get_settings()
            json_resp = JSONResponse(
                status_code=403,
                content={"detail": "totp_enrol_required"},
            )
            json_resp.set_cookie(
                TOTP_ENROL_COOKIE,
                enrol_cookie,
                max_age=600,
                httponly=True,
                secure=s.cookie_secure,
                samesite="lax",
                path="/",
            )
            return json_resp
        if not payload.totp_code:
            raise HTTPException(status_code=401, detail="totp_required")
        if not (
            verify_code(user.totp_secret, payload.totp_code)
            or await verify_recovery(session, user, payload.totp_code)
        ):
            raise HTTPException(status_code=401, detail="invalid totp")

    await auth_service.touch_login(session, user)
    token = create_session_token(
        user_id=user.id,
        platform_role=user.platform_role,
        tenant_id=user.tenant_id,
        tenant_role=user.tenant_role,
    )
    _set_session_cookie(response, token)
    return LoginResponse(user=UserPublic.from_user(user))


@router.post("/logout", status_code=204)
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return None


@router.get("/me", response_model=UserPublic)
async def me(user: User = Depends(get_current_user)):
    return UserPublic.from_user(user)


@router.post("/password/forgot", status_code=202)
async def forgot(
    payload: ForgotPasswordRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    await captcha.verify_or_raise(payload.captcha_token, request)
    user = await auth_service.get_by_email(session, payload.email)
    s = get_settings()
    dev_url: str | None = None
    if user and user.email_verified_at:
        token = await verification.issue(session, user, purpose="reset_password")
        reset_url = f"{s.public_base_url}/reset-password?token={token}"
        await mailer.send_password_reset(
            to_email=user.email,
            display_name=user.display_name,
            reset_url=reset_url,
        )
        if not s.smtp_host:
            dev_url = reset_url
    body: dict = {"message": "if that email exists, a reset link was sent"}
    if dev_url is not None:
        body["dev_reset_url"] = dev_url
    return body


@router.post("/password/reset", status_code=204)
async def reset(
    payload: ResetPasswordRequest,
    session: AsyncSession = Depends(get_session),
):
    user = await verification.consume(session, payload.token, purpose="reset_password")
    if not user:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    await auth_service.update_password(session, user, payload.new_password)
    return None
