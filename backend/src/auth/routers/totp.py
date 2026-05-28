"""TOTP enrolment endpoints: /totp/setup and /totp/confirm."""

import logging
from collections import defaultdict
from time import monotonic

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ...db.session import get_session
from .. import service as auth_service
from .. import totp
from ..dependencies import SESSION_COOKIE, TOTP_ENROL_COOKIE, get_current_user
from ..schemas import TotpConfirmRequest, UserPublic
from ..security import SESSION_TTL_SECONDS, create_session_token, verify_short_lived, sign_short_lived, encrypt_short_lived, decrypt_short_lived

logger = logging.getLogger(__name__)

router = APIRouter(tags=["totp"])


# ── Rate limit for /totp/confirm — keyed by user_id ──────────────────────────
#
# Threat: if the short-lived enrol cookie leaks, an attacker can brute-force
# the 6-digit TOTP code against the secret returned by /totp/setup. With
# `valid_window=1`, ~3 codes out of 10^6 are valid at any time → ~50% success
# in ~170k attempts. Unrestricted, that's minutes at 1k req/s.
#
# In-process counter is sufficient: FastAPI runs a single asyncio loop per
# worker; the WAF API is single-instance per spec, and even in a hypothetical
# multi-worker deploy each worker keeps its own budget — the attacker still
# can't exceed worker_count * limit per window. State is per-(user_id),
# survives until the process restarts, expires by sliding-window pruning.
_TOTP_CONFIRM_WINDOW_SECONDS = 300  # 5 minutes
_TOTP_CONFIRM_MAX_FAILS = 5
_totp_confirm_fails: dict[int, list[float]] = defaultdict(list)


def _prune_and_count_fails(user_id: int) -> int:
    """Drop entries older than the window, return current count."""
    cutoff = monotonic() - _TOTP_CONFIRM_WINDOW_SECONDS
    timestamps = _totp_confirm_fails[user_id]
    timestamps[:] = [t for t in timestamps if t >= cutoff]
    return len(timestamps)


def _record_totp_fail(user_id: int) -> None:
    _totp_confirm_fails[user_id].append(monotonic())


def _clear_totp_fails(user_id: int) -> None:
    _totp_confirm_fails.pop(user_id, None)


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
    """Return user from session cookie or TOTP enrol cookie, or None.

    Enrol-cookie path is gated on ``totp_enabled_at IS NULL``: a stolen
    enrol cookie cannot be used to re-enroll TOTP once the legitimate user
    has already activated it (otherwise an attacker could replace the
    victim's authenticator device).
    """
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
            user = await auth_service.get_user(session, payload["user_id"])
            # Single-use semantics: enrol cookie only works while TOTP is
            # still un-activated. Once activated, the user must use a real
            # session token (post-login) to manage 2FA. This kills the
            # "stolen enrol cookie → re-enroll → take over" path.
            if user and user.totp_enabled_at is None:
                return user

    return None


@router.post("/totp/setup")
async def totp_setup(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    """Generate a new TOTP secret + recovery codes for the authenticated user.

    Accepts either a live session cookie (profile flow) or the short-lived
    ``waf_totp_enrol`` cookie issued on admin first-login.
    """
    user = await _resolve_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="not authorized for totp enrol")

    if user.totp_enabled_at is not None:
        current_code = request.headers.get("X-WAF-Current-TOTP")
        if not current_code or not (
            totp.verify_code(user.totp_secret, current_code)
            or await totp.verify_recovery(session, user, current_code)
        ):
            raise HTTPException(
                status_code=403,
                detail="Verification with current TOTP or recovery code required to re-enroll 2FA",
            )

    secret = totp.generate_secret()
    plain, hashes = totp.generate_recovery_codes()

    # Store the pending secret and hashes in a secure short-lived cookie instead of writing to DB immediately
    pending_payload = {
        "user_id": user.id,
        "secret": secret,
        "hashes": hashes,
    }
    pending_cookie = encrypt_short_lived(pending_payload, ttl_seconds=600, purpose="totp_pending")

    from ...config import get_settings
    s = get_settings()
    response.set_cookie(
        "waf_totp_pending",
        pending_cookie,
        max_age=600,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
    )

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

    Rate-limited per user_id: after ``_TOTP_CONFIRM_MAX_FAILS`` failures in
    the sliding ``_TOTP_CONFIRM_WINDOW_SECONDS`` window the endpoint returns
    429 with Retry-After. This caps brute-force at ~5 codes / 5 min per
    identity (cookie holder), making the 6-digit space unreachable inside
    the cookie's 10-minute TTL.
    """
    user = await _resolve_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="not authorized")

    # Read pending setup from cookie if it exists
    pending = request.cookies.get("waf_totp_pending")
    if not pending:
        # Fall back to user's existing secret if there's no pending cookie
        secret = user.totp_secret
        hashes = user.recovery_codes_hash
        if not secret:
            raise HTTPException(status_code=401, detail="not enrolled")
    else:
        pending_payload = decrypt_short_lived(pending, purpose="totp_pending")
        if not pending_payload or pending_payload.get("user_id") != user.id:
            raise HTTPException(status_code=400, detail="invalid or expired setup session")
        secret = pending_payload["secret"]
        hashes = pending_payload["hashes"]

    # Check rate budget BEFORE running pyotp.verify — the goal is to bound
    # attempts, not just bound successful attempts. Returns Retry-After so
    # clients/browsers back off automatically.
    if _prune_and_count_fails(user.id) >= _TOTP_CONFIRM_MAX_FAILS:
        logger.warning(
            "totp.confirm: rate-limit tripped for user_id=%s", user.id
        )
        raise HTTPException(
            status_code=429,
            detail="too many failed attempts; try again later",
            headers={"Retry-After": str(_TOTP_CONFIRM_WINDOW_SECONDS)},
        )

    if not totp.verify_code(secret, payload.code):
        _record_totp_fail(user.id)
        raise HTTPException(status_code=400, detail="invalid code")

    # Success path: clear the per-user budget so a legitimate user who
    # mistyped a few times doesn't stay locked out after they get it right.
    _clear_totp_fails(user.id)

    # Save the encrypted secret and recovery codes hash
    user.totp_secret = totp.encrypt_secret(secret)
    user.recovery_codes_hash = hashes
    await totp.activate(session, user)

    # Clear pending cookies
    response.delete_cookie("waf_totp_pending", path="/")
    response.delete_cookie(TOTP_ENROL_COOKIE, path="/")
    session_token = create_session_token(
        user_id=user.id,
        platform_role=user.platform_role,
        tenant_id=user.tenant_id,
        tenant_role=user.tenant_role,
    )
    _set_session_cookie(response, session_token)
    return {"ok": True, "user": UserPublic.from_user(user).model_dump()}
