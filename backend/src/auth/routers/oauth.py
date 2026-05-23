"""OAuth2 endpoints: /oauth/{provider}/start and /oauth/{provider}/callback."""

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...db.models import OAuthAccount
from ...db.session import get_session
from ...tenants import service as tenants_service
from .. import service as auth_service
from ..dependencies import SESSION_COOKIE
from ..oauth import get_client, redirect_uri, scopes_for
from ..security import (
    SESSION_TTL_SECONDS,
    create_session_token,
    sign_short_lived,
    verify_short_lived,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])

OAUTH_STATE_COOKIE = "waf_oauth_state"


@router.get("/oauth/{provider}/start")
async def oauth_start(provider: str, intent: str, tenant_name: str | None = None):
    client = get_client(provider)
    ru = redirect_uri(provider)
    if not client or not ru:
        raise HTTPException(status_code=400, detail="provider unavailable")
    if intent not in ("signup", "login"):
        raise HTTPException(status_code=400, detail="intent must be signup or login")

    state = sign_short_lived(
        {"intent": intent, "tenant_name": tenant_name, "provider": provider},
        ttl_seconds=600,
        purpose="oauth_state",
    )
    url = await client.get_authorization_url(ru, state=state, scope=scopes_for(provider))
    response = RedirectResponse(url=url, status_code=307)
    response.set_cookie(
        OAUTH_STATE_COOKIE,
        state,
        max_age=600,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    # 1. Validate state cookie matches state query param.
    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not cookie_state or cookie_state != state:
        raise HTTPException(status_code=400, detail="invalid oauth state")

    # 2. Validate state HMAC.
    payload = verify_short_lived(state, purpose="oauth_state")
    if not payload or payload.get("provider") != provider:
        raise HTTPException(status_code=400, detail="invalid oauth state")

    client = get_client(provider)
    ru = redirect_uri(provider)
    if not client or not ru:
        raise HTTPException(status_code=400, detail="provider unavailable")

    # 3. Exchange code for access token.
    token_data = await client.get_access_token(code, ru)

    # 4. Fetch profile.
    if provider == "google":
        profile = await _fetch_google_profile(token_data["access_token"])
    else:
        profile = await _fetch_github_profile(token_data["access_token"])

    # 5. Reject if email not verified at provider.
    if not profile.get("email") or not profile.get("email_verified", False):
        raise HTTPException(status_code=400, detail="provider email not verified")

    # 6. Look up existing OAuth account.
    existing = (
        await session.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_account_id == profile["sub"],
            )
        )
    ).scalar_one_or_none()

    # 7. Branch on found / not-found + intent.
    if existing:
        user = await auth_service.get_user(session, existing.user_id)
    else:
        intent = payload["intent"]
        if intent == "login":
            raise HTTPException(status_code=404, detail="no account; sign up first")

        # signup
        tenant_name = payload.get("tenant_name")
        if not tenant_name:
            raise HTTPException(status_code=400, detail="tenant_name required for signup")

        # Reject if email already in use (no auto-linking).
        if await auth_service.get_by_email(session, profile["email"]):
            raise HTTPException(
                status_code=409, detail="email already in use; sign in with password"
            )

        try:
            tenant = await tenants_service.create_tenant(
                session,
                name=tenant_name,
                display_name=tenant_name,
            )
        except (tenants_service.InvalidTenantName, tenants_service.TenantNameTaken) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

        user = await auth_service.create_client_user(
            session,
            email=profile["email"],
            password=None,
            tenant_id=tenant.id,
            tenant_role="owner",
            display_name=profile.get("name", ""),
            email_verified=True,
        )
        session.add(
            OAuthAccount(
                user_id=user.id,
                provider=provider,
                provider_account_id=profile["sub"],
                email_at_provider=profile["email"],
            )
        )
        await session.commit()

    await auth_service.touch_login(session, user)
    s_token = create_session_token(
        user_id=user.id,
        platform_role=user.platform_role,
        tenant_id=user.tenant_id,
        tenant_role=user.tenant_role,
    )
    s = get_settings()
    redirect = RedirectResponse(url="/home", status_code=303)
    redirect.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    redirect.set_cookie(
        SESSION_COOKIE,
        s_token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
    )
    return redirect


# ---------------------------------------------------------------------------
# Profile-fetch helpers
# ---------------------------------------------------------------------------


async def _fetch_google_profile(access_token: str) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    r.raise_for_status()
    j = r.json()
    return {
        "sub": j["sub"],
        "email": j["email"],
        "email_verified": j.get("email_verified", False),
        "name": j.get("name", ""),
    }


async def _fetch_github_profile(access_token: str) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as c:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
        u = (await c.get("https://api.github.com/user", headers=headers)).json()
        emails = (await c.get("https://api.github.com/user/emails", headers=headers)).json()
    primary = next(
        (e for e in emails if e.get("primary") and e.get("verified")),
        None,
    )
    if not primary:
        return {"sub": str(u.get("id", "")), "email": None, "email_verified": False, "name": ""}
    return {
        "sub": str(u["id"]),
        "email": primary["email"],
        "email_verified": True,
        "name": u.get("name") or u.get("login", ""),
    }
