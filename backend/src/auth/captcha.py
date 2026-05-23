import httpx
from fastapi import HTTPException
from ..config import get_settings

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify(token: str | None, remote_ip: str | None = None) -> bool:
    settings = get_settings()
    if not settings.turnstile_secret_key:
        return True
    if not token:
        return False
    data = {"secret": settings.turnstile_secret_key, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.post(SITEVERIFY_URL, data=data)
            return bool(r.json().get("success", False))
        except httpx.HTTPError:
            return False


async def verify_or_raise(token: str | None, request) -> None:
    """D6: shared helper for endpoints that need captcha enforcement."""
    remote_ip = request.client.host if request.client else None
    if not await verify(token, remote_ip=remote_ip):
        raise HTTPException(status_code=400, detail="captcha failed")
