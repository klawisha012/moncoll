import ipaddress
import logging

import httpx
from fastapi import HTTPException

from ..config import get_settings

logger = logging.getLogger(__name__)

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _client_ip(request) -> str | None:
    """Real client IP, walking X-Forwarded-For/X-Real-IP. The immediate peer
    in our deployment is frontend-nginx (172.18.x.x), which Cloudflare would
    reject as IP-mismatched against the IP that actually solved the captcha.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",", 1)[0].strip()
        if ip:
            return ip
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else None


async def verify(token: str | None, remote_ip: str | None = None) -> bool:
    settings = get_settings()
    if not settings.turnstile_secret_key:
        return True
    if not token:
        return False
    data = {"secret": settings.turnstile_secret_key, "response": token}
    # Only forward remoteip when it's a real public address — sending a Docker
    # internal IP makes Cloudflare reject the token (IP mismatch with the IP
    # that solved the challenge).
    if remote_ip and not _is_private_ip(remote_ip):
        data["remoteip"] = remote_ip
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.post(SITEVERIFY_URL, data=data)
            body = r.json()
            ok = bool(body.get("success", False))
            if not ok:
                logger.warning(
                    "turnstile siteverify failed: error_codes=%s (sent remoteip=%s)",
                    body.get("error-codes"),
                    data.get("remoteip", "<omitted>"),
                )
            return ok
        except httpx.HTTPError as exc:
            logger.warning("turnstile siteverify HTTP error: %s", exc)
            return False


async def verify_or_raise(token: str | None, request) -> None:
    """D6: shared helper for endpoints that need captcha enforcement."""
    remote_ip = _client_ip(request)
    if not await verify(token, remote_ip=remote_ip):
        raise HTTPException(status_code=400, detail="captcha failed")
