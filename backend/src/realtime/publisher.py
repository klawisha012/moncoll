"""HTTP-клиент для server-side Centrifugo API.

Centrifugo v6 принимает POST /api/<method> с JSON-телом и заголовком
`Authorization: apikey <KEY>`. Используем httpx.AsyncClient как singleton
с keep-alive — publish дёргается каждые ~500ms из aggregator-loop.

Failure mode: если Centrifugo не отвечает или вернул 5xx — логируем,
дропаем дельту и продолжаем. Эти апдейты ephemeral — следующий батч
всё равно перекроет потерю.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from . import config

logger = logging.getLogger(__name__)

_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    """Ленивая инициализация — httpx нельзя создать до event loop'а."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=2.0),
            headers={
                "Authorization": f"apikey {config.CENTRIFUGO_API_KEY}",
                "Content-Type": "application/json",
            },
        )
    return _client


async def close() -> None:
    """Закрыть HTTP-клиент. Вызывается на shutdown lifespan."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def publish(channel: str, data: dict[str, Any]) -> bool:
    """Опубликовать сообщение в Centrifugo-канал.

    Returns True if delivered, False если Centrifugo отверг (логируется).
    Не бросает исключений — для использования в hot path aggregator'а.
    """
    if not config.CENTRIFUGO_API_KEY:
        logger.warning("CENTRIFUGO_API_KEY empty — skipping publish to %s", channel)
        return False

    url = f"{config.CENTRIFUGO_API_URL}/publish"
    payload = {"channel": channel, "data": data}

    try:
        client = _get_client()
        resp = await client.post(url, content=json.dumps(payload))
        if resp.status_code != 200:
            logger.warning(
                "Centrifugo publish %s returned %s: %s",
                channel, resp.status_code, resp.text[:200],
            )
            return False
        # Centrifugo возвращает {"result": {...}} при успехе, {"error": {...}}
        # при ошибке валидации (например, неизвестный namespace).
        body = resp.json()
        if "error" in body:
            logger.warning("Centrifugo publish %s error: %s", channel, body["error"])
            return False
        return True
    except httpx.HTTPError as exc:
        logger.warning("Centrifugo publish %s transport error: %s", channel, exc)
        return False
    except Exception:
        logger.exception("Centrifugo publish %s unexpected error", channel)
        return False


# ---------------------------------------------------------------------------
# Client connection JWT — backend подписывает короткоживущий токен, фронт
# передаёт его в centrifuge-js. Centrifugo верифицирует HMAC-подписью.
# ---------------------------------------------------------------------------

import hmac
import hashlib
import base64


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def make_connection_token(user_id: str, ttl_seconds: int = 3600) -> str:
    """Сгенерировать HS256 JWT для centrifuge-js connect.

    Centrifugo v6 принимает стандартный JWT с обязательными claim'ами:
      sub — идентификатор пользователя
      exp — unix timestamp истечения

    Подписывается HMAC-SHA256 с CENTRIFUGO_TOKEN_HMAC_SECRET — той же
    что в configs/centrifugo/config.json.
    """
    if not config.CENTRIFUGO_TOKEN_HMAC_SECRET:
        raise RuntimeError(
            "CENTRIFUGO_TOKEN_HMAC_SECRET is empty — cannot mint connection tokens"
        )

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "exp": int(time.time()) + ttl_seconds,
    }
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(
        config.CENTRIFUGO_TOKEN_HMAC_SECRET.encode(),
        signing_input,
        hashlib.sha256,
    ).digest()
    s_b64 = _b64url(sig)
    return f"{h_b64}.{p_b64}.{s_b64}"
