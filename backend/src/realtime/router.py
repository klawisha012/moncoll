"""POST /api/realtime/token — выдаёт короткоживущий JWT для centrifuge-js.

Фронтенд при инициализации центрифуги делает один call сюда (cookie-
аутентифицированный), получает HMAC-подписанный JWT и передаёт его в
`new Centrifuge(url, { token })`. Centrifugo верифицирует подписью.

TTL короткий (1ч) на случай если кука отозвана/юзер удалён — клиент
сам перевыпустит токен через refresh-callback centrifuge-js.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..auth.dependencies import require_password_changed
from ..db.models import User
from . import publisher

router = APIRouter(prefix="/api/realtime", tags=["realtime"])


class TokenResponse(BaseModel):
    token: str
    """HS256 JWT для centrifuge-js connect option."""

    ttl_seconds: int
    """Сколько токен валиден — фронт планирует refresh за ~5 мин до."""


@router.post("/token", response_model=TokenResponse)
async def issue_token(user: User = Depends(require_password_changed)) -> TokenResponse:
    ttl = 3600
    token = publisher.make_connection_token(user_id=str(user.id), ttl_seconds=ttl)
    return TokenResponse(token=token, ttl_seconds=ttl)
