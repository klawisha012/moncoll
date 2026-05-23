"""Real-time fan-out для dashboard live updates.

Архитектура (см. docs/superpowers/specs/2026-05-23-realtime-centrifugo-design.md):

    Vector → Redis pub/sub `attacks:raw`
                    ↓ aioredis SUBSCRIBE (consumer.py)
              backend aggregator
                    ↓ HTTP /api/publish (publisher.py)
                Centrifugo
                    ↓ WS/SSE
              browser clients (centrifuge-js)

Запускается в `lifespan` (main.py) как фоновая asyncio.Task; падение
consumer'а логируется но не валит API. Token endpoint (router.py)
выдаёт короткоживущий HMAC-JWT для centrifuge-js.

Single-backend-instance assumption: Redis pub/sub шлёт копию КАЖДОМУ
subscriber'у, поэтому 2+ реплики backend'а породят дубликаты публикаций
в Centrifugo. При горизонтальном масштабировании — вынести consumer в
отдельный worker-контейнер (с одной репликой).
"""

from .router import router as realtime_router

__all__ = ["realtime_router"]
