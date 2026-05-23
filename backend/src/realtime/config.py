"""Конфиг для realtime-модуля. Всё из env, с разумными дефолтами для
docker-compose. В проде секреты обязательны — без них docker-compose
:?-syntax не пустит сервис стартовать.
"""

import os

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
"""URL Redis. Vector пушит в pub/sub channel `attacks:raw`."""

REDIS_RAW_CHANNEL = "attacks:raw"
"""Канал в Redis куда Vector публикует raw geoip access events."""

CENTRIFUGO_API_URL = os.environ.get("CENTRIFUGO_API_URL", "http://centrifugo:8000/api")
"""Centrifugo server HTTP API root (для publish/broadcast)."""

CENTRIFUGO_API_KEY = os.environ.get("CENTRIFUGO_API_KEY", "")
"""API ключ для server-side вызовов. В .env генерируется."""

CENTRIFUGO_TOKEN_HMAC_SECRET = os.environ.get("CENTRIFUGO_TOKEN_HMAC_SECRET", "")
"""HMAC-секрет для подписи client connection JWTs. Должен совпадать с
client_token_hmac_secret_key в configs/centrifugo/config.json."""

CHANNEL_GEOIP_MAP = "dashboard:map"
"""Centrifugo-канал куда публикуем агрегированные дельты карты."""

# Batch tuning — компромисс между «живо» и «не спамить»:
#   <100ms — лишняя нагрузка, человек не различит
#   >1s  — заметная задержка реактивности
AGGREGATOR_FLUSH_INTERVAL_S = 0.5
"""Период сброса накопленных дельт в Centrifugo."""

# Координаты округляются до 2 знаков (~1 км точность) чтобы соседние
# города/датацентры группировались в одну точку карты и счётчик не
# размывался по сотням близких координат.
GEOIP_BUCKET_PRECISION = 2
