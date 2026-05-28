"""Redis subscriber → aggregator → Centrifugo publisher.

Один долгоживущий asyncio task, запускается в lifespan основного API.
Делает три вещи параллельно:
  • держит Redis pub/sub подписку на `attacks:raw` (Vector пушит туда)
  • накапливает события в in-memory buckets (geoip-coord → counter)
  • каждые 500ms делает flush — если буфер не пустой, публикует дельту
    в Centrifugo channel `dashboard:map`

Failure modes:
  • Redis down — backoff loop переподключается, основной API не страдает
  • Centrifugo down — publish возвращает False, дельта дропается
  • Невалидный JSON в сообщении — лог и skip
  • Backend restart — теряются in-flight 500ms батчи, события всё равно
    в ClickHouse, видны через REST на reload

Single-backend-instance assumption: см. __init__.py docstring.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import orjson
import redis.asyncio as aioredis

from . import config, publisher

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _BucketKey:
    """Ключ группировки точек карты — округлённые координаты + country."""
    cc: str
    lat: float
    lon: float
    city: str


class _Aggregator:
    """Накапливает счётчики в памяти между flush-тиками. Stateless между
    батчами — после flush словарь обнуляется. Окно «24 часа» не
    поддерживается тут специально; фронт-end комбинирует начальный
    snapshot из REST + дельты от нас (см. design-doc)."""

    def __init__(self) -> None:
        self._buckets: dict[_BucketKey, int] = {}
        self._dropped_no_geoip = 0

    def add_event(self, raw: dict) -> None:
        """Принять одно raw-событие из Vector. Если у него нет geoip-
        координат (частный IP, MaxMind miss) — увеличиваем счётчик
        потерь, событие игнорируем для карты (всё равно нечего рисовать).
        """
        geoip = raw.get("geoip") or {}
        lat = geoip.get("latitude")
        lon = geoip.get("longitude")
        cc = (geoip.get("country_code") or "").upper()

        # Vector конвертит лат/лон в float, но защитимся
        try:
            lat_f = float(lat) if lat not in (None, "", 0) else None
            lon_f = float(lon) if lon not in (None, "", 0) else None
        except (TypeError, ValueError):
            lat_f = lon_f = None

        if lat_f is None or lon_f is None or not cc:
            self._dropped_no_geoip += 1
            return

        key = _BucketKey(
            cc=cc,
            lat=round(lat_f, config.GEOIP_BUCKET_PRECISION),
            lon=round(lon_f, config.GEOIP_BUCKET_PRECISION),
            city=str(geoip.get("city_name") or ""),
        )
        self._buckets[key] = self._buckets.get(key, 0) + 1

    def drain(self) -> list[dict]:
        """Атомарно забрать накопленные дельты и обнулить буфер. Возвращает
        список JSON-серилизуемых точек (с короткими именами полей для
        экономии bytes на 10k клиентах)."""
        if not self._buckets:
            return []
        out = [
            {
                "cc": k.cc,
                "lat": k.lat,
                "lon": k.lon,
                "city": k.city,
                "delta": v,
            }
            for k, v in self._buckets.items()
        ]
        self._buckets.clear()
        return out


async def _subscribe_loop(agg: _Aggregator, stop: asyncio.Event) -> None:
    """Держать подписку на Redis pub/sub. Auto-reconnect с backoff."""
    backoff = 1.0
    while not stop.is_set():
        client = None
        pubsub = None
        try:
            client = aioredis.from_url(config.REDIS_URL, decode_responses=True)
            pubsub = client.pubsub()
            await pubsub.subscribe(config.REDIS_RAW_CHANNEL)
            logger.info("realtime: subscribed to redis %s", config.REDIS_RAW_CHANNEL)
            backoff = 1.0  # success — reset backoff

            async for message in pubsub.listen():
                if stop.is_set():
                    break
                if message.get("type") != "message":
                    continue
                data = message.get("data")
                if not data:
                    continue
                try:
                    raw = orjson.loads(data)
                except (ValueError, TypeError) as exc:
                    logger.warning("realtime: bad json from redis: %s", exc)
                    continue
                agg.add_event(raw)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "realtime: redis subscribe failed, retry in %.1fs: %s", backoff, exc, exc_info=True,
            )
            try:
                await asyncio.wait_for(stop.wait(), timeout=backoff)
                return  # stop signaled during backoff
            except (TimeoutError, asyncio.TimeoutError):
                pass
            backoff = min(backoff * 2, 30.0)
        finally:
            if pubsub is not None:
                try:
                    await pubsub.unsubscribe()
                    await pubsub.close()
                except Exception:
                    pass
            if client is not None:
                try:
                    await client.close()
                except Exception:
                    pass


async def _flush_loop(agg: _Aggregator, stop: asyncio.Event) -> None:
    """Каждые AGGREGATOR_FLUSH_INTERVAL_S сливаем буфер в Centrifugo."""
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=config.AGGREGATOR_FLUSH_INTERVAL_S)
            return  # stop signaled
        except (TimeoutError, asyncio.TimeoutError):
            pass  # обычный тик

        points = agg.drain()
        if not points:
            continue

        payload = {
            "type": "geoip_map_delta",
            "ts": int(asyncio.get_event_loop().time() * 1000),
            "points": points,
        }
        logger.debug("realtime: flushing %d points to %s", len(points), config.CHANNEL_GEOIP_MAP)
        ok = await publisher.publish(config.CHANNEL_GEOIP_MAP, payload)
        if not ok:
            logger.warning("realtime: drop %d points, publish failed", len(points))


async def _metrics_broadcast_loop(stop: asyncio.Event) -> None:
    """Раз в 2 секунды транслируем свежие метрики дашборда и трафика для всех диапазонов в Centrifugo."""
    import time
    from ..dashboard.service import get_dashboard_metrics, get_traffic_data

    loop = asyncio.get_running_loop()
    # Список стандартных временных диапазонов на фронтенде (15м, 1ч, 24ч, 7дн, 30дн)
    time_windows = [0.25, 1.0, 24.0, 168.0, 720.0]

    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=2.0)
            return  # stop signaled
        except (TimeoutError, asyncio.TimeoutError):
            pass  # обычный тик

        try:
            for hours in time_windows:
                if stop.is_set():
                    break
                # Вычисляем метрики в пуле потоков (активно использует быстрый Redis-кэш)
                metrics = await loop.run_in_executor(None, get_dashboard_metrics, hours, None, None)
                traffic = await loop.run_in_executor(None, get_traffic_data, hours, None, None)

                payload_metrics = {
                    "type": "dashboard_metrics",
                    "ts": int(time.time() * 1000),
                    "metrics": metrics,
                }
                payload_traffic = {
                    "type": "dashboard_traffic",
                    "ts": int(time.time() * 1000),
                    "traffic": traffic,
                }

                await publisher.publish(f"dashboard:metrics:{hours}", payload_metrics)
                await publisher.publish(f"dashboard:traffic:{hours}", payload_traffic)

        except Exception as exc:
            logger.warning("realtime: failed to broadcast dashboard metrics: %s", exc)


async def run_forever(stop: asyncio.Event) -> None:
    """Точка входа — запустить subscribe + flush + broadcast параллельно и ждать stop.
    Вызывается из lifespan через asyncio.create_task."""
    agg = _Aggregator()
    try:
        await asyncio.gather(
            _subscribe_loop(agg, stop),
            _flush_loop(agg, stop),
            return_exceptions=False,
        )
    finally:
        await publisher.close()
        logger.info("realtime: consumer stopped")

