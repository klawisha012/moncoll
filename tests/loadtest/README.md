# Нагрузочное тестирование WAF (k6)

Скрипты в этой папке запускают [k6](https://k6.io) против работающего фронтенда Angie, чтобы мы могли измерить реальную пропускную способность, задержки (latency) и влияние ModSecurity / CrowdSec / сжатия на производительность горячего пути прохождения запросов.

## Локальный запуск (через docker compose)

```bash
# Дымовой тест (Smoke) (10 секунд, 10 виртуальных пользователей) — встроен в CI
docker compose --profile loadtest run --rm k6 run /scripts/smoke.js

# Базовый тест (Baseline) (60 секунд, плавный подъем до 200 пользователей)
docker compose --profile loadtest run --rm k6 run /scripts/baseline.js

# Пиковый тест (Spike) (внезапный наплыв 1000 пользователей)
docker compose --profile loadtest run --rm k6 run /scripts/spike.js

# Нагрузочный тест на выносливость (Soak) (стабильное удержание нагрузки в течение 20 минут)
docker compose --profile loadtest run --rm k6 run /scripts/soak.js

# Тестирование матрицы сжатия (Compression-aware sweep) — перезапуск базового сценария с каждым из алгоритмов сжатия
docker compose --profile loadtest run --rm k6 run /scripts/compression-matrix.js

# Сравнение HTTP/2 и HTTP/3 (запуск TLS-соединения с флагами --http2 / --http3)
docker compose --profile loadtest run --rm \
  -e TARGET_SCHEME=https -e TARGET_PORT=443 \
  k6 run /scripts/http-versions.js
```

Сервис `k6` запускается в профиле compose `loadtest`, поэтому он **не** запускается автоматически при обычном старте стека — вызывайте его явно, когда хотите провести замеры.

## Окружение (Переменные среды)

| Переменная           | По умолчанию | Описание                                                           |
|----------------------|--------------|--------------------------------------------------------------------|
| `TARGET_HOST`        | `angie`      | Хост / сервис для тестирования (`angie` во внутренней сети Docker)  |
| `TARGET_PORT`        | `80`         | Порт (`443` для HTTPS)                                             |
| `TARGET_SCHEME`      | `http`       | Протокол (`http` или `https`)                                      |
| `TARGET_PATH`        | `/`          | Путь для тестирования                                              |
| `K6_VUS`             | (из скрипта) | Переопределение количества виртуальных пользователей (VUs)         |
| `K6_DURATION`        | (из скрипта) | Переопределение длительности теста                                 |
| `K6_OUT`             | (пусто)      | Например, `experimental-prometheus-rw` или `json=results.json`     |

## Целевые показатели (Targets / Thresholds)

Стандартные пороговые значения для `smoke.js` составляют:

* `http_req_failed` ≤ 1% (доля упавших запросов)
* `http_req_duration{p(95)}` ≤ 500ms (95-й процентиль времени ответа)
* `iterations` ≥ 100 (общее число выполненных итераций)

Вы можете настраивать эти пороги в каждом конкретном скрипте по мере масштабирования нагрузки.
