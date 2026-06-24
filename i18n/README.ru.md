# 🛡️ WAF: Современный мультитенантный Web Application Firewall Edge

Высокопроизводительный, безопасный по умолчанию сервис Web Application Firewall (WAF), работающий как обратный прокси (reverse proxy) для origin-серверов, принадлежащих тенантам. Он объединяет **Angie** (современный форк Nginx) с **FastAPI**, **SolidJS**, **CrowdSec** (для изолированной по тенантам динамической блокировки угроз) и **ClickHouse** (для логирования и аналитики в реальном времени).

> 🌐 **Языки:** [English](../README.md) · **Русский**

---

## 🛠️ Быстрый старт

### 0. Установка одной командой (рекомендуется)

Клонирует репозиторий, генерирует свежий `.env` и поднимает стек через Docker Compose.

**macOS / Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/Cringeneers/demo-repository/main/scripts/install/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/Cringeneers/demo-repository/main/scripts/install/install.ps1 | iex
```

> Требуются `git` и Docker (с Compose). На Windows для шага генерации окружения нужен `bash` (Git Bash или WSL). После завершения переходите к [шагу 2](#2-создание-учётной-записи-администратора).

### 1. Клонирование и запуск локального стека

Чтобы поднять локальное окружение для разработки через Docker Compose:

```bash
# Клонировать репозиторий
git clone https://github.com/Cringeneers/demo-repository.git waf
cd ./waf

# Сгенерировать свежие переменные окружения и ключи
./scripts/setup/generate-env.sh

# Собрать и запустить все сервисы
docker compose up -d --build
```

### 2. Создание учётной записи администратора

1. Отредактируйте только что созданный файл `.env` и установите `WAF_PUBLIC_BASE_URL` равным вашему домену или `http://localhost:5173` (для локальной разработки).
2. Выполните миграции базы данных:
   ```bash
   docker compose exec backend alembic upgrade head
   ```
3. Создайте первоначальную административную учётную запись:
   ```bash
   ./scripts/ops/create-admin.sh --email you@yourdomain.com
   ```
4. Откройте панель управления, войдите и зарегистрируйте ваше приложение **TOTP (2FA)**, чтобы разблокировать административные эндпоинты.

---

## ⚙️ Опциональные интеграции

*   **Cloudflare Turnstile (анти-бот):** Задайте `WAF_TURNSTILE_SITE_KEY` и `WAF_TURNSTILE_SECRET_KEY` в `.env`, чтобы включить анти-бот проверку на страницах входа и регистрации. Если параметры не указаны, проверка капчи автоматически пропускается.
*   **SMTP (отправка email):** Задайте `WAF_SMTP_HOST`, `WAF_SMTP_PORT`, `WAF_SMTP_USERNAME`, `WAF_SMTP_PASSWORD` и `WAF_SMTP_FROM_EMAIL`. В режиме разработки, если настройки SMTP отсутствуют, все транзакционные письма (подтверждение, сброс пароля) выводятся в stdout бэкенда.
*   **Социальная аутентификация (OAuth):**
    *   **Google:** Задайте `WAF_OAUTH_GOOGLE_CLIENT_ID` и `WAF_OAUTH_GOOGLE_CLIENT_SECRET`.
    *   **GitHub:** Задайте `WAF_OAUTH_GITHUB_CLIENT_ID` и `WAF_OAUTH_GITHUB_CLIENT_SECRET`.
    *   *Структура callback URL:* `${WAF_PUBLIC_BASE_URL}/api/auth/oauth/[provider]/callback`.

---

## 📈 Горизонтальное масштабирование (режим S3)

По умолчанию (`WAF_STORAGE_BACKEND=local`) backend пишет per-tenant конфиги, TLS и
состояние банов/реестра на локальный том и перезагружает единственный Angie через
`docker exec` — **поведение одного узла остаётся байт-в-байт прежним**.

Чтобы запускать несколько реплик backend и несколько edge-узлов (Angie),
переключите общий источник истины на S3-совместимое хранилище (в dev — MinIO):

```bash
# Сильные креды пишет scripts/setup/generate-env.sh; в .env:
#   WAF_STORAGE_BACKEND=s3
#   WAF_S3_ENDPOINT=minio:9000  WAF_S3_BUCKET=waf-state
#   WAF_S3_ACCESS_KEY=...  WAF_S3_SECRET_KEY=...           # backend RW
#   WAF_S3_EDGE_ACCESS_KEY=...  WAF_S3_EDGE_SECRET_KEY=... # edge RO
docker compose --profile s3 up -d
```

**Как это работает.** Каждая реплика backend пишет объекты в S3 и публикует
**манифест поколения** — единственную точку атомарного коммита. На каждом
edge-узле сайдкар `edge-sync` опрашивает манифест (`WAF_EDGE_SYNC_INTERVAL`,
по умолчанию 10 c), материализует изменённые объекты в локальное дерево Angie,
валидирует через `angie -t` и перезагружает свой Angie. Изменение тенанта
сходится на всех edge за ~30 c.

*   **Атомарность:** edge применяет только полностью скачанное поколение —
    полу-записанный набор никогда не обслуживается.
*   **Согласованность:** конкурентные публикации backend разрешаются compare-and-set
    по манифесту (advisory-lock в Postgres снижает contention); потерь записей нет.
*   **Отказоустойчивость:** при недоступности S3 edge держит **last-known-good**;
    свежий узел холодно синкается с нуля без вмешательства оператора.
*   **Безопасность:** скоупленные пользователи MinIO (backend RW, edge RO); объекты
    TLS-ключей пишутся `sensitive` (SSE at rest). Для прода включите TLS на MinIO и
    `WAF_S3_USE_TLS=true`, чтобы креды/ключи не шли по сети открытым текстом.

**Наблюдаемость.** Backend отдаёт `state_published_generation`; каждый сайдкар —
`edge_sync_applied_generation`, `edge_sync_lag_seconds`, `edge_sync_errors_total`
на `:9101`. Отставание узла = `published − applied`; алерты Prometheus
(`EdgeConvergenceLag`, `EdgeSyncErrors`) и дашборд Grafana лежат в
`docker/prometheus/rules/` и `docker/grafana/provisioning/`.

**Масштаб.** Для настоящего multi-node 1:1 edge↔sidecar используйте Kubernetes
(`k8s/angie.yaml`, сайдкар в Pod Angie). В docker-compose сайдкар работает с
`waf-angie-1` при scale=1 (Compose не выражает pod-пейринг); для демо нескольких
edge берите k8s.
