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
