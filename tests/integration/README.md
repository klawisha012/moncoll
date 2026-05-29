# Интеграционное тестирование (Integration Tests) WAF

В этой директории находятся интеграционные тесты для Web Application Firewall (WAF). Эти тесты проверяют корректность взаимодействия между компонентами приложения: API-эндпоинтами бэкенда, базой данных (PostgreSQL), механизмами авторизации и ролевого доступа, а также фоновыми сервисами.

---

## Особенности интеграционных тестов

1. **Реальная база данных**: В отличие от юнит-тестов, интеграционные тесты выполняют транзакции в реальном экземпляре **PostgreSQL**.
2. **Изоляция данных**: Тесты используют отдельную схему/базу данных и запускают `drop_all` / `create_all` при инициализации. Каждый тест выполняется в рамках изолированной транзакции с автоматическим откатом изменений (rollback) после завершения, чтобы не засорять базу.
3. **GeoIP Наполнение**: Тест `test_geoip_map_population.py` автоматически наполняет базу данных ClickHouse (если она запущена) демо-координатами реальных городов мира (Москва, Сан-Франциско, Лондон и т.д.) для отладки интерактивных 2D и 3D карт.
4. **Автоматическая разметка**: Благодаря кастомному хуку в `tests/conftest.py`, все файлы в этой папке автоматически получают маркер `@pytest.mark.integration`.

---

## Структура директории

```text
tests/integration/
├── README.md           # Этот файл (инструкция)
├── __init__.py
├── test_dashboard_router.py # Тестирование API роутера дашборда
└── backend/            # Интеграционные тесты для backend-компонентов
    ├── conftest.py     # Конфигурация тестовой сессии БД и создание таблиц
    ├── test_admin_tenants.py # Управление клиентами (tenants) администратором
    ├── test_auth_dependencies.py # Проверки инъекций зависимостей авторизации
    ├── test_auth_login_flow.py # Проверка сквозного процесса входа и выдачи токенов
    ├── test_auth_reset_flow.py # Проверка сброса пароля через OTP
    ├── test_auth_signup_flow.py # Интеграционный тест регистрации пользователей
    ├── test_auth_totp_flow.py # Проверка двухфакторной авторизации (2FA) на уровне БД и API
    ├── test_auth_user_service.py # Интеграция сервиса пользователей с БД
    ├── test_connections_tenant_scoping.py # Проверка изоляции подключений разных тенантов
    ├── test_crowdsec_tenant_scoping.py # Проверка изоляции настроек CrowdSec
    ├── test_dashboard_tenant_scoping.py # Изоляция метрик и статистики между тенантами
    ├── test_email_verification.py # Процесс подтверждения электронной почты через БД
    ├── test_geoip_map_population.py # Заполнение ClickHouse демо-данными для 2D/3D карт
    ├── test_modsecurity_tenant_scoping.py # Изоляция настроек ModSecurity правил
    ├── test_monitoring_tenant_scoping.py # Проверка изоляции метрик мониторинга
    ├── test_oauth_flow.py # Интеграционные тесты авторизации через внешних провайдеров
    ├── test_tenant_service.py # Жизненный цикл тенанта (создание, настройка)
    ├── test_tenant_suspend_logout.py # Проверки блокировки тенанта и инвалидации сессий
    └── test_tests_tenant_scoping.py # Изоляция внутренних WAF тестов
```

---

## Подготовка окружения и запуск

Для работы тестов необходим запущенный сервер **PostgreSQL**. Мы рекомендуем запускать его в изолированном Docker-контейнере, чтобы не затрагивать вашу базу данных разработки.

### Шаг 1: Запуск тестовой базы данных

Мы подготовили файл `docker-compose.test.yml`, который переопределяет порт PostgreSQL на `5432`, создавая полностью обособленную песочницу:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d postgres
```

### Шаг 2: Запуск тестов

Вы можете запустить тесты по маркеру `integration` или указав путь к папке:

```bash
# Запуск по маркеру
pytest -m integration

# Запуск по пути (с подробным выводом)
pytest tests/integration/ -v
```

### Шаг 3: Наполнение интерактивных карт (GeoIP демо-данные)

Если у вас локально запущен ClickHouse (весь Docker-стек), вы можете наполнить интерактивную 2D-карту и 3D-глобус красивыми демонстрационными логами доступа (включая координаты Москвы, Лондона, Токио и др.):

```bash
pytest tests/integration/backend/test_geoip_map_population.py -v
```
*(Если ClickHouse недоступен, тест безопасно пропустит выполнение).*

---

## Переопределение строки подключения к БД

По умолчанию тесты ищут PostgreSQL по адресу:  
`postgresql+asyncpg://waf:waf@localhost:5432/waf_test`

Вы можете изменить этот адрес с помощью переменной окружения `TEST_DATABASE_URL`:

### Для Windows (PowerShell)
```powershell
$env:TEST_DATABASE_URL="postgresql+asyncpg://myuser:mypass@localhost:5432/my_test_db"
pytest -m integration
```

### Для Linux/macOS
```bash
TEST_DATABASE_URL=postgresql+asyncpg://myuser:mypass@localhost:5432/my_test_db pytest -m integration
```

> [!WARNING]
> Перед каждым запуском интеграционных тестов целевая база данных очищается (происходит `drop_all`). **Никогда** не указывайте в `TEST_DATABASE_URL` адрес вашей рабочей (production) базы данных!
