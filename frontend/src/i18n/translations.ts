export type Lang = "en" | "ru";

type TranslationDict = Record<string, string>;

const en: TranslationDict = {
  // Layout / Sidebar
  "brand.name": "WAF Panel",
  "brand.sub": "Control Center",
  "nav.overview": "Overview",
  "nav.dashboard": "Dashboard",
  "nav.monitoring": "Monitoring",
  "nav.management": "Management",
  "nav.connections": "Connections",
  "nav.configuration": "Configuration",
  "nav.security": "Security",
  "nav.crowdsec": "CrowdSec",
  "status.engine": "WAF Engine Active",

  // Settings popover
  "settings.title": "Settings",
  "settings.theme": "Theme",
  "settings.theme.dark": "Dark",
  "settings.theme.light": "Light",
  "settings.language": "Language",
  "settings.language.en": "English",
  "settings.language.ru": "Russian",

  // Dashboard
  "dashboard.title": "Dashboard",
  "dashboard.subtitle": "Real-time WAF monitoring and analytics powered by Grafana",
  "dashboard.requests": "Total Requests",
  "dashboard.requests.desc": "Live data via Grafana",
  "dashboard.blocked": "Blocked Threats",
  "dashboard.blocked.desc": "Monitored by WAF",
  "dashboard.activeRules": "Active Rules",
  "dashboard.activeRules.desc": "CRS Protection",
  "dashboard.health": "System Health",
  "dashboard.health.desc": "Performance metrics",

  // Connections
  "connections.title": "Connections / Proxy",
  "connections.subtitle": "Manage site connections and reverse proxy rules for the WAF",
  "connections.empty": "No connections configured",
  "connections.emptyDesc": "Add a connection to start proxying traffic through the WAF.",
  "connections.add": "Add Connection",
  "connections.enabled": "Enabled",
  "connections.certReady": "Certificate Ready",

  // Configuration
  "config.title": "Configuration",
  "config.subtitle": "Manage ModSecurity rules and Angie engine settings",
  "config.tab.modsec": "ModSecurity",
  "config.tab.angie": "Angie",
  "config.ruleEngine": "Rule Engine",
  "config.secRuleEngine": "SecRuleEngine",
  "config.on": "On (Blocking)",
  "config.off": "Off (Disabled)",
  "config.detectionOnly": "DetectionOnly (Logging only)",
  "config.statusEngine": "SecStatusEngine — share version info",
  "config.pcre": "PCRE & Filesystem",

  // Monitoring
  "monitoring.title": "Monitoring",
  "monitoring.subtitle": "Container resource usage and real-time system metrics",
  "monitoring.cpu": "CPU",
  "monitoring.memory": "Memory",
  "monitoring.network": "Network",

  // CrowdSec
  "crowdsec.title": "CrowdSec",
  "crowdsec.subtitle": "Manage IP blocks, scenarios, and security decisions",
  "crowdsec.loading": "Loading CrowdSec data...",
  "crowdsec.activeDecisions": "Active Decisions",
  "crowdsec.installedScenarios": "Installed Scenarios",
  "crowdsec.ipAddress": "IP Address",
  "crowdsec.duration": "Duration",
  "crowdsec.reason": "Reason",
  "crowdsec.installed": "Installed",
  "crowdsec.active": "active",
  "crowdsec.inactive": "inactive",

  // Configuration Tooltips — ModSecurity
  "tooltip.rule_engine": "Controls the ModSecurity rule engine mode. \"On\" actively blocks malicious requests, \"DetectionOnly\" only logs threats without blocking, and \"Off\" disables the WAF entirely.",
  "tooltip.status_engine": "When enabled, ModSecurity includes its version information in the X-ModSecurity response header. Useful for debugging and transparency.",
  "tooltip.request_body_access": "Enables or disables inspection of incoming request bodies (POST payloads, file uploads). Turn off only if you're certain no attack vector exists in request bodies.",
  "tooltip.request_body_limit": "Maximum size (in bytes) of a request body ModSecurity will process. Larger bodies will trigger the limit action. Prevents resource exhaustion from oversized payloads.",
  "tooltip.request_body_no_files_limit": "Maximum size (in bytes) of a request body that contains no file uploads. Typically set lower than the main limit to catch suspiciously large non-file requests.",
  "tooltip.request_body_limit_action": "Action taken when a request body exceeds the limit. \"Reject\" blocks the request with a 403 error; \"ProcessPartial\" inspects only the portion within the limit.",
  "tooltip.request_body_json_depth_limit": "Maximum nesting depth for JSON request bodies. Prevents stack overflow attacks via deeply nested JSON structures (e.g., 1000+ nested objects).",
  "tooltip.arguments_limit": "Maximum number of individual arguments/parameters ModSecurity will inspect. Limits resource usage against attacks that send thousands of parameters.",
  "tooltip.response_body_access": "Enables or disables inspection of outgoing response bodies. Required for data leak prevention rules that scan responses for sensitive information.",
  "tooltip.response_body_limit": "Maximum size (in bytes) of a response body to inspect. Large responses exceeding this size won't be fully analyzed.",
  "tooltip.response_body_limit_action": "What happens when a response body exceeds the inspection limit. \"ProcessPartial\" inspects the first portion; \"Reject\" blocks the response entirely.",
  "tooltip.audit_engine": "Controls audit logging. \"On\" logs every transaction, \"RelevantOnly\" logs only transactions that trigger warnings/errors, \"Off\" disables audit logging.",
  "tooltip.audit_log_type": "How concurrent audit logs are written. \"Serial\" writes one log at a time (slower but ordered); \"Concurrent\" allows simultaneous writes (faster).",
  "tooltip.audit_log_format": "Format of audit log entries. \"Native\" uses ModSecurity's own format; \"JSON\" produces machine-readable JSON output for log processors.",
  "tooltip.audit_log_parts": "Specifies which sections of a transaction to include in the audit log (A=header, B=request body, C=response body, etc.). Use letters A-Z to select parts.",
  "tooltip.audit_log_relevant_status": "A regex pattern matching HTTP response status codes that should trigger audit logging. For example, \"^(4|5)\" logs all 4xx and 5xx responses.",
  "tooltip.audit_log_path": "Absolute or relative file path where ModSecurity writes its audit log. Must be writable by the web server process.",
  "tooltip.pcre_match_limit": "Maximum number of internal regex engine calls per rule execution. Prevents catastrophic backtracking and ReDoS attacks from consuming all CPU.",
  "tooltip.pcre_match_limit_recursion": "Maximum recursion depth for the PCRE regex engine. Limits stack usage during complex pattern matching to prevent crashes.",
  "tooltip.tmp_dir": "Directory where ModSecurity stores temporary files (uploaded files during inspection, swap files). Must exist and be writable.",
  "tooltip.data_dir": "Directory for persistent data storage (e.g., IP reputation collections, session data). Must survive server restarts.",
  "tooltip.response_body_mime_types": "List of MIME types whose response bodies will be inspected. Typically includes text/html, application/json, and text/plain.",
  "tooltip.request_body_mime_types": "(reserved for future use)",

  // Configuration Tooltips — Angie
  "tooltip.worker_processes": "Number of Angie worker processes. \"auto\" matches your CPU core count for optimal performance. More workers handle more concurrent connections but use more memory.",
  "tooltip.worker_rlimit_nofile": "Maximum number of open file descriptors per worker process. Each connection consumes at least one file descriptor, so this must exceed worker_connections.",
  "tooltip.worker_connections": "Maximum simultaneous connections each worker process can handle. Total capacity = worker_processes × worker_connections.",
  "tooltip.keepalive_timeout": "How long (in seconds) a keep-alive HTTP connection stays open waiting for the next request. Longer values reduce TLS handshake overhead; shorter values free up resources faster.",
  "tooltip.sendfile": "When enabled, Angie uses the Linux sendfile() syscall to serve static files directly from disk to socket, bypassing user-space copying. Dramatically improves static file throughput.",
  "tooltip.geoip_countries": "Block traffic originating from selected countries using GeoIP2 databases. Requests from blocked countries receive a 403 Forbidden response before reaching your backend.",

  // General
  "general.save": "Save",
  "general.cancel": "Cancel",
  "general.saving": "Saving...",
  "general.saved": "Saved",
  "general.error": "Error",
  "general.loading": "Loading...",
};

const ru: TranslationDict = {
  // Layout / Sidebar
  "brand.name": "WAF Panel",
  "brand.sub": "Центр управления",
  "nav.overview": "Обзор",
  "nav.dashboard": "Дашборд",
  "nav.monitoring": "Мониторинг",
  "nav.management": "Управление",
  "nav.connections": "Подключения",
  "nav.configuration": "Конфигурация",
  "nav.security": "Безопасность",
  "nav.crowdsec": "CrowdSec",
  "status.engine": "WAF Engine Активен",

  // Settings popover
  "settings.title": "Настройки",
  "settings.theme": "Тема",
  "settings.theme.dark": "Тёмная",
  "settings.theme.light": "Светлая",
  "settings.language": "Язык",
  "settings.language.en": "Английский",
  "settings.language.ru": "Русский",

  // Dashboard
  "dashboard.title": "Дашборд",
  "dashboard.subtitle": "Мониторинг WAF в реальном времени на базе Grafana",
  "dashboard.requests": "Всего запросов",
  "dashboard.requests.desc": "Данные Grafana",
  "dashboard.blocked": "Заблокировано угроз",
  "dashboard.blocked.desc": "Под защитой WAF",
  "dashboard.activeRules": "Активных правил",
  "dashboard.activeRules.desc": "Защита CRS",
  "dashboard.health": "Состояние системы",
  "dashboard.health.desc": "Метрики производительности",

  // Connections
  "connections.title": "Подключения / Прокси",
  "connections.subtitle": "Управление подключениями сайтов и правилами обратного прокси",
  "connections.empty": "Нет настроенных подключений",
  "connections.emptyDesc": "Добавьте подключение, чтобы начать проксирование трафика через WAF.",
  "connections.add": "Добавить подключение",
  "connections.enabled": "Включено",
  "connections.certReady": "Сертификат готов",

  // Configuration
  "config.title": "Конфигурация",
  "config.subtitle": "Управление правилами ModSecurity и настройками Angie",
  "config.tab.modsec": "ModSecurity",
  "config.tab.angie": "Angie",
  "config.ruleEngine": "Движок правил",
  "config.secRuleEngine": "SecRuleEngine",
  "config.on": "Вкл (Блокировка)",
  "config.off": "Выкл (Отключено)",
  "config.detectionOnly": "DetectionOnly (Только логирование)",
  "config.statusEngine": "SecStatusEngine — делиться версией",
  "config.pcre": "PCRE и Файловая система",

  // Monitoring
  "monitoring.title": "Мониторинг",
  "monitoring.subtitle": "Использование ресурсов контейнеров и метрики в реальном времени",
  "monitoring.cpu": "ЦП",
  "monitoring.memory": "Память",
  "monitoring.network": "Сеть",

  // CrowdSec
  "crowdsec.title": "CrowdSec",
  "crowdsec.subtitle": "Управление блокировками IP, сценариями и решениями безопасности",
  "crowdsec.loading": "Загрузка данных CrowdSec...",
  "crowdsec.activeDecisions": "Активные решения",
  "crowdsec.installedScenarios": "Установленные сценарии",
  "crowdsec.ipAddress": "IP-адрес",
  "crowdsec.duration": "Длительность",
  "crowdsec.reason": "Причина",
  "crowdsec.installed": "Установлен",
  "crowdsec.active": "активен",
  "crowdsec.inactive": "неактивен",

  // Configuration Tooltips — ModSecurity
  "tooltip.rule_engine": "Режим работы движка правил ModSecurity. \"Вкл\" активно блокирует вредоносные запросы, \"DetectionOnly\" только логирует угрозы без блокировки, \"Выкл\" полностью отключает WAF.",
  "tooltip.status_engine": "При включении ModSecurity добавляет информацию о своей версии в заголовок ответа X-ModSecurity. Полезно для отладки и прозрачности.",
  "tooltip.request_body_access": "Включает или отключает проверку тел входящих запросов (POST-данные, загрузки файлов). Отключайте только если уверены, что в теле запроса нет векторов атак.",
  "tooltip.request_body_limit": "Максимальный размер (в байтах) тела запроса, обрабатываемого ModSecurity. Тела большего размера вызовут действие ограничения. Предотвращает истощение ресурсов.",
  "tooltip.request_body_no_files_limit": "Максимальный размер (в байтах) тела запроса без файловых загрузок. Обычно устанавливается ниже основного лимита для выявления подозрительных не-файловых запросов.",
  "tooltip.request_body_limit_action": "Действие при превышении лимита тела запроса. \"Reject\" блокирует запрос с ошибкой 403; \"ProcessPartial\" проверяет только часть в пределах лимита.",
  "tooltip.request_body_json_depth_limit": "Максимальная глубина вложенности JSON-объектов. Предотвращает атаки переполнения стека через глубоко вложенные структуры JSON (например, 1000+ вложенных объектов).",
  "tooltip.arguments_limit": "Максимальное количество отдельных аргументов/параметров, проверяемых ModSecurity. Ограничивает использование ресурсов при атаках с тысячами параметров.",
  "tooltip.response_body_access": "Включает или отключает проверку тел исходящих ответов. Необходимо для правил предотвращения утечки данных, сканирующих ответы на конфиденциальную информацию.",
  "tooltip.response_body_limit": "Максимальный размер (в байтах) тела ответа для проверки. Большие ответы, превышающие этот размер, не будут полностью проанализированы.",
  "tooltip.response_body_limit_action": "Что происходит при превышении лимита проверки тела ответа. \"ProcessPartial\" проверяет начальную часть; \"Reject\" полностью блокирует ответ.",
  "tooltip.audit_engine": "Управляет аудит-логированием. \"On\" логирует каждую транзакцию, \"RelevantOnly\" — только транзакции с предупреждениями/ошибками, \"Off\" отключает логирование.",
  "tooltip.audit_log_type": "Способ записи конкурентных аудит-логов. \"Serial\" пишет по одному (медленнее, но упорядоченно); \"Concurrent\" допускает одновременную запись (быстрее).",
  "tooltip.audit_log_format": "Формат записей аудит-лога. \"Native\" использует собственный формат ModSecurity; \"JSON\" создаёт машиночитаемый вывод для обработчиков логов.",
  "tooltip.audit_log_parts": "Какие разделы транзакции включать в аудит-лог (A=заголовок, B=тело запроса, C=тело ответа и т.д.). Используйте буквы A-Z для выбора частей.",
  "tooltip.audit_log_relevant_status": "Regex-шаблон для кодов HTTP-ответов, которые должны вызывать аудит-логирование. Например, \"^(4|5)\" логирует все ответы 4xx и 5xx.",
  "tooltip.audit_log_path": "Абсолютный или относительный путь к файлу, куда ModSecurity записывает аудит-лог. Должен быть доступен для записи процессу веб-сервера.",
  "tooltip.pcre_match_limit": "Максимальное количество внутренних вызовов движка регулярных выражений на одно правило. Предотвращает катастрофический backtracking и ReDoS-атаки.",
  "tooltip.pcre_match_limit_recursion": "Максимальная глубина рекурсии для движка PCRE. Ограничивает использование стека при сложном сопоставлении шаблонов для предотвращения сбоев.",
  "tooltip.tmp_dir": "Директория для временных файлов ModSecurity (загруженные файлы при проверке, файлы подкачки). Должна существовать и быть доступной для записи.",
  "tooltip.data_dir": "Директория для постоянного хранения данных (например, коллекции репутации IP, данные сессий). Должна сохраняться между перезапусками сервера.",
  "tooltip.response_body_mime_types": "Список MIME-типов, тела ответов которых будут проверяться. Обычно включает text/html, application/json и text/plain.",
  "tooltip.request_body_mime_types": "(зарезервировано для будущего использования)",

  // Configuration Tooltips — Angie
  "tooltip.worker_processes": "Количество рабочих процессов Angie. \"auto\" соответствует количеству ядер CPU для оптимальной производительности. Больше процессов — больше одновременных соединений, но больше расход памяти.",
  "tooltip.worker_rlimit_nofile": "Максимальное количество открытых файловых дескрипторов на рабочий процесс. Каждое соединение потребляет минимум один дескриптор, поэтому это значение должно превышать worker_connections.",
  "tooltip.worker_connections": "Максимальное количество одновременных соединений на один рабочий процесс. Общая ёмкость = worker_processes × worker_connections.",
  "tooltip.keepalive_timeout": "Время (в секундах), в течение которого keep-alive HTTP-соединение остаётся открытым в ожидании следующего запроса. Большие значения снижают накладные расходы TLS; меньшие — быстрее освобождают ресурсы.",
  "tooltip.sendfile": "При включении Angie использует системный вызов Linux sendfile() для отправки статических файлов напрямую с диска в сокет, минуя копирование в пользовательском пространстве. Значительно улучшает пропускную способность статики.",
  "tooltip.geoip_countries": "Блокировка трафика из выбранных стран с использованием баз GeoIP2. Запросы из заблокированных стран получают ответ 403 Forbidden до достижения вашего бэкенда.",

  // General
  "general.save": "Сохранить",
  "general.cancel": "Отмена",
  "general.saving": "Сохранение...",
  "general.saved": "Сохранено",
  "general.error": "Ошибка",
  "general.loading": "Загрузка...",
};

export const translations: Record<Lang, TranslationDict> = { en, ru };

export function t(lang: Lang, key: string): string {
  return translations[lang]?.[key] ?? translations.en[key] ?? key;
}
