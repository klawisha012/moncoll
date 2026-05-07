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
