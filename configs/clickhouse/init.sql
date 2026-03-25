CREATE DATABASE IF NOT EXISTS logs;

-- Таблица для логов ModSecurity (WAF)
-- Оптимизирована для хранения вложенных алертов и сложных структур запроса
CREATE TABLE IF NOT EXISTS logs.waf_audit_log
(
    -- Временная метка события
    `timestamp` DateTime CODEC(Delta, ZSTD(1)),
    
    -- Идентификаторы
    `unique_id` String,
    `server_id` String,
    
    -- Сетевая информация (IPv4/IPv6 эффективнее String)
    `client_ip` String,
    `client_port` UInt16,
    `host_ip` String,
    `host_port` UInt16,
    
    -- Детали HTTP запроса
    `request_method` LowCardinality(String),
    `request_http_version` LowCardinality(String),
    `request_uri` String,
    `request_headers` Map(String, String), -- Хранение заголовков как Map
    
    -- Детали ответа
    `response_http_code` UInt16,
    `response_headers` Map(String, String),
    
    -- Информация о движке WAF
    `producer_modsecurity` LowCardinality(String),
    `producer_connector` LowCardinality(String),
    `producer_secrules_engine` LowCardinality(String),
    
    -- Вложенная структура для сообщений об атаках (messages)
    -- Nested автоматически создает массивы: messages.ruleId, messages.severity и т.д.
    `messages` Nested
    (
        ruleId String,
        severity UInt8,
        message String,
        data String,
        file String,
        lineNumber String,
        match String
    ),
    
    -- Теги идут массивом строк для каждого сообщения, Nested не поддерживает Array внутри,
    -- поэтому выносим в параллельный массив массивов
    `messages_tags` Array(Array(String)), 
    
    -- Технические метрики WAF (из messages, если нужно агрегировать общий скор)
    `anomaly_score` UInt32 DEFAULT 0

) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp) -- Партицирование по месяцам
ORDER BY (timestamp, client_ip, unique_id) -- Сортировка для быстрого поиска
TTL timestamp + INTERVAL 6 MONTH; -- Авто-удаление старых логов через 6 месяцев


-- Таблица для Access Logs (Nginx)
-- Легковесная таблица для аналитики трафика
CREATE TABLE IF NOT EXISTS logs.nginx_access_log
(
    `time_local` DateTime CODEC(Delta, ZSTD(1)),
    
    `remote_addr` IPv4,
    `remote_user` String,
    
    `request_method` LowCardinality(String),
    `request_uri` String,
    `server_protocol` LowCardinality(String),
    
    `status` UInt16,
    `body_bytes_sent` UInt64,
    
    `http_referer` String,
    `http_user_agent` String,
    
    -- GeoIP данные (разворачиваем объект geoip)
    `geoip_country_code` LowCardinality(String),
    `geoip_city_name` LowCardinality(String),
    `geoip_organization` String,
    `geoip_latitude` Float64,
    `geoip_longitude` Float64

) ENGINE = MergeTree()
PARTITION BY toYYYYMM(time_local)
ORDER BY (time_local, remote_addr, status)
TTL time_local + INTERVAL 3 MONTH;