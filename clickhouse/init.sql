CREATE DATABASE IF NOT EXISTS waf;

USE waf;

CREATE TABLE access_logs (
    timestamp DateTime DEFAULT now(),
    message String
) ENGINE = MergeTree()
ORDER BY timestamp;