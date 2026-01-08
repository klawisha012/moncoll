CREATE TABLE access_logs (
    timestamp DateTime DEFAULT now(),
    message String
) ENGINE = MergeTree()
ORDER BY timestamp;