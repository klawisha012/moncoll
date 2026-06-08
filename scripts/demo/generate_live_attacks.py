#!/usr/bin/env python3
import time
import json
import random
import os
import uuid
from datetime import datetime, timezone
import redis
from clickhouse_driver import Client as ClickHouseClient

# Realistic global cities
LOCATIONS = [
    {"country_code": "RU", "latitude": 55.7558, "longitude": 37.6173, "city_name": "Moscow"},
    {"country_code": "US", "latitude": 37.7749, "longitude": -122.4194, "city_name": "San Francisco"},
    {"country_code": "GB", "latitude": 51.5074, "longitude": -0.1278, "city_name": "London"},
    {"country_code": "JP", "latitude": 35.6762, "longitude": 139.6503, "city_name": "Tokyo"},
    {"country_code": "CN", "latitude": 32.0603, "longitude": 118.7969, "city_name": "Nanjing"},
    {"country_code": "AU", "latitude": -33.8688, "longitude": 151.2093, "city_name": "Sydney"},
    {"country_code": "EG", "latitude": 30.0444, "longitude": 31.2357, "city_name": "Cairo"},
    {"country_code": "BR", "latitude": -22.9068, "longitude": -43.1729, "city_name": "Rio de Janeiro"},
    {"country_code": "DE", "latitude": 52.5200, "longitude": 13.4050, "city_name": "Berlin"},
    {"country_code": "FR", "latitude": 48.8566, "longitude": 2.3522, "city_name": "Paris"},
    {"country_code": "IN", "latitude": 19.0760, "longitude": 72.8777, "city_name": "Mumbai"},
]

SCENARIOS = [
    {"rule_id": "941100", "severity": 3, "msg": "XSS Attack Detected", "file": "REQUEST-941-APPLICATION-ATTACK-XSS.conf"},
    {"rule_id": "942100", "severity": 4, "msg": "SQL Injection Attack Detected", "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"},
    {"rule_id": "932100", "severity": 4, "msg": "Remote Code Execution (RCE) Attempt", "file": "REQUEST-932-APPLICATION-ATTACK-RCE.conf"},
    {"rule_id": "930100", "severity": 2, "msg": "Local File Inclusion (LFI) Attempt", "file": "REQUEST-930-APPLICATION-ATTACK-LFI.conf"},
    {"rule_id": "913100", "severity": 1, "msg": "Malicious Scanner Request Blocked", "file": "REQUEST-913-SCANNER-DETECTION.conf"},
]

DOMAINS = ["test1.zwarder.ru", "test2.zwarder.ru", "localhost"]

def load_env_credentials():
    creds = {
        "user": os.environ.get("CLICKHOUSE_USER", "default"),
        "password": os.environ.get("CLICKHOUSE_PASSWORD", ""),
        "db": os.environ.get("CLICKHOUSE_DB", "logs"),
    }
    # Also check /app/.env if we are in Docker container
    env_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        "/app/.env"
    ]
    for env_path in env_paths:
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip().strip('"').strip("'")
                        if key == "CLICKHOUSE_USER" and not os.environ.get("CLICKHOUSE_USER"):
                            creds["user"] = val
                        elif key == "CLICKHOUSE_PASSWORD" and not os.environ.get("CLICKHOUSE_PASSWORD"):
                            creds["password"] = val
                        elif key == "CLICKHOUSE_DB" and not os.environ.get("CLICKHOUSE_DB"):
                            creds["db"] = val
            break
    return creds


def main():
    # Resolve hostnames based on where the script runs (host vs container)
    is_docker = os.path.exists("/.dockerenv") or os.environ.get("AM_I_IN_A_DOCKER_CONTAINER")
    redis_host = "redis" if is_docker else "127.0.0.1"
    ch_host = "clickhouse" if is_docker else "127.0.0.1"

    print(f"Connecting to Redis at {redis_host}...")
    try:
        r = redis.Redis(host=redis_host, port=6379, db=0, socket_timeout=3.0)
        r.ping()
    except Exception as e:
        print(f"Error connecting to Redis: {e}")
        return

    creds = load_env_credentials()
    print(f"Connecting to ClickHouse at {ch_host}:9000...")
    try:
        ch_client = ClickHouseClient(
            host=ch_host,
            port=9000,
            user=creds["user"],
            password=creds["password"],
            database=creds["db"],
            connect_timeout=5
        )
        ch_client.execute("SELECT 1")
    except Exception as e:
        print(f"Error connecting to ClickHouse: {e}")
        return

    print("SUCCESS: Connected to Redis & ClickHouse!")
    print("Starting real-time attack simulation with direct ClickHouse insertion...")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            burst_size = random.randint(1, 3)
            now = datetime.now(timezone.utc)

            access_batch = []
            waf_batch = []

            for _ in range(burst_size):
                loc = random.choice(LOCATIONS)
                status = random.choice([200, 200, 200, 302, 404, 403, 403])
                ip = f"198.51.{random.randint(1, 254)}.{random.randint(1, 254)}"
                selected_host = random.choice(DOMAINS)
                
                # 1. Access Log Row
                access_batch.append((
                    now,
                    ip,
                    "",
                    random.choice(["GET", "POST"]),
                    random.choice(["/", "/login", "/dashboard", "/api/v1/metrics"]),
                    "HTTP/1.1",
                    status,
                    random.randint(256, 16384),
                    "https://github.com",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    loc["country_code"],
                    loc["city_name"],
                    "Live Simulation Network",
                    loc["latitude"],
                    loc["longitude"],
                    selected_host
                ))

                # 2. WAF Audit Log Row (if attack simulated)
                if status == 403:
                    scenario = random.choice(SCENARIOS)
                    unique_id = str(uuid.uuid4())
                    waf_batch.append((
                        now,
                        unique_id,
                        "waf-server-main",
                        ip,
                        random.randint(1024, 65535),
                        "127.0.0.1",
                        443,
                        "POST",
                        "HTTP/1.1",
                        random.choice(["/admin?sqli=UNION+SELECT", "/login?user=<script>"]),
                        {"Host": selected_host, "User-Agent": "curl/7.68.0"},
                        403,
                        {"Content-Type": "text/html"},
                        "modsecurity-crs",
                        "angie-connector",
                        "on",
                        [scenario["rule_id"]],
                        [scenario["severity"]],
                        [scenario["msg"]],
                        ["Matched pattern in payload"],
                        [scenario["file"]],
                        ["231"],
                        ["ARGS:param"],
                        [[f"tag_crs_{scenario['rule_id']}", "attack-generic"]],
                        random.randint(15, 65)
                    ))

                # 3. WebSocket Realtime Map Push (via Redis)
                event = {
                    "geoip": {
                        "country_code": loc["country_code"],
                        "latitude": loc["latitude"] + random.uniform(-0.3, 0.3),
                        "longitude": loc["longitude"] + random.uniform(-0.3, 0.3),
                        "city_name": loc["city_name"]
                    },
                    "status": status
                }
                r.publish("attacks:raw", json.dumps(event))

            # Insert batch into ClickHouse
            if access_batch:
                ch_client.execute(
                    "INSERT INTO logs.nginx_access_log ("
                    "  time_local, remote_addr, remote_user, request_method, request_uri, "
                    "  server_protocol, status, body_bytes_sent, http_referer, http_user_agent, "
                    "  geoip_country_code, geoip_city_name, geoip_organization, "
                    "  geoip_latitude, geoip_longitude, host"
                    ") VALUES",
                    access_batch
                )
            if waf_batch:
                ch_client.execute(
                    "INSERT INTO logs.waf_audit_log ("
                    "  timestamp, unique_id, server_id, client_ip, client_port, host_ip, host_port, "
                    "  request_method, request_http_version, request_uri, request_headers, "
                    "  response_http_code, response_headers, producer_modsecurity, producer_connector, "
                    "  producer_secrules_engine, messages.ruleId, messages.severity, messages.message, "
                    "  messages.data, messages.file, messages.lineNumber, messages.match, messages_tags, "
                    "  anomaly_score"
                    ") VALUES",
                    waf_batch
                )

            time.sleep(random.uniform(0.5, 1.5))

    except KeyboardInterrupt:
        print("\nStopping live simulation. Done.")

if __name__ == "__main__":
    main()
