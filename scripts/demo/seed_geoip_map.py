#!/usr/bin/env python3
"""Seeding script to populate WAF 2D/3D maps and dashboards with realistic global traffic.

Reads credentials from the project's .env file, fetches active domain connections
from the PostgreSQL database, and inserts hundreds of access and security logs
across various global coordinates matching those active domains in ClickHouse.
"""

from datetime import datetime, timedelta, timezone
import os
import random
import subprocess
import json
import uuid
from clickhouse_driver import Client as ClickHouseClient

# Realistic global cities and threat counts
SEEDS = [
    {"ip": "81.177.100.1", "country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "hits": 320, "threats": 42},
    {"ip": "8.8.8.8", "country": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "hits": 650, "threats": 85},
    {"ip": "178.62.200.1", "country": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278, "hits": 410, "threats": 38},
    {"ip": "210.140.10.1", "country": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "hits": 520, "threats": 61},
    {"ip": "114.114.114.114", "country": "CN", "city": "Nanjing", "lat": 32.0603, "lon": 118.7969, "hits": 280, "threats": 29},
    {"ip": "1.1.1.1", "country": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "hits": 190, "threats": 12},
    {"ip": "163.121.10.1", "country": "EG", "city": "Cairo", "lat": 30.0444, "lon": 31.2357, "hits": 140, "threats": 18},
    {"ip": "186.200.10.1", "country": "BR", "city": "Rio de Janeiro", "lat": -22.9068, "lon": -43.1729, "hits": 230, "threats": 27},
    {"ip": "82.165.10.1", "country": "DE", "city": "Berlin", "lat": 52.5200, "lon": 13.4050, "hits": 260, "threats": 21},
    {"ip": "194.254.10.1", "country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "hits": 310, "threats": 33},
    {"ip": "103.21.10.1", "country": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "hits": 340, "threats": 49},
    {"ip": "197.80.10.1", "country": "ZA", "city": "Cape Town", "lat": -33.9249, "lon": 18.4241, "hits": 120, "threats": 8},
    {"ip": "185.112.10.1", "country": "IS", "city": "Reykjavik", "lat": 64.1466, "lon": -21.9426, "hits": 80, "threats": 5},
]

# Unresolved GeoIP ranges
UNRESOLVED = [
    {"ip": "203.0.113.8", "hits": 45},
    {"ip": "198.51.100.15", "hits": 65},
    {"ip": "192.0.2.42", "hits": 35},
]

# Threat rules for logs.waf_audit_log
SCENARIOS = [
    {"rule_id": "941100", "severity": 3, "msg": "XSS Attack Detected", "file": "REQUEST-941-APPLICATION-ATTACK-XSS.conf"},
    {"rule_id": "942100", "severity": 4, "msg": "SQL Injection Attack Detected", "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"},
    {"rule_id": "932100", "severity": 4, "msg": "Remote Code Execution (RCE) Attempt", "file": "REQUEST-932-APPLICATION-ATTACK-RCE.conf"},
    {"rule_id": "930100", "severity": 2, "msg": "Local File Inclusion (LFI) Attempt", "file": "REQUEST-930-APPLICATION-ATTACK-LFI.conf"},
    {"rule_id": "913100", "severity": 1, "msg": "Malicious Scanner Request Blocked", "file": "REQUEST-913-SCANNER-DETECTION.conf"},
]


def load_env_credentials():
    """Locate and parse the .env file in the WAF repository root."""
    creds = {
        "user": "default",
        "password": "",
        "db": "logs"
    }
    # Script lives at scripts/demo/, so the repo root (where .env sits) is three levels up.
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
    if not os.path.exists(env_path):
        print(f"Warning: .env file not found at {env_path}, using defaults.")
        return creds

    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key == "CLICKHOUSE_USER":
                    creds["user"] = val
                elif key == "CLICKHOUSE_PASSWORD":
                    creds["password"] = val
                elif key == "CLICKHOUSE_DB":
                    creds["db"] = val
    return creds


def get_db_domains():
    """Fetch active domains from Postgres so seeded traffic matches dashboard filters.

    The backend was migrated Python -> Go, so the old waf-backend-1 Python
    container no longer exists. Query the waf-postgres-1 container directly.
    """
    try:
        cmd = [
            "docker", "exec", "waf-postgres-1", "psql", "-U", "waf", "-d", "waf", "-tAc",
            "SELECT domain FROM connections WHERE enabled = true;",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        domains = [d.strip() for d in res.stdout.strip().splitlines() if d.strip()]
        if domains:
            print(f"Discovered active connections: {domains}")
            return list(set(domains))
    except Exception as e:
        print(f"Warning: Failed to fetch connections dynamically, falling back: {e}")

    return ["test1.zwarder.ru", "test2.zwarder.ru", "waf.example.com", "localhost"]


def main():
    creds = load_env_credentials()
    domains = get_db_domains()
    
    print("Connecting to ClickHouse at 127.0.0.1:9000...")
    
    try:
        client = ClickHouseClient(
            host="127.0.0.1",
            port=9000,
            user=creds["user"],
            password=creds["password"],
            database=creds["db"],
            connect_timeout=5
        )
        client.execute("SELECT 1")
    except Exception as e:
        print(f"Error: Unable to connect to ClickHouse. Make sure 'docker compose up -d' is running.\n{e}")
        return

    # Clear old data to ensure fresh, clean visualizations
    print("Clearing existing nginx_access_log and waf_audit_log tables...")
    client.execute("TRUNCATE TABLE logs.nginx_access_log")
    client.execute("TRUNCATE TABLE logs.waf_audit_log")

    now = datetime.now(timezone.utc)
    access_logs = []
    waf_logs = []

    total_requests = 0
    total_threats = 0

    print("Generating seeded GeoIP traffic and WAF security blocks...")
    
    for item in SEEDS:
        ip = item["ip"]
        country = item["country"]
        city = item["city"]
        lat = item["lat"]
        lon = item["lon"]
        hits = item["hits"]
        threats = item["threats"]

        total_requests += hits
        total_threats += threats

        # Generate hits distributed over the last 2 hours
        for i in range(hits):
            # Create a staggered timestamp
            ts = now - timedelta(minutes=random.randint(0, 120))
            status = random.choice([200, 200, 200, 204, 301, 302, 304, 404, 404])
            
            # Staggered IP generation to make dashboard statistics look beautiful and detailed
            ip_octets = ip.split(".")
            staggered_ip = f"{ip_octets[0]}.{ip_octets[1]}.{ip_octets[2]}.{random.randint(1, 254)}"
            
            selected_host = random.choice(domains)

            access_logs.append((
                ts,
                staggered_ip,
                "",  # remote_user
                random.choice(["GET", "GET", "GET", "POST", "HEAD"]),
                random.choice(["/", "/dashboard", "/api/v1/metrics", "/login", "/static/bundle.js", "/assets/hero.png"]),
                "HTTP/1.1",
                status,
                random.randint(128, 65536),
                random.choice(["", "https://google.com", "https://github.com", "http://localhost:3000/"]),
                random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36"
                ]),
                country,
                city,
                "Threat Intelligence Network",
                lat,
                lon,
                selected_host
            ))

        # Generate WAF threat entries for this location
        for i in range(threats):
            ts = now - timedelta(minutes=random.randint(0, 120))
            scenario = random.choice(SCENARIOS)
            staggered_ip = f"{ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}.{random.randint(1, 254)}"
            selected_host = random.choice(domains)
            
            # WAF log entry
            unique_id = str(uuid.uuid4())
            req_uri = random.choice(["/admin?sqli=UNION+SELECT", "/login?user=<script>alert(1)", "/shell?cmd=cat+/etc/passwd", "/upload"])
            
            # clickhouse nested array join properties
            waf_logs.append((
                ts,
                unique_id,
                "waf-server-main",
                staggered_ip,
                random.randint(1024, 65535),
                "127.0.0.1",
                443,
                "POST",
                "HTTP/1.1",
                req_uri,
                {"Host": selected_host, "User-Agent": "curl/7.68.0", "X-Test-Source": "geoip-seeder"},
                403,
                {"Content-Type": "text/html", "Server": "Angie"},
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
                random.randint(5, 45) # anomaly score
            ))

    # Add Unresolved IP logs
    for item in UNRESOLVED:
        ip = item["ip"]
        hits = item["hits"]
        total_requests += hits

        for i in range(hits):
            ts = now - timedelta(minutes=random.randint(0, 120))
            
            # Staggered IP
            staggered_ip = f"{ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}.{random.randint(1, 254)}"
            selected_host = random.choice(domains)
            
            access_logs.append((
                ts,
                staggered_ip,
                "",
                "GET",
                "/static/config.json",
                "HTTP/1.1",
                404,
                128,
                "",
                "pytest-unresolved-ip",
                "",  # no country
                "",  # no city
                "",  # no org
                0.0, # no coordinates
                0.0,
                selected_host
            ))

    # 1. Batch insert Access Logs
    print(f"Inserting {len(access_logs)} Access Logs into logs.nginx_access_log...")
    client.execute(
        "INSERT INTO logs.nginx_access_log ("
        "  time_local, remote_addr, remote_user, request_method, request_uri, "
        "  server_protocol, status, body_bytes_sent, http_referer, http_user_agent, "
        "  geoip_country_code, geoip_city_name, geoip_organization, "
        "  geoip_latitude, geoip_longitude, host"
        ") VALUES",
        access_logs
    )

    # 2. Batch insert WAF Audit Logs
    print(f"Inserting {len(waf_logs)} WAF Security Logs into logs.waf_audit_log...")
    client.execute(
        "INSERT INTO logs.waf_audit_log ("
        "  timestamp, unique_id, server_id, client_ip, client_port, host_ip, host_port, "
        "  request_method, request_http_version, request_uri, request_headers, "
        "  response_http_code, response_headers, producer_modsecurity, producer_connector, "
        "  producer_secrules_engine, messages.ruleId, messages.severity, messages.message, "
        "  messages.data, messages.file, messages.lineNumber, messages.match, messages_tags, "
        "  anomaly_score"
        ") VALUES",
        waf_logs
    )

    print("\n" + "=" * 50)
    print("SUCCESS: SEEDING COMPLETED SUCCESSFULLY!")
    print(f"Total seeded Access Requests: {total_requests}")
    print(f"Total seeded WAF Threat blocks: {total_threats}")
    print("All coordinates, cities, severities, and metrics are successfully loaded.")
    print("Your 2D map, 3D Globe, unresolved IPs lists, and dashboards are now fully populated!")
    print("=" * 50)


if __name__ == "__main__":
    main()
