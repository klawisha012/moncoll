#!/usr/bin/env python3
"""
CrowdSec Alerts Exporter
Polls CrowdSec Local API for new alerts and writes them to alerts.log in JSONL format
compatible with Vector's parse_crowdsec_alerts transform.
"""
import requests
import time
import json
import os
import yaml
from datetime import datetime

CROWDSEC_API = "http://crowdsec:8080"
ALERTS_ENDPOINT = f"{CROWDSEC_API}/v1/alerts"
TOKEN_ENDPOINT = f"{CROWDSEC_API}/v1/watchers/login"
CREDENTIALS_FILE = "/etc/crowdsec/local_api_credentials.yaml"
ALERTS_FILE = "/var/log/crowdsec/alerts.log"
POLL_INTERVAL = 5  # seconds

def get_token():
    """Read client credentials and fetch JWT token."""
    with open(CREDENTIALS_FILE, 'r') as f:
        cred = yaml.safe_load(f)
    client_id = cred.get('client_id', 'localhost')
    client_secret = cred.get('client_secret', '')
    resp = requests.post(TOKEN_ENDPOINT, json={'client_id': client_id, 'client_secret': client_secret}, timeout=10)
    resp.raise_for_status()
    token = resp.json().get('token')
    return token

def get_last_timestamp():
    """Read the last timestamp from the alerts file to avoid duplicates."""
    if not os.path.exists(ALERTS_FILE):
        return None
    try:
        with open(ALERTS_FILE, 'r') as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].strip()
                if last_line:
                    last_alert = json.loads(last_line)
                    return last_alert.get('timestamp')
    except Exception:
        pass
    return None

def fetch_alerts(token, since=None):
    """Call CrowdSec API to get alerts since given timestamp."""
    params = {'include_capi': 'false', 'output': 'json'}
    if since:
        params['since'] = since
    headers = {'Authorization': f'Bearer {token}'}
    try:
        resp = requests.get(ALERTS_ENDPOINT, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return []

def transform_alert(alert):
    """Transform API alert to format expected by Vector."""
    # Extract first decision if exists
    decision = {}
    if alert.get('decisions') and len(alert['decisions']) > 0:
        d = alert['decisions'][0]
        decision = {
            "type": d.get('type', ''),
            "duration": str(d.get('duration', '')),
            "scope": d.get('scope', ''),
            "value": d.get('value', ''),
            "origin": d.get('origin', ''),
            "simulated": d.get('simulated', False)
        }
    # Format timestamp to include milliseconds if missing
    ts = alert.get('start_at') or alert.get('created_at')
    if ts and 'Z' in ts and '.' not in ts:
        ts = ts.replace('Z', '.000Z')
    # Build transformed alert
    transformed = {
        "timestamp": ts,
        "alert_id": str(alert.get('id', '')),
        "scenario": alert.get('scenario', ''),
        "message": alert.get('message', ''),
        "source": {
            "ip": alert.get('source', {}).get('ip', '0.0.0.0')
        },
        "decision": decision,
        "meta": {},  # Not provided in API alert
        "capacity": alert.get('capacity', 0),
        "leakspeed": str(alert.get('leakspeed', '')),
        "events_count": alert.get('events_count', 0)
    }
    return transformed

def main():
    print("Starting CrowdSec alerts exporter...")
    token = None
    while True:
        try:
            if token is None:
                token = get_token()
            last_ts = get_last_timestamp()
            alerts = fetch_alerts(token, since=last_ts)
            if alerts:
                with open(ALERTS_FILE, 'a') as f:
                    for alert in alerts:
                        transformed = transform_alert(alert)
                        f.write(json.dumps(transformed) + '\n')
                print(f"Written {len(alerts)} alert(s) to {ALERTS_FILE}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            token = None  # Force token refresh next iteration
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

