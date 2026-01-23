#!/usr/bin/env python3

import requests
import time
import subprocess
import json

def test_modsecurity_advanced():
    print("Testing ModSecurity advanced rules trigger")

    # Test payloads for different attack types
    payloads = {
        "SQL Injection": "' UNION SELECT * FROM users; --",
        "XSS": "<script>alert('xss')</script>",
        "RCE": ";ls -la",
        "LFI": "../../../etc/passwd"
    }

    expected_rules = {
        "SQL Injection": "942100",
        "XSS": "941100",
        "RCE": "932230",
        "LFI": "930120"
    }

    triggered_rules = []

    for attack_type, payload in payloads.items():
        print(f"Sending {attack_type} payload: {payload}")
        response = requests.get(f"http://localhost/?param={payload}")
        time.sleep(0.5)  # Shorter sleep between requests

    time.sleep(2)  # Wait for logs to be written

    # Get logs from Docker container
    try:
        result = subprocess.run(
            ["docker", "exec", "waf-angie-1", "cat", "/var/log/angie/modsec_audit.log"],
            capture_output=True,
            text=True,
            check=True
        )
        log_content = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing docker command: {e}")
        return

    # Parse JSON log
    try:
        log_data = json.loads(log_content)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON log: {e}")
        return

    # Extract messages with ruleId
    messages = log_data.get("messages", [])
    filtered_messages = []
    for msg in messages:
        if "ruleId" in msg:
            filtered_messages.append(f"{msg['ruleId']}: {msg.get('msg', '')}")

    # Check for expected rules
    log_output = "\n".join(filtered_messages)
    for attack_type, rule_id in expected_rules.items():
        if rule_id in log_output:
            triggered_rules.append(f"{attack_type} (rule {rule_id})")
            print(f"{attack_type} rule triggered successfully with rule {rule_id}")
        else:
            print(f"{attack_type} rule not triggered (expected {rule_id})")

    if len(triggered_rules) == len(expected_rules):
        print("All advanced ModSecurity rules triggered successfully")
    else:
        print(f"Some rules not triggered. Triggered: {', '.join(triggered_rules)}")

if __name__ == "__main__":
    test_modsecurity_advanced()