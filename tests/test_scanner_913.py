#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> user_agent_payload
# These User-Agents are from scanners-user-agents.data and should trigger 913100
scanner_payloads = {
    "913100": "arachni",
    "913100": "sqlmap",
    "913100": "nikto",
    "913100": "nmap",
    "913100": "nuclei",
    "913100": "dirbuster",
    "913100": "wpscan",
    "913100": "nessus",
    "913100": "openvas",
    "913100": "zgrab",
}

@pytest.fixture(scope="function")
def setup_teardown():
    """Fixture for setup and teardown: clear logs before test"""
    try:
        subprocess.run(
            ["docker", "exec", "waf-angie-1", "truncate", "-s", "0", "/var/log/angie/modsec_audit.log"],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError:
        pass  # Ignore if truncate fails
    yield
    # Teardown: optionally clean up after test
    pass

@pytest.mark.parametrize("rule_id,user_agent", list(scanner_payloads.items()))
def test_scanner_detection_rule_trigger(setup_teardown, rule_id, user_agent):
    """Test that scanner detection rule is triggered by scanner User-Agents"""

    # Send GET request with scanner User-Agent
    headers = {"User-Agent": user_agent}
    try:
        response = requests.get("http://localhost/?param=test", headers=headers, timeout=10)
    except requests.RequestException as e:
        pytest.fail(f"Request failed: {e}")

    time.sleep(1)

    # Get logs from Docker container
    try:
        result = subprocess.run(
            ["docker", "exec", "waf-angie-1", "cat", "/var/log/angie/modsec_audit.log"],
            capture_output=True,
            text=True,
            check=True
        )
        log_content = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Error executing docker command: {e}")

    if not log_content:
        pytest.fail("Log file is empty or not found")

    # Parse JSON log
    try:
        log_data = json.loads(log_content)
    except json.JSONDecodeError as e:
        pytest.fail(f"Error parsing JSON log: {e}")

    # Extract messages with ruleId
    messages = log_data.get("messages", [])
    rule_ids_in_log = [msg.get("ruleId") for msg in messages if "ruleId" in msg]

    # Assert that the expected rule_id is triggered
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered for User-Agent '{user_agent}'. Found rules: {rule_ids_in_log}"

if __name__ == "__main__":
    pytest.main([__file__])