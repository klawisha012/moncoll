#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: list of test cases for LFI rules
lfi_test_cases = [
    {
        "rule_id": "930100",
        "url": "http://localhost/",
        "params": {"param": "../../../etc/passwd"},
        "headers": {}
    },
    {
        "rule_id": "930110",
        "url": "http://localhost/",
        "params": {"param": "../../../etc/passwd"},
        "headers": {}
    },
    {
        "rule_id": "930120",
        "url": "http://localhost/",
        "params": {"param": "../../../etc/passwd"},
        "headers": {}
    },
    {
        "rule_id": "930130",
        "url": "http://localhost/.env",
        "params": {},
        "headers": {}
    },
]

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

@pytest.mark.parametrize("test_case", lfi_test_cases, ids=[tc["rule_id"] for tc in lfi_test_cases])
def test_lfi_rule_trigger(setup_teardown, test_case):
    """Test that each LFI rule is triggered by its payload"""

    # Send GET request with LFI payload based on test case
    try:
        response = requests.get(
            test_case["url"],
            params=test_case["params"],
            headers=test_case["headers"],
            timeout=10
        )
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
    assert test_case["rule_id"] in rule_ids_in_log, f"Rule {test_case['rule_id']} not triggered. Found rules: {rule_ids_in_log}"

if __name__ == "__main__":
    pytest.main([__file__])