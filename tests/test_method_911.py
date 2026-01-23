#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: method -> expected rule_id
# These methods are not in the default allowed_methods (GET HEAD POST OPTIONS)
method_payloads = {
    "911100": "PUT",      # Should trigger 911100
    "911100": "DELETE",   # Should trigger 911100
    "911100": "PATCH",    # Should trigger 911100
    "911100": "TRACE",    # Should trigger 911100
    "911100": "CONNECT",  # Should trigger 911100
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

@pytest.mark.parametrize("rule_id,method", list(method_payloads.items()))
def test_method_enforcement_rule_trigger(setup_teardown, rule_id, method):
    """Test that method enforcement rule is triggered by disallowed methods"""

    # Send request with disallowed method
    try:
        response = requests.request(method, "http://localhost/?param=test", timeout=10)
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
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered for method {method}. Found rules: {rule_ids_in_log}"

if __name__ == "__main__":
    pytest.main([__file__])