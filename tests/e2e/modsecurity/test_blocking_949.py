#/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload info
# Each entry has 'payload', 'method', 'headers', 'params', 'data', 'files'
blocking_payloads = {
    "949110": {
        "payload": "high score",
        "method": "POST",
        "headers": {},
        "params": {"param": "high score"},
        "data": None,
        "files": None,
        "note": "Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})"
    }
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

@pytest.mark.parametrize("rule_id,payload_info", list(blocking_payloads.items()))
def test_blocking_rule_trigger(setup_teardown, rule_id, payload_info):
    """Test that blocking evaluation is triggered by high anomaly score"""

    payload = payload_info["payload"]
    method = payload_info["method"]
    headers = payload_info["headers"]
    params = payload_info["params"]
    data = payload_info["data"]
    files = payload_info["files"]

    # Build URL
    url = "http://localhost/"
    if method == "GET" and params:
        url += "?" + "&".join([f"{k}={requests.utils.quote(str(v))}" for k, v in params.items()])

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            if files:
                response = requests.post(url, headers=headers, data=data, files=files, timeout=10)
            else:
                response = requests.post(url, headers=headers, data=data, timeout=10)
        else:
            response = requests.request(method, url, headers=headers, data=data, params=params, files=files, timeout=10)
    except requests.RequestException as e:
        # If the connection was aborted, reset, or closed by WAF, proceed to check logs
        err_msg = str(e)
        if any(msg in err_msg for msg in ["Connection aborted", "Connection reset", "RemoteDisconnected", "Remote end closed"]):
            pass
        else:
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
        log_data = json.loads(log_content.splitlines()[-1])
    except json.JSONDecodeError as e:
        pytest.fail(f"Error parsing JSON log: {e}")

    # Extract messages with ruleId
    messages = log_data.get("transaction", {}).get("messages", []) or log_data.get("messages", [])
    rule_ids_in_log = []
    for m in messages:
        rid = m.get("ruleId") or m.get("details", {}).get("ruleId")
        if rid:
            rule_ids_in_log.append(rid)

    # Assert that the expected rule_id is triggered
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered. Found rules: {rule_ids_in_log}. Payload: {payload_info}"

if __name__ == "__main__":
    pytest.main([__file__])