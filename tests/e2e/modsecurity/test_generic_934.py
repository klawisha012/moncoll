#/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload info
# Each entry has 'payload', 'method', 'headers', 'params', 'data', 'files'
generic_payloads = {
    "934100": {
        "payload": "_$$ND_FUNC$$_",
        "method": "POST",
        "headers": {},
        "params": {"param": "_$$ND_FUNC$$_"},
        "data": None,
        "files": None,
        "note": "Node.js Injection Attack 1/2"
    },
    "934110": {
        "payload": "http://169.254.169.254",
        "method": "POST",
        "headers": {},
        "params": {"param": "http://169.254.169.254"},
        "data": None,
        "files": None,
        "note": "Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter"
    },
    "934130": {
        "payload": "__proto__.toString",
        "method": "POST",
        "headers": {},
        "params": {"param": "__proto__.toString"},
        "data": None,
        "files": None,
        "note": "JavaScript Prototype Pollution"
    },
    "934150": {
        "payload": "Process.spawn(",
        "method": "POST",
        "headers": {},
        "params": {"param": "Process.spawn("},
        "data": None,
        "files": None,
        "note": "Ruby Injection Attack"
    },
    "934160": {
        "payload": "while(true){}",
        "method": "POST",
        "headers": {},
        "params": {"param": "while(true){}"},
        "data": None,
        "files": None,
        "note": "Node.js DoS attack"
    },
    "934170": {
        "payload": "data:text/plain;base64,",
        "method": "POST",
        "headers": {},
        "params": {"param": "data:text/plain;base64,"},
        "data": None,
        "files": None,
        "note": "PHP data scheme attack"
    },
    "934101": {
        "payload": "spawn(",
        "method": "POST",
        "headers": {},
        "params": {"param": "spawn("},
        "data": None,
        "files": None,
        "note": "Node.js Injection Attack 2/2"
    },
    "934120": {
        "payload": "http://2852039166/",
        "method": "POST",
        "headers": {},
        "params": {"param": "http://2852039166/"},
        "data": None,
        "files": None,
        "note": "Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address"
    },
    "934140": {
        "payload": "@{[system 'ls']}",
        "method": "POST",
        "headers": {},
        "params": {"param": "@{[system 'ls']}"},
        "data": None,
        "files": None,
        "note": "Perl Injection Attack"
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

@pytest.mark.parametrize("rule_id,payload_info", list(generic_payloads.items()))
def test_generic_rule_trigger(setup_teardown, rule_id, payload_info):
    """Test that each generic rule is triggered by its payload"""

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