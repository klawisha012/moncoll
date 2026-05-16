#/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload info
# Each entry has 'payload', 'method', 'headers', 'params', 'data', 'files'
php_payloads = {
    "933100": {
        "payload": "<?php echo 'test'; ?>",
        "method": "POST",
        "headers": {},
        "params": {"param": "<?php echo 'test'; ?>"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: PHP Open Tag Found"
    },
    "933110": {
        "payload": "evil.php",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data"},
        "params": {},
        "data": None,
        "files": {"file": ("evil.php", "content")},
        "note": "PHP Injection Attack: PHP Script File Upload Found"
    },
    "933120": {
        "payload": "disable_functions",
        "method": "POST",
        "headers": {},
        "params": {"param": "disable_functions"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Configuration Directive Found"
    },
    "933130": {
        "payload": "$_SERVER",
        "method": "POST",
        "headers": {},
        "params": {"param": "$_SERVER"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Variables Found"
    },
    "933140": {
        "payload": "php://input",
        "method": "POST",
        "headers": {},
        "params": {"param": "php://input"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: I/O Stream Found"
    },
    "933150": {
        "payload": "base64_decode",
        "method": "POST",
        "headers": {},
        "params": {"param": "base64_decode"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: High-Risk PHP Function Name Found"
    },
    "933160": {
        "payload": "eval(",
        "method": "POST",
        "headers": {},
        "params": {"param": "eval("},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: High-Risk PHP Function Call Found"
    },
    "933170": {
        "payload": 'O:8:"stdClass":1:{s:1:"a";i:2;}',
        "method": "POST",
        "headers": {},
        "params": {"param": 'O:8:"stdClass":1:{s:1:"a";i:2;}'},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Serialized Object Injection"
    },
    "933180": {
        "payload": "$func = 'system'; $func('ls');",
        "method": "POST",
        "headers": {},
        "params": {"param": "$func = 'system'; $func('ls');"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Variable Function Call Found"
    },
    "933200": {
        "payload": "zip://evil.zip",
        "method": "POST",
        "headers": {},
        "params": {"param": "zip://evil.zip"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Wrapper scheme detected"
    },
    "933210": {
        "payload": "($system)('ls');",
        "method": "POST",
        "headers": {},
        "params": {"param": "($system)('ls');"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Variable Function Call Found"
    },
    "933151": {
        "payload": "array_diff(",
        "method": "POST",
        "headers": {},
        "params": {"param": "array_diff("},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Medium-Risk PHP Function Name Found"
    },
    "933131": {
        "payload": "HTTP_USER_AGENT",
        "method": "POST",
        "headers": {},
        "params": {"param": "HTTP_USER_AGENT"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Variables Found"
    },
    "933161": {
        "payload": "abs(",
        "method": "POST",
        "headers": {},
        "params": {"param": "abs("},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Low-Value PHP Function Call Found"
    },
    "933111": {
        "payload": "evil.php.tmp",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data"},
        "params": {},
        "data": None,
        "files": {"file": ("evil.php.tmp", "content")},
        "note": "PHP Injection Attack: PHP Script File Upload Found"
    },
    "933190": {
        "payload": "?>",
        "method": "POST",
        "headers": {},
        "params": {"param": "?>"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: PHP Closing Tag Found"
    },
    "933211": {
        "payload": "(system)(ls);",
        "method": "POST",
        "headers": {},
        "params": {"param": "(system)(ls);"},
        "data": None,
        "files": None,
        "note": "PHP Injection Attack: Variable Function Call Found"
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

@pytest.mark.parametrize("rule_id,payload_info", list(php_payloads.items()))
def test_php_rule_trigger(setup_teardown, rule_id, payload_info):
    """Test that each PHP rule is triggered by its payload"""

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
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered. Found rules: {rule_ids_in_log}. Payload: {payload_info}"

if __name__ == "__main__":
    pytest.main([__file__])