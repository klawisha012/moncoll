#/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload info
# Each entry has 'payload', 'method', 'headers', 'params', 'data', 'files'
protocol_payloads = {
    "921110": {
        "payload": "get http/1.1",
        "method": "POST",
        "headers": {},
        "params": {"param": "get http/1.1"},
        "data": None,
        "files": None,
        "note": "HTTP Request Smuggling Attack"
    },
    "921120": {
        "payload": "\r\ncontent-type:",
        "method": "POST",
        "headers": {},
        "params": {"param": "\r\ncontent-type: text/plain"},
        "data": None,
        "files": None,
        "note": "HTTP Response Splitting Attack"
    },
    "921130": {
        "payload": "http/1.1",
        "method": "POST",
        "headers": {},
        "params": {"param": "http/1.1"},
        "data": None,
        "files": None,
        "note": "HTTP Response Splitting Attack"
    },
    "921140": {
        "payload": "\n",
        "method": "GET",
        "headers": {"X-Test": "value\nvalue"},
        "params": {},
        "data": None,
        "files": None,
        "note": "HTTP Header Injection Attack via headers"
    },
    "921150": {
        "payload": "\n",
        "method": "POST",
        "headers": {},
        "params": {"param\n": "value"},
        "data": None,
        "files": None,
        "note": "HTTP Header Injection Attack via payload (CR/LF detected)"
    },
    "921160": {
        "payload": "\nrefresh:",
        "method": "GET",
        "headers": {},
        "params": {"param": "\nrefresh: http://evil.com"},
        "data": None,
        "files": None,
        "note": "HTTP Header Injection Attack via payload (CR/LF and header-name detected)"
    },
    "921190": {
        "payload": "\n",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "HTTP Splitting (CR/LF in request filename detected)"
    },
    "921200": {
        "payload": ")(cn=root)",
        "method": "POST",
        "headers": {},
        "params": {"param": ")(cn=root)"},
        "data": None,
        "files": None,
        "note": "LDAP Injection Attack"
    },
    "921421": {
        "payload": "application/json",
        "method": "POST",
        "headers": {"Content-Type": "text/plain; application/json"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Content-Type header: Dangerous content type outside the mime type declaration"
    },
    "921240": {
        "payload": "unix:AAAAAAAAAAAAA|http://",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "mod_proxy attack attempt detected"
    },
    "921151": {
        "payload": "\n",
        "method": "GET",
        "headers": {},
        "params": {"param": "value\n"},
        "data": None,
        "files": None,
        "note": "HTTP Header Injection Attack via payload (CR/LF detected)"
    },
    "921422": {
        "payload": "audio/wav",
        "method": "POST",
        "headers": {"Content-Type": "text/plain; audio/wav"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Content-Type header: Dangerous content type outside the mime type declaration"
    },
    "921230": {
        "payload": "bytes=1-10",
        "method": "GET",
        "headers": {"Range": "bytes=1-10"},
        "params": {},
        "data": None,
        "files": None,
        "note": "HTTP Range Header detected"
    },
    "921170": {
        "payload": "multiple same params",
        "method": "GET",
        "headers": {},
        "params": {"param": ["value1", "value2"]},
        "data": None,
        "files": None,
        "note": "HTTP Parameter Pollution"
    },
    "921180": {
        "payload": "multiple same params",
        "method": "GET",
        "headers": {},
        "params": {"param": ["value1", "value2"]},
        "data": None,
        "files": None,
        "note": "HTTP Parameter Pollution (%{TX.1})"
    },
    "921210": {
        "payload": "foo[1]a",
        "method": "GET",
        "headers": {},
        "params": {"foo[1]a": "bar"},
        "data": None,
        "files": None,
        "note": "HTTP Parameter Pollution after detecting bogus char after parameter array"
    },
    "921220": {
        "payload": "foo[1]",
        "method": "GET",
        "headers": {},
        "params": {"foo[1]": "bar"},
        "data": None,
        "files": None,
        "note": "HTTP Parameter Pollution possible via array notation"
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

@pytest.mark.parametrize("rule_id,payload_info", list(protocol_payloads.items()))
def test_protocol_rule_trigger(setup_teardown, rule_id, payload_info):
    """Test that each protocol enforcement rule is triggered by its payload"""

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