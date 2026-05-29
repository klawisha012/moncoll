#/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload
# Only includes rules that can be triggered by GET requests with param=payload
rce_payloads = {
    "932120": "Get-Process",
    "932125": "gps",
    "932130": "$(id)",
    "932140": "for %a in (set) do",
    "932160": "uname",
    "932170": "() { :; }; echo vulnerable",
    "932171": "() { :; }; echo vulnerable",
    "932175": "alias ls='rm -rf /'",
    "932190": "/*/*/",
    "932200": "cat$u+/etc$u/passwd",
    "932210": ";.system 'ls'",
    "932220": "cat /etc/passwd |",
    "932230": ";ls -la",
    "932235": "uname -a",
    "932250": "ls -la",
    "932260": "whoami",
    "932330": "!-1",
    "932370": "cmd /c dir",
    "932380": "net user",
    # Note: 955100 is response-based and cannot be tested with this method
    # "955100": "web-shell content"  # Response-based rule, not applicable
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

@pytest.mark.parametrize("rule_id,payload", list(rce_payloads.items()))
def test_rce_rule_trigger(setup_teardown, rule_id, payload):
    """Test that each RCE rule is triggered by its payload"""

    # Send GET request with RCE payload
    try:
        response = requests.get(f"http://localhost/?param={requests.utils.quote(payload)}", timeout=10)
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
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered. Found rules: {rule_ids_in_log}"

if __name__ == "__main__":
    pytest.main([__file__])