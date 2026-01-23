#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload
xss_payloads = {
    "941100": "<script>alert</script>",
    "941110": "<script>alert(1)</script>",
    "941130": "xlink:href=javascript:alert(1)",
    "941140": "background:url(javascript:alert(1))",
    "941160": "<script>alert(1)</script>",
    "941170": "javascript:alert(1)",
    "941180": "document.cookie",
    "941190": "<style>@import",
    "941200": "<vmlframe src=",
    "941210": "javascript:",
    "941220": "vbscript:",
    "941230": "<embed src=",
    "941240": "<import implementation=",
    "941250": "<meta http-equiv=",
    "941260": "<meta charset=",
    "941270": "<link href=",
    "941280": "<base href=",
    "941290": "<applet>",
    "941300": "<object code=",
    "941310": "\xbcscript\xbealert\xbc/script\xbe",
    "941350": "+ADw-script+AD4-alert+ADw-/script+AD4-",
    "941360": "!![]",
    "941370": "self[document]",
    "941390": "eval(",
    "941400": "[].sort.call`${alert}`1337",
    "941101": "<script>alert</script>",  # in filename
    "941120": "onload=",
    "941150": "href=",
    "941181": "-->",
    "941320": "<script>",
    "941330": 'location.href',
    "941340": 'location.href',
    "941380": "{{constructor.constructor('alert(1)')()}}"
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

@pytest.mark.parametrize("rule_id,payload", list(xss_payloads.items()))
def test_xss_rule_trigger(setup_teardown, rule_id, payload):
    """Test that each XSS rule is triggered by its payload"""

    # Send GET request with XSS payload
    try:
        response = requests.get(f"http://localhost/?param={requests.utils.quote(payload)}", timeout=10)
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
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered. Found rules: {rule_ids_in_log}"

if __name__ == "__main__":
    pytest.main([__file__])