#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-950-DATA-LEAKAGES rules (950xxx)
#
# These rules check response bodies and status codes for data leakages:
# - 950100: 500-level status codes
# - 950130: Directory listings
# - 950140: CGI source code leakage
#
# To properly test these RESPONSE rules, a test server must be configured to return
# specific responses containing the patterns that trigger these rules.
#
# For example:
# - An endpoint that returns HTTP 500 status
# - An endpoint that returns directory listing HTML
# - An endpoint that returns CGI script source code starting with #!
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that return problematic responses
data_leakage_endpoints = {
    "950100": "/server-error",  # Should return 500 status
    "950130": "/directory-listing",  # Should return directory listing HTML
    "950140": "/cgi-source",  # Should return CGI script source
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

@pytest.mark.parametrize("rule_id,endpoint", list(data_leakage_endpoints.items()))
def test_data_leakage_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for data leakage rules

    NOTE: This test requires a specially configured server that returns
    responses triggering the specific rules. The server must be set up to:

    For 950100: Return HTTP 500 status code
    For 950130: Return HTML with directory listing content like:
        <TITLE>Index of /</TITLE><H1>Index of /</H1>
    For 950140: Return content starting with #!/usr/bin/perl or similar

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to return leakage responses")

    # This would send request to endpoint that returns problematic response
    try:
        response = requests.get(f"http://localhost{endpoint}", timeout=10)
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