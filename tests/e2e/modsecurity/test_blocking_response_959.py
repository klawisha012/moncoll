#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-959-BLOCKING-EVALUATION rules (959xxx)
#
# These rules evaluate outbound anomaly scores and perform blocking decisions:
# - 959100: Outbound Anomaly Score Exceeded (phase 4)
# - 959101: Outbound Anomaly Score Exceeded in phase 3 (early blocking)
# - Various other rules for summing up anomaly scores across paranoia levels
#
# To properly test these RESPONSE rules, a test server must be configured to return
# responses that trigger multiple outbound anomaly rules simultaneously, causing
# the total anomaly score to exceed the threshold (tx.outbound_anomaly_score_threshold).
#
# The server should return responses that combine multiple leakages:
# - SQL error messages + PHP errors + Java stack traces
# - Multiple web shell signatures
# - IIS error pages + directory listings
# - etc.
#
# The combination should result in an anomaly score high enough to trigger blocking.
# The default threshold is usually 5, but can be configured.
#
# For example, a single response that contains:
# - SQL error from 951xxx rules
# - PHP error from 953xxx rules
# - Java error from 952xxx rules
# - Web shell signature from 955xxx rules
#
# Should trigger multiple rules and exceed the threshold.
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that return high-anomaly responses
blocking_response_endpoints = {
    "959100": "/high-anomaly-response",  # Should trigger multiple outbound rules exceeding threshold in phase 4
    "959101": "/early-blocking-response",  # Should trigger early blocking in phase 3
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

@pytest.mark.parametrize("rule_id,endpoint", list(blocking_response_endpoints.items()))
def test_blocking_response_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for blocking response evaluation rules

    NOTE: This test requires a specially configured server that returns
    responses triggering multiple outbound anomaly rules simultaneously.
    The server must be set up to return responses that combine multiple
    types of leakages to exceed the anomaly score threshold.

    Example response that should trigger blocking (combining multiple categories):

    HTTP Response Body containing:
    - SQL error: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    - PHP error: "Fatal error: Call to undefined function foo() in /var/www/html/index.php on line 5"
    - Java stack trace: "java.lang.NullPointerException at com.example.MyClass.method(MyClass.java:42)"
    - Web shell signature: "<title>r57 Shell Version 2.0</title>"
    - IIS error: "<title>500 - Internal server error.</title>"
    - Directory listing: "<TITLE>Index of /</TITLE><H1>Index of /</H1>"

    This combination should trigger rules from 951xxx, 953xxx, 952xxx, 955xxx, 954xxx, 950xxx
    categories, accumulating enough anomaly score to exceed the threshold and trigger blocking.

    For early blocking (959101), the response needs to trigger enough rules in phase 3
    to exceed the threshold before phase 4 processing.

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to return high-anomaly responses that trigger blocking")

    # This would send request to endpoint that returns high-anomaly response
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

    # For blocking rules, we expect the response to be blocked/denied
    # The log should show the blocking rule was triggered
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered. Found rules: {rule_ids_in_log}"

    # Additional check: verify that the request was actually blocked
    # This would require checking response status or other indicators
    # For now, just verify the rule triggered

if __name__ == "__main__":
    pytest.main([__file__])