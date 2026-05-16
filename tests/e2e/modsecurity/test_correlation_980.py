#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-980-CORRELATION rules (980xxx)
#
# These rules perform correlation between inbound and outbound anomaly scores
# in the logging phase (phase 5):
# - 980170: Anomaly Scores reporting (main correlation rule)
# - Various rules for score combination and reporting thresholds
#
# To properly test these RESPONSE rules, a test server must be configured to return
# responses that trigger both inbound (REQUEST) rules and outbound (RESPONSE) rules
# simultaneously, so that anomaly scores can be correlated in the logging phase.
#
# The server should return responses that combine:
# - Inbound triggers: XSS payloads, SQL injection attempts, etc. in the request
# - Outbound triggers: Error leakages, data disclosures, etc. in the response
#
# The correlation rules will then combine these scores and generate logging events
# in phase 5 based on the total anomaly scores.
#
# For example:
# - Request with SQL injection payload (triggers REQUEST-942 rules)
# - Response with SQL error message (triggers RESPONSE-951 rules)
# - Correlation rule reports combined scores in phase 5
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that trigger both inbound and outbound rules
correlation_endpoints = {
    "980170": "/correlation-test",  # Should trigger both inbound and outbound rules for correlation reporting
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

@pytest.mark.parametrize("rule_id,endpoint", list(correlation_endpoints.items()))
def test_correlation_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for correlation rules

    NOTE: This test requires a specially configured server that returns
    responses triggering both inbound and outbound anomaly rules in the same
    transaction. The server must be set up to:

    1. Accept requests with attack payloads (inbound triggers like SQLi, XSS)
    2. Return responses with leakages (outbound triggers like SQL errors, PHP errors)

    Example scenario:
    - Request URL: /correlation-test?id=1' UNION SELECT * FROM users --
      (This triggers REQUEST-942 SQL injection rules)
    - Response body: "You have an error in your SQL syntax; check the manual..."
      (This triggers RESPONSE-951 SQL leakage rules)

    The correlation rules in phase 5 will then combine the inbound and outbound
    anomaly scores and generate a comprehensive report with rule 980170.

    The log should contain detailed anomaly score reporting showing:
    - Inbound scores from request analysis
    - Outbound scores from response analysis
    - Combined totals and per-PL breakdowns
    - Specific attack type scores (SQLI, XSS, etc.)

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to trigger both inbound and outbound rules for correlation")

    # This would send attack-like request to endpoint that returns leakage response
    # The request itself should trigger inbound rules, response should trigger outbound rules
    try:
        # Example: request with SQL injection that triggers REQUEST-942 rules
        response = requests.get(f"http://localhost{endpoint}?id=1' UNION SELECT", timeout=10)
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

    # For correlation rules, we expect comprehensive anomaly score reporting
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered. Found rules: {rule_ids_in_log}"

    # Additional verification could check that both inbound and outbound scores are reported
    # and that the correlation provides meaningful combined analysis

if __name__ == "__main__":
    pytest.main([__file__])