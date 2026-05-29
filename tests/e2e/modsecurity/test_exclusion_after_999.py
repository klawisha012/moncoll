#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-999-EXCLUSION-RULES-AFTER-CRS rules (999xxx)
#
# This file (RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf) is used for local exclusions
# and modifications to CRS rules after the main rule set has been loaded.
#
# Since this is an exclusion file, there are no actual rules with IDs 999xxx to test.
# Instead, this file contains examples of how to:
# - Remove rules by ID: SecRuleRemoveById 999xxx
# - Remove rules by tag: SecRuleRemoveByTag "tag-name"
# - Update rule targets: SecRuleUpdateTargetByTag "tag" "!ARGS:param"
# - Update rule actions: SecRuleUpdateActionById 999xxx "action"
#
# To properly test RESPONSE-999 functionality, you would need to:
# 1. Create actual exclusion rules in the RESPONSE-999 file
# 2. Test that the exclusions work as expected (rules are disabled/modified)
#
# For example:
# - Add SecRuleRemoveById 950130 to disable directory listing detection
# - Test that directory listing responses no longer trigger alerts
#
# Current implementation: placeholder with comments

# Test data placeholders - these would test exclusion functionality
exclusion_test_endpoints = {
    "exclusion_test": "/test-exclusion",  # Would test that certain rules are properly excluded
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

@pytest.mark.parametrize("test_name,endpoint", list(exclusion_test_endpoints.items()))
def test_exclusion_after_crs(setup_teardown, test_name, endpoint):
    """Placeholder test for RESPONSE-999 exclusion rules

    NOTE: This test requires actual exclusion rules to be configured in
    RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf file. The test would verify
    that exclusions work correctly.

    Example test scenario:
    1. Configure exclusion: SecRuleRemoveById 950130 (disable directory listing detection)
    2. Send request that would normally trigger 950130
    3. Verify that the rule is NOT triggered due to exclusion

    Or test action modifications:
    1. Configure: SecRuleUpdateActionById 959100 "t:none,deny,status:404"
    2. Trigger blocking condition
    3. Verify response returns 404 instead of default 403

    Currently this test is a placeholder as it requires custom exclusion configuration.
    """
    pytest.skip("Placeholder test - requires actual exclusion rules configured in RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf")

    # This would test that exclusions work properly
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

    if log_content:
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

        # For exclusion tests, we would verify that excluded rules are NOT triggered
        # and that modified actions work as expected

    # Placeholder assertion
    assert True  # Would be replaced with actual exclusion verification

if __name__ == "__main__":
    pytest.main([__file__])