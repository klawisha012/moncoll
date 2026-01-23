#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-954-DATA-LEAKAGES-IIS rules (954xxx)
#
# These rules check response bodies and status for IIS-related data leakages:
# - 954100: Disclosure of IIS install location (regex for c:\inetpub)
# - 954110: Application Availability Error (various IIS/SQL timeout/connection errors)
# - 954120: IIS Information Leakage (checks against iis-errors.data - IIS error page titles)
# - 954130: IIS Information Leakage (non-404 status + "Server Error in Application")
#
# To properly test these RESPONSE rules, a test server must be configured to return
# specific responses containing IIS error messages or path disclosures.
#
# For 954100: Server should return responses containing paths like:
#   - c:\inetpub\wwwroot\default.aspx
#
# For 954110: Server should return responses with timeout/connection errors like:
#   - "Microsoft OLE DB Provider for SQL Server error '80004005' Timeout expired"
#   - "cannot connect to the server: timed out"
#
# For 954120: Server should return responses containing IIS error titles like:
#   - "<title>404 - File or directory not found.</title>"
#   - "<title>500 - Internal server error.</title>"
#   - "<title>403 - Forbidden: Access is denied.</title>"
#
# For 954130: Server should return non-404 responses with "Server Error in Application"
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that return IIS leakage responses
iis_leakage_endpoints = {
    "954100": "/iis-path-disclosure",  # Should return c:\inetpub path
    "954110": "/iis-timeout-error",    # Should return SQL timeout errors
    "954120": "/iis-error-page",      # Should return IIS error page HTML
    "954130": "/iis-app-error",       # Should return non-404 with "Server Error in Application"
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

@pytest.mark.parametrize("rule_id,endpoint", list(iis_leakage_endpoints.items()))
def test_iis_leakage_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for IIS leakage rules

    NOTE: This test requires a specially configured server that returns
    responses containing IIS error messages or path disclosures. The server
    must be set up to return responses with content like:

    For IIS path disclosure:
    - Error messages revealing: c:\inetpub\wwwroot\app\config.aspx

    For SQL timeout errors:
    - OLE DB errors: Microsoft OLE DB Provider for SQL Server (0x80040e31) Timeout expired
    - Connection errors: cannot connect to the server: timed out

    For IIS error pages:
    - Standard IIS error HTML with titles like:
      <html><head><title>500 - Internal server error.</title></head><body>...</body></html>

    For application errors:
    - ASP.NET error pages with "Server Error in '/' Application" (but not 404 status)

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to return IIS leakage responses")

    # This would send request to endpoint that returns IIS leakage response
    try:
        response = requests.get(f"http://localhost{endpoint}", timeout=10)
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