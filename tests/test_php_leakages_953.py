#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-953-DATA-LEAKAGES-PHP rules (953xxx)
#
# These rules check response bodies for PHP-related data leakages:
# - 953100: PHP Error Message Leakage (checks against php-errors.data)
# - 953110: PHP source code leakage (regex for PHP functions like ftp_get, session_start, etc.)
# - 953120: PHP source code leakage (PHP open tags like <?php, <?=)
# - 953101: PHP Information Leakage (PL2, checks against php-errors-pl2.data)
#
# To properly test these RESPONSE rules, a test server must be configured to return
# specific responses containing PHP error messages or PHP source code.
#
# For 953100/953101: Server should return responses containing PHP errors like:
#   - "Fatal error: ..."
#   - "Warning: ..."
#   - "Parse error: ..."
#   - "Notice: ..."
#
# For 953110/953120: Server should return responses containing PHP source code like:
#   - PHP functions: session_start(), ftp_get(), file_get_contents()
#   - PHP tags: <?php echo "hello"; ?>
#   - Variable usage: $_GET, $_POST, $_SESSION
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that return PHP leakage responses
php_leakage_endpoints = {
    "953100": "/php-error-basic",  # Should return basic PHP errors
    "953110": "/php-source-functions",  # Should return PHP source with functions
    "953120": "/php-source-tags",  # Should return PHP source with open tags
    "953101": "/php-error-pl2",   # Should return PL2 PHP errors
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

@pytest.mark.parametrize("rule_id,endpoint", list(php_leakage_endpoints.items()))
def test_php_leakage_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for PHP leakage rules

    NOTE: This test requires a specially configured server that returns
    responses containing PHP errors or source code. The server must be
    set up to return responses with content like:

    For PHP errors:
    - Fatal error: Call to undefined function foo() in /var/www/html/index.php on line 5
    - Warning: include(/etc/passwd): failed to open stream: Permission denied
    - Parse error: syntax error, unexpected '}' in /var/www/html/script.php on line 10

    For PHP source code:
    - <?php session_start(); $user = $_GET['user']; echo "Welcome $user"; ?>
    - Function calls: file_get_contents('/etc/passwd'), system('ls -la')
    - Variable usage: $_POST['password'], $_SESSION['logged_in']

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to return PHP leakage responses")

    # This would send request to endpoint that returns PHP leakage response
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