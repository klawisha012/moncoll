#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-952-DATA-LEAKAGES-JAVA rules (952xxx)
#
# These rules check response bodies for Java-related data leakages:
# - 952100: Java Source Code Leakage (checks against java-code-leakages.data)
# - 952110: Java Errors (checks against java-errors.data)
#
# To properly test these RESPONSE rules, a test server must be configured to return
# specific responses containing Java source code fragments or Java error messages/stack traces.
#
# For 952100: Server should return responses containing patterns like:
#   - <jsp:...
#   - javax.servlet...
#   - response.write...
#   - server.createobject...
#
# For 952110: Server should return responses containing Java stack traces like:
#   - java.lang.NullPointerException
#   - at java.lang.Thread.run
#   - at org.apache.catalina...
#   - at org.apache.tomcat...
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that return Java leakage responses
java_leakage_endpoints = {
    "952100": "/java-source-leak",  # Should return Java source code fragments
    "952110": "/java-error",        # Should return Java error messages/stack traces
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

@pytest.mark.parametrize("rule_id,endpoint", list(java_leakage_endpoints.items()))
def test_java_leakage_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for Java leakage rules

    NOTE: This test requires a specially configured server that returns
    responses containing Java source code or error messages. The server
    must be set up to return responses with content like:

    For Java source leaks:
    - JSP tags: <jsp:directive.include file="..." />
    - Java imports: import javax.servlet.*;
    - Server objects: server.createobject("ADODB.Connection")

    For Java errors:
    - Stack traces: java.lang.NullPointerException at com.example.MyClass.method(MyClass.java:42)
    - Framework errors: at org.apache.catalina.core.StandardWrapperValve.invoke
    - Exception messages: java.rmi.ServerException: RemoteException occurred

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to return Java leakage responses")

    # This would send request to endpoint that returns Java leakage response
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