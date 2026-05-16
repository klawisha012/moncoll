#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-951-DATA-LEAKAGES-SQL rules (951xxx)
#
# These rules check response bodies for SQL error leakages from various databases:
# - 951110: Microsoft Access SQL errors
# - 951120: Oracle SQL errors
# - 951130: DB2 SQL errors
# - 951140: EMC SQL errors
# - 951150: firebird SQL errors
# - 951160: Frontbase SQL errors
# - 951170: hsqldb SQL errors
# - 951180: informix SQL errors
# - 951190: ingres SQL errors
# - 951200: interbase SQL errors
# - 951210: maxDB SQL errors
# - 951220: mssql SQL errors
# - 951230: mysql SQL errors
# - 951240: postgres SQL errors
# - 951250: sqlite SQL errors
# - 951260: Sybase SQL errors
#
# To properly test these RESPONSE rules, a test server must be configured to return
# specific responses containing SQL error messages that match the patterns in sql-errors.data
# and the specific regex patterns for each database type.
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that return SQL error responses
sql_leakage_endpoints = {
    "951110": "/access-error",  # Should return "JET Database Engine" or similar
    "951120": "/oracle-error",  # Should return "ORA-01234" or similar
    "951130": "/db2-error",     # Should return "DB2 SQL error:" or similar
    "951140": "/emc-error",     # Should return "[DM_QUERY_E_SYNTAX]" or similar
    "951150": "/firebird-error", # Should return "Dynamic SQL Error" or similar
    "951160": "/frontbase-error", # Should return "Exception condition 123. Transaction rollback." or similar
    "951170": "/hsqldb-error",  # Should return "org.hsqldb.jdbc" or similar
    "951180": "/informix-error", # Should return "An illegal character has been found" or similar
    "951190": "/ingres-error",  # Should return "Warning.*ingres_" or similar
    "951200": "/interbase-error", # Should return "<b>Warning</b>: ibase_" or similar
    "951210": "/maxdb-error",   # Should return "SQL error.*POS[0-9]+.*" or similar
    "951220": "/mssql-error",   # Should return "Microsoft OLE DB Provider for SQL Server" or similar
    "951230": "/mysql-error",   # Should return "You have an error in your SQL syntax" or similar
    "951240": "/postgres-error", # Should return "PostgreSQL query failed:" or similar
    "951250": "/sqlite-error",  # Should return "Warning.*sqlite_" or similar
    "951260": "/sybase-error",  # Should return "Sybase message:" or similar
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

@pytest.mark.parametrize("rule_id,endpoint", list(sql_leakage_endpoints.items()))
def test_sql_leakage_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for SQL leakage rules

    NOTE: This test requires a specially configured server that returns
    responses containing SQL error messages that match the specific patterns
    for each database type. The server must be set up to return responses
    with error messages like:

    - MySQL: "You have an error in your SQL syntax; check the manual..."
    - PostgreSQL: "PostgreSQL query failed: ERROR: syntax error at or near"
    - MSSQL: "Microsoft OLE DB Provider for SQL Server error '80040e14'"
    - Oracle: "ORA-00936: missing expression"
    - etc.

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to return SQL error responses")

    # This would send request to endpoint that returns SQL error response
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