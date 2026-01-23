#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload
sqli_payloads = {
    "942100": "' UNION SELECT * FROM users; --",
    "942101": "' UNION SELECT * FROM users; --",
    "942120": "!=1",
    "942130": "1=1",
    "942131": "1!=2",
    "942140": "information_schema",
    "942150": "json_extract('{}', ')",
    "942151": "SELECT SLEEP(5)",
    "942152": "SELECT SLEEP(5)",
    "942160": "sleep(5)",
    "942170": "SELECT benchmark(1,1)",
    "942180": "' or 1=1 --",
    "942190": "exec master..sysdatabases",
    "942200": "' --",
    "942210": "and 1=1",
    "942220": "0000012345",
    "942230": "case when 1=1 then 1 else 0 end",
    "942240": "alter table t1 charset set utf8",
    "942250": "match password against ('*')",
    "942251": "having 1=1",
    "942260": "like '",
    "942270": "union select from",
    "942280": "select pg_sleep(5)",
    "942290": "$ne",
    "942300": "case when 1=1 then 1 end",
    "942310": "(select 1)",
    "942320": "create function f()",
    "942321": "create function f()",
    "942330": "' or '1'",
    "942340": "' or 1=1 --",
    "942350": "create function f() returns int",
    "942360": "select from users",
    "942361": "alter table",
    "942362": "create table",
    "942370": "' or '1",
    "942380": "having 1=1",
    "942390": "or 1=1",
    "942400": "and 1=1",
    "942410": "char(65)",
    "942420": "!!!@#$%^&*()",
    "942421": "!!!@#$",
    "942430": "!!!@#$%^&*()",
    "942431": "!!!@#$%^&",
    "942432": "!!!@#",
    "942440": "--",
    "942450": "0x4142",
    "942460": "!!!!",
    "942470": "autonomous_transaction",
    "942480": "sys_context",
    "942490": "' or '1",
    "942500": "/*!*/",
    "942510": "`if`",
    "942511": "'if'",
    "942520": "' like",
    "942521": "' and",
    "942522": "\\' and",
    "942530": "';",
    "942540": "';",
    "942550": '{"key": {"$gt": 1}}',
    "942560": "1.e(",
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

@pytest.mark.parametrize("rule_id,payload", list(sqli_payloads.items()))
def test_sqli_rule_trigger(setup_teardown, rule_id, payload):
    """Test that each SQLi rule is triggered by its payload"""

    # Send GET request with SQL injection payload
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