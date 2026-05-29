#!/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Placeholder test file for RESPONSE-955-WEB-SHELLS rules (955xxx)
#
# These rules check response bodies for web shell signatures and backdoors:
# - 955100: Web shell detected (checks against web-shells-php.data)
# - 955110: r57 web shell
# - 955120: WSO web shell
# - 955130: b4tm4n web shell
# - 955140: Mini Shell web shell
# - 955150: Ashiyane web shell
# - 955160: Symlink_Sa web shell
# - 955170: CasuS web shell
# - 955180: GRP WebShell
# - 955190: NGHshell web shell
# - 955200: SimAttacker web shell
# - 955210: Unknown web shell (Artyum)
# - 955220: lama's'hell web shell
# - 955230: lostDC web shell
# - 955240: Unknown web shell (PHP Web Shell)
# - 955250: Unknown web shell (Input command)
# - 955260: Ru24PostWebShell web shell
# - 955270: s72 Shell web shell
# - 955280: PhpSpy web shell
# - 955290: g00nshell web shell
# - 955300: PuNkHoLic shell web shell
# - 955310: azrail web shell
# - 955320: SmEvK_PaThAn Shell web shell
# - 955330: Shell I web shell
# - 955340: b374k m1n1 web shell
# - 955350: webadmin.php file manager (PL2)
#
# To properly test these RESPONSE rules, a test server must be configured to return
# specific responses containing web shell HTML output that matches the patterns.
#
# The server must return responses with HTML content like:
# - "<title>r57 Shell Version 1.3.0</title>" for r57
# - "<html><head><meta http-equiv='Content-Type' content='text/html; charset=Windows-1251'><title>WSO 2.5</title>" for WSO
# - "<title>=[ 1n73ct10n privat shell ]=</title>" for web-shells-php.data patterns
# - etc.
#
# Current implementation: placeholder with comments

# Test data placeholders - these would be URLs/paths that return web shell responses
web_shell_endpoints = {
    "955100": "/web-shell-php",      # Should return content from web-shells-php.data
    "955110": "/r57-shell",         # Should return r57 shell HTML
    "955120": "/wso-shell",         # Should return WSO shell HTML
    "955130": "/b4tm4n-shell",      # Should return b4tm4n shell HTML
    "955140": "/mini-shell",        # Should return Mini Shell HTML
    "955150": "/ashiyane-shell",    # Should return Ashiyane shell HTML
    "955160": "/symlink-sa-shell",  # Should return Symlink_Sa shell HTML
    "955170": "/casus-shell",       # Should return CasuS shell HTML
    "955180": "/grp-shell",         # Should return GRP WebShell HTML
    "955190": "/nghshell",          # Should return NGHshell HTML
    "955200": "/simattacker-shell", # Should return SimAttacker shell HTML
    "955210": "/artyum-shell",      # Should return Artyum shell HTML
    "955220": "/lamas-hell",        # Should return lama's'hell HTML
    "955230": "/lostdc-shell",      # Should return lostDC shell HTML
    "955240": "/php-web-shell",     # Should return PHP Web Shell HTML
    "955250": "/input-command-shell", # Should return Input command shell HTML
    "955260": "/ru24-shell",        # Should return Ru24PostWebShell HTML
    "955270": "/s72-shell",         # Should return s72 Shell HTML
    "955280": "/phpspy-shell",      # Should return PhpSpy shell HTML
    "955290": "/g00nshell",         # Should return g00nshell HTML
    "955300": "/punkholic-shell",   # Should return PuNkHoLic shell HTML
    "955310": "/azrail-shell",      # Should return azrail shell HTML
    "955320": "/smevk-shell",       # Should return SmEvK_PaThAn Shell HTML
    "955330": "/shell-i",           # Should return Shell I HTML
    "955340": "/b374k-shell",       # Should return b374k m1n1 shell HTML
    "955350": "/webadmin-shell",    # Should return webadmin.php HTML (PL2)
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

@pytest.mark.parametrize("rule_id,endpoint", list(web_shell_endpoints.items()))
def test_web_shell_rule_trigger(setup_teardown, rule_id, endpoint):
    """Placeholder test for web shell rules

    NOTE: This test requires a specially configured server that returns
    responses containing web shell HTML output that matches the specific
    patterns for each shell type. The server must be set up to return
    responses with HTML like:

    For r57 shell:
    - <title>r57 Shell Version 2.0</title>

    For WSO shell:
    - <html><head><meta http-equiv='Content-Type' content='text/html; charset=Windows-1251'><title>WSO 4.2.3</title>

    For PHP web shells (from web-shells-php.data):
    - <title>=[ 1n73ct10n privat shell ]=</title>
    - <title>--==[[ Andela Yuwono Priv8 Shell ]]==--</title>
    - <title>Ani-Shell | India</title>

    For b374k:
    - <title>:: b374k 3.2 ::</title>

    And many other specific HTML patterns for each web shell type.

    Currently this test will likely fail as it sends normal requests.
    """
    pytest.skip("Placeholder test - requires server configured to return web shell HTML responses")

    # This would send request to endpoint that returns web shell response
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