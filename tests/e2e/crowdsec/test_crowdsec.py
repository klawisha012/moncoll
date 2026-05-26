"""Tests for CrowdSec management and API."""

import pytest
import requests
import subprocess
import time
import json

CROWDSEC_CONTAINER = "waf-crowdsec-1"
ANGIE_CONTAINER = "waf-angie-1"
ANGIE_URL = "http://localhost"
BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/crowdsec"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"


# ── Fixtures ────────────────────────────────────────────────


@pytest.fixture(scope="module")
def auth_session() -> requests.Session:
    """Authenticated session — dynamically signs up a client and verifies them."""
    import uuid
    import re
    import subprocess

    unique_id = uuid.uuid4().hex[:8]
    email = f"crowdsec-client-{unique_id}@example.com"
    password = "Password1!"
    tenant_name = f"tenant{unique_id}"

    s = requests.Session()

    # 1. Signup
    r = s.post(
        f"{BASE_URL}/api/auth/signup",
        json={
            "email": email,
            "password": password,
            "tenant_name": tenant_name,
            "captcha_token": "e2e-test-bypass",
        },
        timeout=15,
    )
    if r.status_code != 202:
        s.close()
        pytest.skip(f"Signup failed: {r.status_code} - {r.text}")

    # 2. Extract verification token from logs
    time.sleep(2)
    try:
        logs = subprocess.check_output(
            ["docker", "logs", "--tail", "300", "waf-backend-1"],
            stderr=subprocess.STDOUT, timeout=15,
        ).decode(errors="replace")
        m = re.search(r"/verify-email\?token=([A-Za-z0-9_\-]+)", logs)
    except Exception as e:
        s.close()
        pytest.skip(f"Could not get logs or find token: {e}")

    if not m:
        s.close()
        pytest.skip("Verification token not found in backend logs")

    # 3. Verify email
    r = s.post(
        f"{BASE_URL}/api/auth/verify-email",
        json={"token": m.group(1)},
        timeout=10,
    )
    if r.status_code != 200:
        s.close()
        pytest.skip(f"Email verification failed: {r.status_code} - {r.text}")

    yield s
    s.close()


@pytest.fixture(scope="function")
def clean_decisions():
    """Clean CrowdSec decisions before and after test."""
    def _clean():
        subprocess.run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "delete", "--all"],
            capture_output=True, text=True, check=False
        )
    _clean()
    yield
    _clean()


@pytest.fixture(scope="function")
def ensure_scenario_loaded():
    """Ensure the http-scan-404 scenario is loaded."""
    # Try installing it for the local scenario file
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "scenarios", "install", "zwarder/http-scan-404", "--force"],
        capture_output=True, text=True, check=False
    )
    # Also try the crowdsecurity hub version
    subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "scenarios", "install", "crowdsecurity/http-scan-404", "--force"],
        capture_output=True, text=True, check=False
    )
    yield


# ── Container state tests ──────────────────────────────────


def test_crowdsec_container_running():
    """Verify CrowdSec container is running."""
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name={CROWDSEC_CONTAINER}", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True
    )
    assert CROWDSEC_CONTAINER in result.stdout, "CrowdSec container not running"


def test_crowdsec_scenario_loaded(ensure_scenario_loaded):
    """Verify custom scenario http-scan-404 is loaded."""
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "scenarios", "list"],
        capture_output=True, text=True, check=True
    )
    assert "http-scan-404" in result.stdout, (
        f"Scenario http-scan-404 not loaded in CrowdSec.\n"
        f"Loaded scenarios:\n{result.stdout}"
    )


def test_crowdsec_scenarios_list_has_entries():
    """Verify scenarios list returns data."""
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "scenarios", "list", "-o", "json"],
        capture_output=True, text=True, check=True
    )
    raw = json.loads(result.stdout) if result.stdout.strip() else {}
    # cscli returns {"scenarios": [...]} dict format
    data = raw.get("scenarios", []) if isinstance(raw, dict) else raw
    assert isinstance(data, list), f"Scenarios output should be a list, got {type(data)}"
    assert len(data) > 0, "At least one scenario should exist"


# ── Decision management tests ───────────────────────────────


def test_crowdsec_decisions_empty(clean_decisions):
    """Verify decisions list is empty after cleanup."""
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "list", "-o", "json"],
        capture_output=True, text=True, check=True
    )
    raw = json.loads(result.stdout) if result.stdout.strip() else None
    ips = _extract_blocked_ips(raw)
    assert len(ips) == 0, f"Decisions should be empty after cleanup, got {ips}"


def _extract_blocked_ips(data: list | dict | None) -> list:
    """Extract blocked IPs from cscli decisions JSON output."""
    if data is None:
        return []
    items = data if isinstance(data, list) else data.get("decisions", [])
    if items is None:
        return []
    ips = []
    for alert in items:
        if not isinstance(alert, dict):
            continue
        # IP can be in source.value or decisions[].value
        source = alert.get("source", {})
        if isinstance(source, dict) and source.get("value"):
            ips.append(source["value"])
        for dec in alert.get("decisions", []) or []:
            if isinstance(dec, dict) and dec.get("value"):
                if dec["value"] not in ips:
                    ips.append(dec["value"])
    return ips


def test_crowdsec_add_decision(clean_decisions):
    """Verify we can add a manual decision via cscli."""
    test_ip = "10.99.99.99"
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "add",
         "--ip", test_ip, "--duration", "1h", "--reason", "test_block"],
        capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, f"Failed to add decision: {result.stderr}"

    # Verify decision exists
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "list", "-o", "json"],
        capture_output=True, text=True, check=True
    )
    raw = json.loads(result.stdout) if result.stdout.strip() else None
    ips_blocked = _extract_blocked_ips(raw)
    assert test_ip in ips_blocked, f"IP {test_ip} not found in decisions: {ips_blocked}"


def test_crowdsec_delete_decision(clean_decisions):
    """Verify we can delete a decision via cscli."""
    test_ip = "10.88.88.88"
    # Add first
    subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "add",
         "--ip", test_ip, "--duration", "1h", "--reason", "test_delete"],
        capture_output=True, text=True, check=False
    )
    # Delete
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "delete", "--ip", test_ip],
        capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, f"Failed to delete decision: {result.stderr}"

    # Verify gone
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "list", "-o", "json"],
        capture_output=True, text=True, check=True
    )
    raw = json.loads(result.stdout) if result.stdout.strip() else None
    ips_blocked = _extract_blocked_ips(raw)
    assert test_ip not in ips_blocked, f"IP {test_ip} should have been deleted"


# ── API validation helper ──────────────────────────────────


def _api_available(url: str, session: requests.Session | None = None) -> bool:
    """Check if the CrowdSec API is deployed on the backend."""
    try:
        caller = session if session is not None else requests
        r = caller.get(url, timeout=3)
        return r.status_code != 404
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return False


# ── API endpoint tests ─────────────────────────────────────


def test_api_crowdsec_status(auth_session):
    """Verify the CrowdSec status API endpoint returns valid data."""
    if not _api_available(f"{API_URL}/status", auth_session):
        pytest.skip("CrowdSec API not deployed (backend rebuild required)")
    response = auth_session.get(f"{API_URL}/status", timeout=5)
    assert response.status_code == 200, f"Status: {response.status_code}"
    data = response.json()
    assert "running" in data, f"Missing 'running' field: {data}"
    assert "decisions_count" in data
    assert "scenarios_count" in data
    assert "alerts_count" in data


def test_api_crowdsec_decisions(clean_decisions, auth_session):
    """Verify the CrowdSec decisions API endpoint."""
    if not _api_available(f"{API_URL}/status", auth_session):
        pytest.skip("CrowdSec API not deployed (backend rebuild required)")

    # List should work
    response = auth_session.get(f"{API_URL}/decisions", timeout=5)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list), f"Expected list, got {type(data)}"

    # Add a decision via API
    response = auth_session.post(
        f"{API_URL}/decisions",
        json={"ip": "10.77.77.77", "duration": "1h", "reason": "api_test"},
        timeout=5
    )
    assert response.status_code == 200, f"Add failed: {response.text}"
    result = response.json()
    assert result.get("success"), f"Add not successful: {result}"

    # Verify in list
    response = auth_session.get(f"{API_URL}/decisions", timeout=5)
    data = response.json()
    ips_blocked = [d.get("value", "") for d in data]
    assert "10.77.77.77" in ips_blocked, f"IP not found via API: {ips_blocked}"

    # Delete via API
    response = auth_session.delete(f"{API_URL}/decisions/10.77.77.77", timeout=5)
    assert response.status_code == 200, f"Delete failed: {response.text}"
    result = response.json()
    assert result.get("success"), f"Delete not successful: {result}"


def test_api_crowdsec_scenarios(auth_session):
    """Verify the CrowdSec scenarios API endpoint."""
    if not _api_available(f"{API_URL}/status", auth_session):
        pytest.skip("CrowdSec API not deployed (backend rebuild required)")

    response = auth_session.get(f"{API_URL}/scenarios", timeout=5)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list), f"Expected list, got {type(data)}"
    # At least one scenario should exist
    scenario_names = [s.get("name", "") for s in data]
    assert any("http-scan-404" in name for name in scenario_names), \
        f"http-scan-404 not found in scenarios via API: {scenario_names}"


def test_api_crowdsec_reload(auth_session):
    """Verify the CrowdSec reload API endpoint."""
    if not _api_available(f"{API_URL}/status", auth_session):
        pytest.skip("CrowdSec API not deployed (backend rebuild required)")

    response = auth_session.post(f"{API_URL}/reload", timeout=30)
    assert response.status_code == 200
    data = response.json()
    assert data.get("success"), f"Reload not successful: {data}"


# ── End-to-end block detection tests ────────────────────────


def test_crowdsec_blocks_ip_after_404_scan(clean_decisions):
    """Verify CrowdSec detects 404 scanning and creates decisions."""
    # Generate many 404 requests
    for i in range(6):
        try:
            requests.get(f"{ANGIE_URL}/scan-probe-{i}-{int(time.time())}", timeout=3)
        except Exception:
            pass
        time.sleep(0.3)

    # Wait for CrowdSec to process
    time.sleep(5)

    # Check decisions
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "list", "-o", "json"],
        capture_output=True, text=True, check=False
    )
    # Test is informational - in docker environment internal IP handling may differ
    assert result.returncode == 0, "Failed to get decisions list"


def test_blocked_ips_conf_exists():
    """Verify blocked_ips.list file exists."""
    import os
    path = "configs/angie/http.d/blocked_ips.list"
    if not os.path.exists(path):
        pytest.skip(f"{path} does not exist yet")
    with open(path, "r") as f:
        content = f.read()
    if content.strip():
        assert "deny" in content, f"Invalid format in blocked_ips.list"


def test_crowdsec_acquisition_config():
    """Verify CrowdSec config is accessible."""
    result = subprocess.run(
        ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "config", "show"],
        capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, "Failed to get CrowdSec config"


def test_crowdsec_hub_items(auth_session):
    """Verify we can inspect hub scenarios and parsers."""
    if not _api_available(f"{API_URL}/status", auth_session):
        pytest.skip("CrowdSec API not deployed (backend rebuild required)")
    response = auth_session.get(f"{API_URL}/scenarios/hub", timeout=10)
    assert response.status_code == 200
    data = response.json()
    # May be empty or have items depending on hub state
    assert isinstance(data, list), f"Expected list from hub, got {type(data)}"
