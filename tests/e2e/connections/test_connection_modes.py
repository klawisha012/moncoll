"""End-to-end Playwright test for the rewritten New Connection flow.

Covers all three source types:

  1. ``nginx_config``     — deploy from an existing nginx .conf with includes
  2. ``static_generate``  — generate config from index.html + domains
  3. ``container``        — reverse-proxy to a container host:port

The test drives the real UI (login, modal, submit), then verifies that
the backend wrote the expected nginx fragment AND that Angie serves the
expected response when the corresponding Host header is set.
"""
from __future__ import annotations

import os
import subprocess
import time
import uuid

import pytest
import requests
from playwright.sync_api import Page, expect, sync_playwright

FRONTEND_URL = os.environ.get("E2E_FRONTEND_URL", "http://localhost:3000")
BACKEND_URL = os.environ.get("E2E_BACKEND_URL", "http://localhost:8000")
ANGIE_URL = os.environ.get("E2E_ANGIE_URL", "http://localhost:80")
ADMIN_USER = os.environ.get("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("E2E_ADMIN_PASS", "admin")

RUN_ID = uuid.uuid4().hex[:6]


def _api_login() -> requests.Session:
    s = requests.Session()
    r = s.post(
        f"{BACKEND_URL}/api/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=10,
    )
    r.raise_for_status()
    return s


def _api_delete_conn_by_name(s: requests.Session, name: str) -> None:
    r = s.get(f"{BACKEND_URL}/api/connections/", timeout=10)
    r.raise_for_status()
    for conn in r.json():
        if conn["name"] == name:
            s.delete(f"{BACKEND_URL}/api/connections/{conn['id']}", timeout=10)


def _api_reload_angie(s: requests.Session) -> None:
    r = s.post(f"{BACKEND_URL}/api/angie/reload", timeout=30)
    r.raise_for_status()


def _angie_get(host: str, path: str = "/") -> requests.Response:
    return requests.get(f"{ANGIE_URL}{path}", headers={"Host": host}, timeout=10)


def _read_generated_config(conn_id: int) -> str:
    out = subprocess.run(
        ["docker", "exec", "waf-angie-1", "cat",
         f"/etc/angie/http.d/conn_{conn_id}/{conn_id}.conf"],
        capture_output=True, text=True, check=False,
    )
    return out.stdout or ""


def _ui_login(page: Page) -> None:
    page.goto(f"{FRONTEND_URL}/")
    page.wait_for_load_state("networkidle")
    # Login form shows only when not authenticated.
    if page.locator("input[type='password']").count() > 0:
        page.locator("input[type='text']").first.fill(ADMIN_USER)
        page.locator("input[type='password']").first.fill(ADMIN_PASS)
        page.locator("button[type='submit']").first.click()
        page.wait_for_load_state("networkidle")


def _ui_open_new_connection(page: Page) -> None:
    page.goto(f"{FRONTEND_URL}/connections")
    page.wait_for_load_state("networkidle")
    page.get_by_role("button", name="Add Connection").click()


def _ui_submit(page: Page) -> None:
    page.get_by_test_id("conn-submit").click()
    page.wait_for_selector("text=/successfully/i", timeout=10_000)


def _wait_for_response(host: str, expected_substr: str, path: str = "/", timeout_s: float = 15.0):
    deadline = time.time() + timeout_s
    last_text = ""
    last_status = None
    while time.time() < deadline:
        try:
            r = _angie_get(host, path)
            last_text = r.text
            last_status = r.status_code
            if expected_substr in last_text and r.status_code == 200:
                return r
        except requests.RequestException:
            pass
        time.sleep(1.0)
    raise AssertionError(
        f"After {timeout_s}s, Angie response for Host={host!r} path={path!r} did not contain "
        f"{expected_substr!r}. Last status={last_status}, body[:300]={last_text[:300]!r}"
    )


@pytest.fixture(scope="module")
def browser_context():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        yield ctx
        ctx.close()
        browser.close()


@pytest.fixture
def page(browser_context):
    pg = browser_context.new_page()
    _ui_login(pg)
    yield pg
    pg.close()


@pytest.fixture
def api_session():
    s = _api_login()
    yield s


def test_mode_nginx_config(page: Page, api_session: requests.Session):
    name = f"e2e-nginx-{RUN_ID}"
    _api_delete_conn_by_name(api_session, name)

    _ui_open_new_connection(page)
    page.get_by_test_id("source-type-nginx_config").click()
    page.get_by_test_id("conn-name").fill(name)
    page.get_by_test_id("conn-domains").fill("test1.example")
    page.get_by_test_id("conn-nginx-config-path").fill(
        "/app/site-templates/examples/test_mode1/nginx.conf"
    )
    _ui_submit(page)

    expect(page.get_by_text(name)).to_be_visible()

    rows = api_session.get(f"{BACKEND_URL}/api/connections/").json()
    conn = next(c for c in rows if c["name"] == name)
    assert conn["source_type"] == "nginx_config"

    cfg = _read_generated_config(conn["id"])
    assert "## Source: nginx_config" in cfg, cfg
    assert "/probe" in cfg and "mode1-include-ok" in cfg, cfg

    _api_reload_angie(api_session)
    r = _wait_for_response("test1.example", "mode1-include-ok", path="/probe")
    assert "mode1-include-ok" in r.text


def test_mode_static_generate(page: Page, api_session: requests.Session):
    name = f"e2e-static-{RUN_ID}"
    _api_delete_conn_by_name(api_session, name)

    _ui_open_new_connection(page)
    page.get_by_test_id("source-type-static_generate").click()
    page.get_by_test_id("conn-name").fill(name)
    page.get_by_test_id("conn-domains").fill("test2.example")
    page.get_by_test_id("conn-static-dir").fill("examples/test_mode2")
    _ui_submit(page)

    expect(page.get_by_text(name)).to_be_visible()

    rows = api_session.get(f"{BACKEND_URL}/api/connections/").json()
    conn = next(c for c in rows if c["name"] == name)
    assert conn["source_type"] == "static_generate"

    cfg = _read_generated_config(conn["id"])
    assert "## Source: static_generate" in cfg
    assert "try_files $uri $uri/ =404" in cfg

    _api_reload_angie(api_session)
    r = _wait_for_response("test2.example", "mode2-static-ok")
    assert "mode2-static-ok" in r.text


def test_mode_container(page: Page, api_session: requests.Session):
    name = f"e2e-container-{RUN_ID}"
    _api_delete_conn_by_name(api_session, name)

    _ui_open_new_connection(page)
    page.get_by_test_id("source-type-container").click()
    page.get_by_test_id("conn-name").fill(name)
    page.get_by_test_id("conn-domains").fill("test3.example")
    page.get_by_test_id("conn-backend-url").fill("frontend:3000")
    _ui_submit(page)

    expect(page.get_by_text(name)).to_be_visible()

    rows = api_session.get(f"{BACKEND_URL}/api/connections/").json()
    conn = next(c for c in rows if c["name"] == name)
    assert conn["source_type"] == "container"

    cfg = _read_generated_config(conn["id"])
    assert "## Source: container" in cfg
    assert "proxy_pass http://frontend:3000" in cfg

    _api_reload_angie(api_session)
    r = _wait_for_response("test3.example", "<div id=\"root\"")
    assert r.status_code == 200
