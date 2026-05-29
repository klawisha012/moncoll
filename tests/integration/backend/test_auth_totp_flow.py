"""Integration tests for the TOTP enrolment + login gating flow."""

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient

from backend.src.auth import service as auth_service
from backend.src.auth.dependencies import SESSION_COOKIE, TOTP_ENROL_COOKIE
from backend.src.db.session import get_session
from backend.src.main import app


def _make_client(db_session):
    app.dependency_overrides[get_session] = lambda: db_session
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


async def _create_admin(db_session, email="admin@example.com", password="adminpass1"):
    return await auth_service.create_admin(db_session, email=email, password=password)


@pytest.fixture(autouse=True)
def clear_settings_cache(monkeypatch):
    monkeypatch.setenv("WAF_COOKIE_SECURE", "false")
    from backend.src.config import get_settings
    from backend.src.auth import security
    get_settings.cache_clear()
    security._cached_key = None
    yield
    get_settings.cache_clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_admin_first_login_returns_enrol_cookie(db_session, monkeypatch):
    """Admin without TOTP secret → 403 totp_enrol_required + enrol cookie set."""
    monkeypatch.setenv("WAF_PASETO_KEY", "a0" * 32)
    from backend.src.auth import security
    security._cached_key = None

    await _create_admin(db_session)

    async with _make_client(db_session) as c:
        r = await c.post(
            "/api/auth/login",
            json={"email": "admin@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        assert r.status_code == 403, r.text
        assert r.json()["detail"] == "totp_enrol_required"
        assert TOTP_ENROL_COOKIE in r.cookies

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_totp_setup_with_enrol_cookie(db_session, monkeypatch):
    """POST /totp/setup with enrol cookie → returns secret + QR + recovery codes."""
    monkeypatch.setenv("WAF_PASETO_KEY", "b1" * 32)
    from backend.src.auth import security
    security._cached_key = None

    await _create_admin(db_session, email="setup@example.com")

    async with _make_client(db_session) as c:
        # First login to get the enrol cookie
        login_r = await c.post(
            "/api/auth/login",
            json={"email": "setup@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        assert login_r.status_code == 403
        enrol_cookie = login_r.cookies[TOTP_ENROL_COOKIE]
        c.cookies.set(TOTP_ENROL_COOKIE, enrol_cookie)

        # POST /totp/setup using the enrol cookie
        setup_r = await c.post("/api/auth/totp/setup")
        assert setup_r.status_code == 200, setup_r.text
        data = setup_r.json()
        assert "secret_base32" in data
        assert "qr_code_data_uri" in data
        assert data["qr_code_data_uri"].startswith("data:image/png;base64,")
        assert "recovery_codes" in data
        assert len(data["recovery_codes"]) == 10

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_totp_confirm_issues_session(db_session, monkeypatch):
    """Full enrol flow: setup → confirm with valid code → session cookie issued."""
    monkeypatch.setenv("WAF_PASETO_KEY", "c2" * 32)
    from backend.src.auth import security
    security._cached_key = None

    await _create_admin(db_session, email="confirm@example.com")

    async with _make_client(db_session) as c:
        # Step 1: first login → enrol cookie
        login_r = await c.post(
            "/api/auth/login",
            json={"email": "confirm@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        assert login_r.status_code == 403
        enrol_cookie = login_r.cookies[TOTP_ENROL_COOKIE]
        c.cookies.set(TOTP_ENROL_COOKIE, enrol_cookie)

        # Step 2: setup → get secret
        setup_r = await c.post("/api/auth/totp/setup")
        assert setup_r.status_code == 200
        secret = setup_r.json()["secret_base32"]

        # Step 3: confirm with valid TOTP code
        valid_code = pyotp.TOTP(secret).now()
        confirm_r = await c.post(
            "/api/auth/totp/confirm",
            json={"code": valid_code},
        )
        assert confirm_r.status_code == 200, confirm_r.text
        assert confirm_r.json()["ok"] is True
        assert SESSION_COOKIE in confirm_r.cookies

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_login_with_totp_code(db_session, monkeypatch):
    """After enrolment, admin login succeeds with valid TOTP code."""
    monkeypatch.setenv("WAF_PASETO_KEY", "d3" * 32)
    from backend.src.auth import security
    security._cached_key = None

    await _create_admin(db_session, email="totp_login@example.com")

    async with _make_client(db_session) as c:
        # Step 1: first login → enrol cookie
        login_r = await c.post(
            "/api/auth/login",
            json={"email": "totp_login@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        enrol_cookie = login_r.headers.get("set-cookie", "")
        # Extract just the cookie value from the Set-Cookie header
        import re
        match = re.search(rf"{TOTP_ENROL_COOKIE}=([^;]+)", enrol_cookie)
        assert match, f"enrol cookie not found in: {enrol_cookie}"
        enrol_value = match.group(1)

        # Step 2: setup — set cookie on client
        c.cookies.set(TOTP_ENROL_COOKIE, enrol_value)
        setup_r = await c.post("/api/auth/totp/setup")
        assert setup_r.status_code == 200, setup_r.text
        secret = setup_r.json()["secret_base32"]

        # Step 3: confirm
        code = pyotp.TOTP(secret).now()
        confirm_r = await c.post("/api/auth/totp/confirm", json={"code": code})
        assert confirm_r.status_code == 200
        c.cookies.clear()

        # Step 4: log in with TOTP code
        code2 = pyotp.TOTP(secret).now()
        login2_r = await c.post(
            "/api/auth/login",
            json={
                "email": "totp_login@example.com",
                "password": "adminpass1",
                "captcha_token": "tok",
                "totp_code": code2,
            },
        )
        assert login2_r.status_code == 200, login2_r.text
        assert SESSION_COOKIE in login2_r.cookies

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_login_missing_totp_code(db_session, monkeypatch):
    """After enrolment, login without TOTP code → 401 totp_required."""
    monkeypatch.setenv("WAF_PASETO_KEY", "e4" * 32)
    from backend.src.auth import security
    security._cached_key = None

    await _create_admin(db_session, email="missing_totp@example.com")

    async with _make_client(db_session) as c:
        # Enrol
        login_r = await c.post(
            "/api/auth/login",
            json={"email": "missing_totp@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        enrol_cookie = login_r.cookies[TOTP_ENROL_COOKIE]
        c.cookies.set(TOTP_ENROL_COOKIE, enrol_cookie)
        setup_r = await c.post("/api/auth/totp/setup")
        secret = setup_r.json()["secret_base32"]
        code = pyotp.TOTP(secret).now()
        await c.post(
            "/api/auth/totp/confirm",
            json={"code": code},
        )

        # Login without TOTP code
        r = await c.post(
            "/api/auth/login",
            json={"email": "missing_totp@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        assert r.status_code == 401, r.text
        assert r.json()["detail"] == "totp_required"

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_login_with_recovery_code(db_session, monkeypatch):
    """Admin can log in using a recovery code instead of TOTP."""
    monkeypatch.setenv("WAF_PASETO_KEY", "f5" * 32)
    from backend.src.auth import security
    security._cached_key = None

    await _create_admin(db_session, email="recovery@example.com")

    async with _make_client(db_session) as c:
        # Enrol and capture recovery codes
        login_r = await c.post(
            "/api/auth/login",
            json={"email": "recovery@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        enrol_cookie = login_r.cookies[TOTP_ENROL_COOKIE]
        c.cookies.set(TOTP_ENROL_COOKIE, enrol_cookie)
        setup_r = await c.post("/api/auth/totp/setup")
        data = setup_r.json()
        secret = data["secret_base32"]
        recovery_codes = data["recovery_codes"]

        code = pyotp.TOTP(secret).now()
        await c.post(
            "/api/auth/totp/confirm",
            json={"code": code},
        )

        # Login using a recovery code
        r = await c.post(
            "/api/auth/login",
            json={
                "email": "recovery@example.com",
                "password": "adminpass1",
                "captcha_token": "tok",
                "totp_code": recovery_codes[0],
            },
        )
        assert r.status_code == 200, r.text
        assert SESSION_COOKIE in r.cookies

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_recovery_code_single_use(db_session, monkeypatch):
    """A recovery code can only be used once; second use → 401."""
    monkeypatch.setenv("WAF_PASETO_KEY", "06" * 32)
    from backend.src.auth import security
    security._cached_key = None

    await _create_admin(db_session, email="oneuse@example.com")

    async with _make_client(db_session) as c:
        # Enrol
        login_r = await c.post(
            "/api/auth/login",
            json={"email": "oneuse@example.com", "password": "adminpass1", "captcha_token": "tok"},
        )
        enrol_cookie = login_r.cookies[TOTP_ENROL_COOKIE]
        c.cookies.set(TOTP_ENROL_COOKIE, enrol_cookie)
        setup_r = await c.post("/api/auth/totp/setup")
        data = setup_r.json()
        secret = data["secret_base32"]
        recovery_codes = data["recovery_codes"]

        code = pyotp.TOTP(secret).now()
        await c.post(
            "/api/auth/totp/confirm",
            json={"code": code},
        )

        # First use of recovery code — should succeed
        r1 = await c.post(
            "/api/auth/login",
            json={
                "email": "oneuse@example.com",
                "password": "adminpass1",
                "captcha_token": "tok",
                "totp_code": recovery_codes[0],
            },
        )
        assert r1.status_code == 200, r1.text

        # Second use of the same recovery code — should fail
        r2 = await c.post(
            "/api/auth/login",
            json={
                "email": "oneuse@example.com",
                "password": "adminpass1",
                "captcha_token": "tok",
                "totp_code": recovery_codes[0],
            },
        )
        assert r2.status_code == 401, r2.text
        assert r2.json()["detail"] == "invalid totp"

    app.dependency_overrides.clear()
    security._cached_key = None


@pytest.mark.asyncio
async def test_totp_setup_without_cookie_returns_401(db_session, monkeypatch):
    """POST /totp/setup with no cookies → 401."""
    monkeypatch.setenv("WAF_PASETO_KEY", "17" * 32)
    from backend.src.auth import security
    security._cached_key = None

    async with _make_client(db_session) as c:
        r = await c.post("/api/auth/totp/setup")
        assert r.status_code == 401

    app.dependency_overrides.clear()
    security._cached_key = None
