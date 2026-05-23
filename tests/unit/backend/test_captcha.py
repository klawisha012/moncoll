import pytest
import respx
from src.auth import captcha


@pytest.mark.asyncio
@respx.mock
async def test_verify_success(monkeypatch):
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "sec")
    from src.config import get_settings
    get_settings.cache_clear()
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").respond(
        200, json={"success": True}
    )
    assert await captcha.verify("token", remote_ip="1.2.3.4") is True


@pytest.mark.asyncio
@respx.mock
async def test_verify_failure(monkeypatch):
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "sec")
    from src.config import get_settings
    get_settings.cache_clear()
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").respond(
        200, json={"success": False, "error-codes": ["invalid-input-response"]}
    )
    assert await captcha.verify("token", remote_ip="1.2.3.4") is False


@pytest.mark.asyncio
async def test_verify_disabled_passes(monkeypatch):
    monkeypatch.delenv("WAF_TURNSTILE_SECRET_KEY", raising=False)
    from src.config import get_settings
    get_settings.cache_clear()
    assert await captcha.verify("anything") is True


@pytest.mark.asyncio
@respx.mock
async def test_verify_or_raise_failure(monkeypatch):
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "sec")
    from src.config import get_settings
    get_settings.cache_clear()
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").respond(
        200, json={"success": False}
    )

    from fastapi import HTTPException

    class FakeReq:
        client = type("c", (), {"host": "1.2.3.4"})()

    with pytest.raises(HTTPException) as exc:
        await captcha.verify_or_raise("token", FakeReq())
    assert exc.value.status_code == 400
