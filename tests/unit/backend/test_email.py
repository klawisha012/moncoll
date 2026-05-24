import pytest
from unittest.mock import patch
from src.auth import email


@pytest.mark.asyncio
async def test_dev_mode_logs_when_no_smtp(monkeypatch, caplog):
    monkeypatch.delenv("WAF_SMTP_HOST", raising=False)
    from src.config import get_settings
    get_settings.cache_clear()
    caplog.set_level("INFO")
    await email.send_verify_email(to_email="a@b.com", display_name="Joe", verify_url="https://x/v?t=1")
    assert "EMAIL BODY" in caplog.text
    assert "https://x/v?t=1" in caplog.text


@pytest.mark.asyncio
async def test_sends_via_smtp_when_configured(monkeypatch):
    monkeypatch.setenv("WAF_SMTP_HOST", "smtp.example.com")
    from src.config import get_settings
    get_settings.cache_clear()
    with patch("aiosmtplib.send") as m:
        await email.send_verify_email(to_email="a@b.com", display_name="Joe", verify_url="https://x/v?t=1")
        m.assert_awaited_once()
