import pytest
from src.config import get_settings


def test_settings_reads_env(monkeypatch):
    monkeypatch.setenv("WAF_PUBLIC_BASE_URL", "https://example.com")
    monkeypatch.setenv("WAF_TURNSTILE_SITE_KEY", "site-key")
    monkeypatch.setenv("WAF_TURNSTILE_SECRET_KEY", "secret-key")
    get_settings.cache_clear()
    s = get_settings()
    assert s.public_base_url == "https://example.com"
    assert s.turnstile_site_key == "site-key"
    assert s.oauth_google_enabled is False


def test_settings_oauth_enabled(monkeypatch):
    monkeypatch.setenv("WAF_OAUTH_GOOGLE_CLIENT_ID", "x")
    monkeypatch.setenv("WAF_OAUTH_GOOGLE_CLIENT_SECRET", "y")
    monkeypatch.setenv("WAF_OAUTH_GOOGLE_REDIRECT_URI", "z")
    get_settings.cache_clear()
    s = get_settings()
    assert s.oauth_google_enabled is True
