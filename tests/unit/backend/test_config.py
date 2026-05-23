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


def test_settings_defaults(monkeypatch):
    """A regression in any default value (e.g. cookie_secure flipping to True) must fail loudly."""
    # Clear any env vars set by other tests
    for key in [
        "WAF_PUBLIC_BASE_URL", "WAF_COOKIE_SECURE", "WAF_TURNSTILE_SITE_KEY",
        "WAF_TURNSTILE_SECRET_KEY", "WAF_SMTP_HOST", "WAF_SMTP_PORT",
        "WAF_SMTP_FROM_EMAIL", "WAF_SMTP_FROM_NAME", "WAF_SMTP_STARTTLS",
        "WAF_OAUTH_GOOGLE_CLIENT_ID", "WAF_OAUTH_GITHUB_CLIENT_ID",
    ]:
        monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    s = get_settings()
    assert s.public_base_url == "http://localhost"
    assert s.cookie_secure is False
    assert s.smtp_port == 587
    assert s.smtp_from_email == "noreply@localhost"
    assert s.smtp_starttls is True
    assert s.oauth_google_enabled is False
    assert s.oauth_github_enabled is False
