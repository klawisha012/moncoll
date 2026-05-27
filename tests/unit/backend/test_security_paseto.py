# tests/unit/backend/test_security_paseto.py
import pytest
from backend.src.auth import security


def test_hash_and_verify_password():
    h = security.hash_password("hello")
    assert security.verify_password("hello", h)
    assert not security.verify_password("wrong", h)


def test_paseto_roundtrip(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    security._cached_key = None
    token = security.create_session_token(user_id=1, platform_role="client", tenant_id=2, tenant_role="owner")
    payload = security.decode_session_token(token)
    assert payload["sub"] == "1"
    assert payload["pr"] == "client"
    assert payload["tn"] == 2
    assert payload["tr"] == "owner"


def test_paseto_tamper_rejected(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    security._cached_key = None
    token = security.create_session_token(user_id=1, platform_role="admin", tenant_id=None, tenant_role=None)
    tampered = token[:-4] + "AAAA"
    assert security.decode_session_token(tampered) is None


def test_hmac_signed_cookie_roundtrip(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "1" * 64)
    security._cached_key = None
    value = security.sign_short_lived({"user_id": 5}, ttl_seconds=600, purpose="totp_enrol")
    payload = security.verify_short_lived(value, purpose="totp_enrol")
    assert payload == {"user_id": 5}


def test_short_lived_wrong_purpose(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "1" * 64)
    security._cached_key = None
    value = security.sign_short_lived({"user_id": 5}, ttl_seconds=600, purpose="totp_enrol")
    assert security.verify_short_lived(value, purpose="oauth_state") is None


def test_paseto_env_key_wrong_length_raises(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "shortkey")
    security._cached_key = None
    with pytest.raises(SystemExit, match="64 hex"):
        security._load_or_create_paseto_key()


def test_paseto_env_key_invalid_hex_raises(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "Z" * 64)
    security._cached_key = None
    with pytest.raises(SystemExit, match="not valid hex"):
        security._load_or_create_paseto_key()


def test_paseto_expired_returns_none(monkeypatch):
    import time
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    security._cached_key = None
    original = security.SESSION_TTL_SECONDS
    security.SESSION_TTL_SECONDS = 1
    try:
        token = security.create_session_token(user_id=1, platform_role="client", tenant_id=2, tenant_role="owner")
        time.sleep(1.2)
        assert security.decode_session_token(token) is None
    finally:
        security.SESSION_TTL_SECONDS = original


def test_short_lived_expired_returns_none(monkeypatch):
    import time
    monkeypatch.setenv("WAF_PASETO_KEY", "0" * 64)
    security._cached_key = None
    value = security.sign_short_lived({"x": 1}, ttl_seconds=1, purpose="oauth_state")
    time.sleep(1.2)
    assert security.verify_short_lived(value, purpose="oauth_state") is None


def test_short_lived_signature_with_dots(monkeypatch):
    monkeypatch.setenv("WAF_PASETO_KEY", "1" * 64)
    security._cached_key = None
    
    # Craft a fake 32-byte HMAC-SHA256 signature containing dot characters
    fake_digest = b"some.fake.digest.with.dots.12345"
    assert len(fake_digest) == 32
    
    class MockHMAC:
        def __init__(self, *args, **kwargs):
            pass
        def digest(self):
            return fake_digest
            
    import hmac
    monkeypatch.setattr(hmac, "new", MockHMAC)
    
    value = security.sign_short_lived({"user_id": 5}, ttl_seconds=600, purpose="totp_enrol")
    payload = security.verify_short_lived(value, purpose="totp_enrol")
    assert payload == {"user_id": 5}
