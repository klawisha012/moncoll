"""Unit tests for backend/src/auth/totp.py."""

import hashlib

import pyotp
import pytest

from backend.src.auth.totp import (
    generate_recovery_codes,
    generate_secret,
    provisioning_uri,
    verify_code,
)


def test_verify_code_valid():
    secret = generate_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_code(secret, code) is True


def test_verify_code_invalid():
    secret = generate_secret()
    assert verify_code(secret, "000000") is False


def test_verify_code_no_secret():
    assert verify_code(None, "123456") is False


def test_verify_code_empty_secret():
    assert verify_code("", "123456") is False


def test_generate_recovery_codes_count():
    plain, hashes = generate_recovery_codes()
    assert len(plain) == 10
    assert len(hashes) == 10


def test_generate_recovery_codes_uniqueness():
    plain, hashes = generate_recovery_codes()
    assert len(set(plain)) == 10
    assert len(set(hashes)) == 10


def test_generate_recovery_codes_hashes_match():
    plain, hashes = generate_recovery_codes()
    for p, h in zip(plain, hashes):
        assert hashlib.sha256(p.encode()).hexdigest() == h


def test_generate_recovery_codes_plain_not_stored():
    """Plain codes must not appear in the hashes list (not stored as-is)."""
    plain, hashes = generate_recovery_codes()
    for p in plain:
        assert p not in hashes


def test_provisioning_uri_format():
    secret = generate_secret()
    uri = provisioning_uri(secret, account_label="user@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "WAF" in uri
    assert "user%40example.com" in uri or "user@example.com" in uri


def test_encrypt_decrypt_secret():
    from backend.src.auth.totp import encrypt_secret, decrypt_secret
    secret = "JBSWY3DPEHPK3PXP"
    encrypted = encrypt_secret(secret)
    assert encrypted != secret
    decrypted = decrypt_secret(encrypted)
    assert decrypted == secret

