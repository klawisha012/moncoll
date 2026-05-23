"""Session security primitives — PASETO v4.local tokens + HMAC short-lived cookies."""

import hashlib
import hmac
import json
import logging
import os
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyseto
from passlib.context import CryptContext
from pyseto import Key

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 8 * 60 * 60
PASETO_KEY_FILE = Path("/var/lib/angie/.paseto_key")

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_cached_key: bytes | None = None


def _load_or_create_paseto_key() -> bytes:
    global _cached_key
    if _cached_key is not None:
        return _cached_key

    env = os.environ.get("WAF_PASETO_KEY")
    if env:
        # Must be exactly 64 hex chars (32 bytes). Fail-fast on any other shape
        # so a typo in secret-management config crashes the container at startup
        # rather than silently producing a different key on each node (D2).
        if len(env) != 64:
            raise SystemExit(
                f"WAF_PASETO_KEY must be exactly 64 hex characters (32 bytes). Got {len(env)} chars."
            )
        try:
            _cached_key = bytes.fromhex(env)
        except ValueError as exc:
            raise SystemExit(f"WAF_PASETO_KEY is not valid hex: {exc}") from None
        return _cached_key

    try:
        if PASETO_KEY_FILE.exists():
            _cached_key = PASETO_KEY_FILE.read_bytes()
            return _cached_key
        PASETO_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_bytes(32)
        PASETO_KEY_FILE.write_bytes(new_key)
        try:
            os.chmod(PASETO_KEY_FILE, 0o600)
        except OSError:
            pass
        logger.info("Generated new PASETO key at %s", PASETO_KEY_FILE)
        _cached_key = new_key
        return _cached_key
    except OSError as exc:
        logger.warning("Cannot persist PASETO key (%s) — using ephemeral key", exc)
        _cached_key = secrets.token_bytes(32)
        return _cached_key


def _paseto_key() -> Key:
    return Key.new(version=4, purpose="local", key=_load_or_create_paseto_key())


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return _pwd_context.verify(plain, hashed)
    except (ValueError, TypeError):
        return False


def create_session_token(
    *,
    user_id: int,
    platform_role: str,
    tenant_id: int | None,
    tenant_role: str | None,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "pr": platform_role,
        "tn": tenant_id,
        "tr": tenant_role,
        "iat": now.timestamp(),
        "exp": (now + timedelta(seconds=SESSION_TTL_SECONDS)).timestamp(),
    }
    return pyseto.encode(_paseto_key(), json.dumps(payload).encode()).decode()


def decode_session_token(token: str) -> dict | None:
    try:
        decoded = pyseto.decode(_paseto_key(), token)
        data = json.loads(decoded.payload)
        if data.get("exp", 0) < datetime.now(UTC).timestamp():
            return None
        return data
    except Exception:
        return None


def sign_short_lived(payload: dict, *, ttl_seconds: int, purpose: str) -> str:
    """Return base64url(json_body . hmac_tag) for a short-lived signed cookie."""
    body = {**payload, "exp": datetime.now(UTC).timestamp() + ttl_seconds, "p": purpose}
    raw = json.dumps(body, separators=(",", ":")).encode()
    tag = hmac.new(_load_or_create_paseto_key(), raw, hashlib.sha256).digest()
    return urlsafe_b64encode(raw + b"." + tag).rstrip(b"=").decode()


def verify_short_lived(value: str, *, purpose: str) -> dict | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = urlsafe_b64decode(padded.encode())
        raw, tag = decoded.rsplit(b".", 1)
        expected = hmac.new(_load_or_create_paseto_key(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return None
        body = json.loads(raw)
        if body.get("p") != purpose:
            return None
        if body.get("exp", 0) < datetime.now(UTC).timestamp():
            return None
        body.pop("p")
        body.pop("exp")
        return body
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Transition shims — removed after Phase 4 / Phase 8 land.
# ---------------------------------------------------------------------------

# dependencies.py (Phase 4 not yet updated) still imports decode_access_token.
decode_access_token = decode_session_token  # legacy name; same behaviour

# router.py (Phase 8 not yet updated) still imports these two names.
JWT_TTL_SECONDS = SESSION_TTL_SECONDS  # same value, old name


def create_access_token(*, user_id: int, username: str, role: str) -> str:  # noqa: ARG001
    """Shim: maps old single-tenant signature to new PASETO token.

    username is dropped (not stored in PASETO claims).
    role maps to platform_role; tenant context is None until Phase 8 rewrites login.
    """
    return create_session_token(
        user_id=user_id,
        platform_role=role,
        tenant_id=None,
        tenant_role=None,
    )
