import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 8 * 60 * 60  # 8 hours
JWT_SECRET_FILE = Path("/var/lib/angie/.jwt_secret")

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_cached_secret: str | None = None


def _load_or_create_jwt_secret() -> str:
    """Return the JWT signing secret.

    Priority:
    1. Env var ``WAF_JWT_SECRET`` (for orchestrators that prefer ENV).
    2. ``/var/lib/angie/.jwt_secret`` — generated on first run, persists across restarts.
    """
    global _cached_secret
    if _cached_secret is not None:
        return _cached_secret

    env_secret = os.environ.get("WAF_JWT_SECRET")
    if env_secret:
        _cached_secret = env_secret
        return _cached_secret

    try:
        if JWT_SECRET_FILE.exists():
            data = JWT_SECRET_FILE.read_text().strip()
            if data:
                _cached_secret = data
                return _cached_secret
        JWT_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        new_secret = secrets.token_urlsafe(48)
        JWT_SECRET_FILE.write_text(new_secret)
        try:
            os.chmod(JWT_SECRET_FILE, 0o600)
        except OSError:
            pass
        logger.info("Generated new JWT signing secret at %s", JWT_SECRET_FILE)
        _cached_secret = new_secret
        return _cached_secret
    except OSError as exc:
        logger.warning("Cannot persist JWT secret (%s) — falling back to ephemeral", exc)
        _cached_secret = secrets.token_urlsafe(48)
        return _cached_secret


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd_context.verify(plain, hashed)
    except (ValueError, TypeError):
        return False


def create_access_token(*, user_id: int, username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=JWT_TTL_SECONDS)).timestamp()),
    }
    return jwt.encode(payload, _load_or_create_jwt_secret(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, _load_or_create_jwt_secret(), algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None
