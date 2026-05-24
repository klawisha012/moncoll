"""TOTP primitives: secret generation, QR, code verification, recovery codes."""

import base64
import hashlib
import io
import secrets
from datetime import UTC, datetime

import pyotp
import qrcode
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import User


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, *, account_label: str, issuer: str = "WAF") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account_label, issuer_name=issuer)


def qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def verify_code(secret: str | None, code: str) -> bool:
    if not secret:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(n: int = 10) -> tuple[list[str], list[str]]:
    """Return (plain_codes, sha256_hashes). Store only the hashes."""
    plain = [secrets.token_hex(5) for _ in range(n)]
    hashes = [hashlib.sha256(c.encode()).hexdigest() for c in plain]
    return plain, hashes


async def verify_recovery(session: AsyncSession, user: User, code: str) -> bool:
    if not user.recovery_codes_hash:
        return False
    h = hashlib.sha256(code.encode()).hexdigest()
    if h not in user.recovery_codes_hash:
        return False
    user.recovery_codes_hash = [x for x in user.recovery_codes_hash if x != h]
    await session.commit()
    await session.refresh(user)
    return True


async def activate(session: AsyncSession, user: User) -> None:
    user.totp_enabled_at = datetime.now(UTC)
    await session.commit()
