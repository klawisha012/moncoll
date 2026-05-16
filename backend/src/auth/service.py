import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .schemas import UserCreate, UserPublic, UserUpdate
from .security import hash_password, verify_password

logger = logging.getLogger(__name__)

USERS_DIR = Path("/var/lib/angie/data")
USERS_FILE = USERS_DIR / "users.json"

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"


def _ensure_dirs() -> None:
    USERS_DIR.mkdir(parents=True, exist_ok=True)


def _load_users() -> list[dict]:
    if not USERS_FILE.exists():
        return []
    try:
        content = USERS_FILE.read_text()
        data = json.loads(content)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to read users.json: %s", exc)
        return []


def _save_users(users: list[dict]) -> None:
    """Atomic write — tempfile + os.replace so the file is never half-written."""
    _ensure_dirs()
    fd, tmp_path = tempfile.mkstemp(prefix=".users.", suffix=".json.tmp", dir=str(USERS_DIR))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(users, f, indent=2)
        os.replace(tmp_path, USERS_FILE)
        try:
            os.chmod(USERS_FILE, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _next_id(users: list[dict]) -> int:
    return max([u.get("id", 0) for u in users] + [0]) + 1


def _to_public(user: dict) -> UserPublic:
    return UserPublic(
        id=user["id"],
        username=user["username"],
        role=user["role"],
        must_change_password=user.get("must_change_password", False),
        created_at=user["created_at"],
        updated_at=user["updated_at"],
    )


def _count_admins(users: list[dict]) -> int:
    return sum(1 for u in users if u.get("role") == "admin")


def seed_default_admin() -> None:
    """Create default admin/admin user if no users exist."""
    _ensure_dirs()
    users = _load_users()
    if users:
        return
    now = datetime.now(timezone.utc).isoformat()
    admin = {
        "id": 1,
        "username": DEFAULT_ADMIN_USERNAME,
        "password_hash": hash_password(DEFAULT_ADMIN_PASSWORD),
        "role": "admin",
        "must_change_password": True,
        "created_at": now,
        "updated_at": now,
    }
    _save_users([admin])
    logger.warning(
        "Created default admin user (username=%s, password=%s, must_change_password=true). "
        "Change the password on first login.",
        DEFAULT_ADMIN_USERNAME,
        DEFAULT_ADMIN_PASSWORD,
    )


def authenticate(username: str, password: str) -> dict | None:
    for user in _load_users():
        if user.get("username") == username and verify_password(
            password, user.get("password_hash", "")
        ):
            return user
    return None


def get_user(user_id: int) -> dict | None:
    for user in _load_users():
        if user.get("id") == user_id:
            return user
    return None


def list_users() -> list[UserPublic]:
    return [_to_public(u) for u in _load_users()]


def create_user(payload: UserCreate) -> UserPublic:
    users = _load_users()
    if any(u.get("username") == payload.username for u in users):
        raise ValueError("username already exists")
    now = datetime.now(timezone.utc).isoformat()
    new_user = {
        "id": _next_id(users),
        "username": payload.username,
        "password_hash": hash_password(payload.password),
        "role": payload.role,
        "must_change_password": False,
        "created_at": now,
        "updated_at": now,
    }
    users.append(new_user)
    _save_users(users)
    return _to_public(new_user)


def update_user(user_id: int, payload: UserUpdate) -> UserPublic | None:
    users = _load_users()
    for user in users:
        if user.get("id") != user_id:
            continue
        if payload.role is not None:
            if user.get("role") == "admin" and payload.role != "admin":
                if _count_admins(users) <= 1:
                    raise ValueError("cannot demote the last admin")
            user["role"] = payload.role
        if payload.password is not None:
            user["password_hash"] = hash_password(payload.password)
            user["must_change_password"] = True
        user["updated_at"] = datetime.now(timezone.utc).isoformat()
        _save_users(users)
        return _to_public(user)
    return None


def change_password(user_id: int, new_password: str) -> bool:
    users = _load_users()
    for user in users:
        if user.get("id") == user_id:
            user["password_hash"] = hash_password(new_password)
            user["must_change_password"] = False
            user["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_users(users)
            return True
    return False


def delete_user(user_id: int) -> bool:
    users = _load_users()
    for idx, user in enumerate(users):
        if user.get("id") == user_id:
            if user.get("role") == "admin" and _count_admins(users) <= 1:
                raise ValueError("cannot delete the last admin")
            users.pop(idx)
            _save_users(users)
            return True
    return False
