from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

PlatformRole = Literal["admin", "client"]
TenantRole = Literal["owner", "member"]


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    display_name: str
    platform_role: PlatformRole
    tenant_id: int | None
    tenant_role: TenantRole | None
    email_verified: bool
    totp_enabled: bool

    @classmethod
    def from_user(cls, user) -> "UserPublic":
        return cls(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            platform_role=user.platform_role,
            tenant_id=user.tenant_id,
            tenant_role=user.tenant_role,
            email_verified=user.email_verified_at is not None,
            totp_enabled=user.totp_enabled_at is not None,
        )


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    tenant_name: str = Field(min_length=3, max_length=32)
    display_name: str | None = Field(default=None, max_length=64)
    captcha_token: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    captcha_token: str
    totp_code: str | None = None


class VerifyEmailRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    captcha_token: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=256)


class TotpConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class LoginResponse(BaseModel):
    user: UserPublic


# ---------------------------------------------------------------------------
# Transition shims for legacy router.py — removed in Phase 8 when router
# rewrite lands. router.py references these names only at parse time;
# substituting SignupRequest is safe because the legacy endpoints are
# unreachable (no admin user, schema mismatch with new DB).
# ---------------------------------------------------------------------------
ChangePasswordRequest = SignupRequest  # noqa: N816
UserCreate = SignupRequest  # noqa: N816
UserUpdate = SignupRequest  # noqa: N816
