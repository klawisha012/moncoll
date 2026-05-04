from pydantic import BaseModel, Field

class CertificateRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1)
    challenge_type: str = Field(default="http")

class CertificateResponse(BaseModel):
    success: bool
    certificate_path: str | None = None
    key_path: str | None = None
    message: str
