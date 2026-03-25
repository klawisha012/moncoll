from pydantic import BaseModel


class ModSecurityConfigResponse(BaseModel):
    content: str
    file_path: str


class ModSecurityConfigUpdate(BaseModel):
    content: str


class RuleCreate(BaseModel):
    rule: str


class RuleResponse(BaseModel):
    rule: str
    id: int | None = None
    success: bool
    message: str = ""


class RuleItem(BaseModel):
    id: int
    rule: str
    message: str = ""
    phase: int | None = None
    action: str = "pass"
    severity: int | None = None


class ReloadResponse(BaseModel):
    success: bool
    message: str
