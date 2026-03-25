from pydantic import BaseModel, Field


class ModSecuritySettings(BaseModel):
    rule_engine: str = Field(
        default="DetectionOnly", description="SecRuleEngine: On, Off, DetectionOnly"
    )
    request_body_access: bool = Field(default=True, description="SecRequestBodyAccess")
    response_body_access: bool = Field(
        default=True, description="SecResponseBodyAccess"
    )
    request_body_limit: int = Field(
        default=13107200, description="SecRequestBodyLimit in bytes"
    )
    request_body_no_files_limit: int = Field(
        default=131072, description="SecRequestBodyNoFilesLimit in bytes"
    )
    request_body_limit_action: str = Field(
        default="Reject",
        description="SecRequestBodyLimitAction: Reject or ProcessPartial",
    )
    request_body_json_depth_limit: int = Field(
        default=512, description="SecRequestBodyJsonDepthLimit"
    )
    arguments_limit: int = Field(default=1000, description="SecArgumentsLimit")
    response_body_mime_types: list[str] = Field(
        default=["text/plain", "text/html", "text/xml"]
    )
    response_body_limit: int = Field(
        default=524288, description="SecResponseBodyLimit in bytes"
    )
    response_body_limit_action: str = Field(
        default="ProcessPartial",
        description="SecResponseBodyLimitAction: ProcessPartial or Reject",
    )
    audit_engine: str = Field(
        default="RelevantOnly", description="SecAuditEngine: On, Off, RelevantOnly"
    )
    audit_log_type: str = Field(
        default="Serial", description="SecAuditLogType: Serial or Concurrent"
    )
    audit_log_format: str = Field(
        default="JSON", description="SecAuditLogFormat: JSON or Native"
    )
    audit_log_parts: str = Field(default="ABIJDEFHZ", description="SecAuditLogParts")
    audit_log_relevant_status: str = Field(
        default="^(?:5|4(?!04))", description="SecAuditLogRelevantStatus regex"
    )
    audit_log_path: str = Field(
        default="/var/log/angie/audit.log", description="SecAuditLog path"
    )
    pcre_match_limit: int = Field(default=1000, description="SecPcreMatchLimit")
    pcre_match_limit_recursion: int = Field(
        default=1000, description="SecPcreMatchLimitRecursion"
    )
    status_engine: bool = Field(default=False, description="SecStatusEngine")
    tmp_dir: str = Field(default="/tmp/", description="SecTmpDir")
    data_dir: str = Field(default="/tmp/", description="SecDataDir")


class ModSecuritySettingsResponse(ModSecuritySettings):
    pass


class ModSecuritySettingsUpdate(ModSecuritySettings):
    pass
