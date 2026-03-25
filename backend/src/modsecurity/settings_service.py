import re
from pathlib import Path

from .settings_schemas import ModSecuritySettings

MODSECURITY_CONFIG_DIR = Path("/app/etc/angie/modsecurity")
MODSECURITY_CONFIG_FILE = MODSECURITY_CONFIG_DIR / "modsecurity.conf"


def parse_modsecurity_config(content: str) -> ModSecuritySettings:
    settings = ModSecuritySettings()

    m = re.search(r"^SecRuleEngine\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.rule_engine = m.group(1)

    m = re.search(r"^SecRequestBodyAccess\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.request_body_access = m.group(1).lower() == "on"

    m = re.search(r"^SecResponseBodyAccess\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.response_body_access = m.group(1).lower() == "on"

    m = re.search(r"^SecRequestBodyLimit\s+(\d+)", content, re.MULTILINE)
    if m:
        settings.request_body_limit = int(m.group(1))

    m = re.search(r"^SecRequestBodyNoFilesLimit\s+(\d+)", content, re.MULTILINE)
    if m:
        settings.request_body_no_files_limit = int(m.group(1))

    m = re.search(r"^SecRequestBodyLimitAction\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.request_body_limit_action = m.group(1)

    m = re.search(r"^SecRequestBodyJsonDepthLimit\s+(\d+)", content, re.MULTILINE)
    if m:
        settings.request_body_json_depth_limit = int(m.group(1))

    m = re.search(r"^SecArgumentsLimit\s+(\d+)", content, re.MULTILINE)
    if m:
        settings.arguments_limit = int(m.group(1))

    m = re.search(r"^SecResponseBodyMimeType\s+(.+)$", content, re.MULTILINE)
    if m:
        settings.response_body_mime_types = m.group(1).strip().split()

    m = re.search(r"^SecResponseBodyLimit\s+(\d+)", content, re.MULTILINE)
    if m:
        settings.response_body_limit = int(m.group(1))

    m = re.search(r"^SecResponseBodyLimitAction\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.response_body_limit_action = m.group(1)

    m = re.search(r"^SecAuditEngine\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.audit_engine = m.group(1)

    m = re.search(r"^SecAuditLogType\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.audit_log_type = m.group(1)

    m = re.search(r"^SecAuditLogFormat\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.audit_log_format = m.group(1)

    m = re.search(r"^SecAuditLogParts\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.audit_log_parts = m.group(1)

    m = re.search(r'^SecAuditLogRelevantStatus\s+"?([^"\n]+)"?', content, re.MULTILINE)
    if m:
        settings.audit_log_relevant_status = m.group(1).strip()

    m = re.search(r"^SecAuditLog\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.audit_log_path = m.group(1)

    m = re.search(r"^SecPcreMatchLimit\s+(\d+)", content, re.MULTILINE)
    if m:
        settings.pcre_match_limit = int(m.group(1))

    m = re.search(r"^SecPcreMatchLimitRecursion\s+(\d+)", content, re.MULTILINE)
    if m:
        settings.pcre_match_limit_recursion = int(m.group(1))

    m = re.search(r"^SecStatusEngine\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.status_engine = m.group(1).lower() == "on"

    m = re.search(r"^SecTmpDir\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.tmp_dir = m.group(1)

    m = re.search(r"^SecDataDir\s+(\S+)", content, re.MULTILINE)
    if m:
        settings.data_dir = m.group(1)

    return settings


def _on_off(value: bool) -> str:
    return "On" if value else "Off"


def generate_modsecurity_config(settings: ModSecuritySettings) -> str:
    mime_types = " ".join(settings.response_body_mime_types)
    status_engine = _on_off(settings.status_engine)

    return f"""# -- Rule engine initialization ----------------------------------------------
SecRuleEngine {settings.rule_engine}

# -- Request body handling ---------------------------------------------------
SecRequestBodyAccess {_on_off(settings.request_body_access)}

SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\\+|/)|text/)xml" \\
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

SecRule REQUEST_HEADERS:Content-Type "^application/json" \\
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

SecRequestBodyLimit {settings.request_body_limit}
SecRequestBodyNoFilesLimit {settings.request_body_no_files_limit}

SecRequestBodyLimitAction {settings.request_body_limit_action}

SecRequestBodyJsonDepthLimit {settings.request_body_json_depth_limit}

SecArgumentsLimit {settings.arguments_limit}

SecRule &ARGS "@ge {settings.arguments_limit}" \\
"id:'200007', phase:2,t:none,log,deny,status:400,msg:'Failed to fully parse request body due to large argument count',severity:2"

SecRule REQBODY_ERROR "!@eq 0" \\
"id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{{reqbody_error_msg}}',severity:2"

SecRule MULTIPART_STRICT_ERROR "!@eq 0" \\
"id:'200003',phase:2,t:none,log,deny,status:400, \\
msg:'Multipart request body failed strict validation: \\
PE %{{REQBODY_PROCESSOR_ERROR}}, \\
BQ %{{MULTIPART_BOUNDARY_QUOTED}}, \\
BW %{{MULTIPART_BOUNDARY_WHITESPACE}}, \\
DB %{{MULTIPART_DATA_BEFORE}}, \\
DA %{{MULTIPART_DATA_AFTER}}, \\
HF %{{MULTIPART_HEADER_FOLDING}}, \\
LF %{{MULTIPART_LF_LINE}}, \\
SM %{{MULTIPART_MISSING_SEMICOLON}}, \\
IQ %{{MULTIPART_INVALID_QUOTING}}, \\
IP %{{MULTIPART_INVALID_PART}}, \\
IH %{{MULTIPART_INVALID_HEADER_FOLDING}}, \\
FL %{{MULTIPART_FILE_LIMIT_EXCEEDED}}'"

SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" \\
    "id:'200004',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"

# PCRE Tuning
SecPcreMatchLimit {settings.pcre_match_limit}
SecPcreMatchLimitRecursion {settings.pcre_match_limit_recursion}

SecRule TX:/^MSC_/ "!@streq 0" \\
    "id:'200005',phase:2,t:none,log,deny,msg:'ModSecurity internal error flagged: %{{MATCHED_VAR_NAME}}'"

# -- Response body handling --------------------------------------------------
SecResponseBodyAccess {_on_off(settings.response_body_access)}

SecResponseBodyMimeType {mime_types}

SecResponseBodyLimit {settings.response_body_limit}

SecResponseBodyLimitAction {settings.response_body_limit_action}

# -- Filesystem configuration ------------------------------------------------
SecTmpDir {settings.tmp_dir}
SecDataDir {settings.data_dir}

# -- Audit log configuration -------------------------------------------------
SecAuditEngine {settings.audit_engine}
SecAuditLogRelevantStatus "{settings.audit_log_relevant_status}"

SecAuditLogParts {settings.audit_log_parts}

SecAuditLogType {settings.audit_log_type}
SecAuditLogFormat {settings.audit_log_format}
SecAuditLog {settings.audit_log_path}

# -- Miscellaneous -----------------------------------------------------------
SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile unicode.mapping 20127
SecStatusEngine {status_engine}
"""


def get_modsecurity_settings() -> ModSecuritySettings:
    if MODSECURITY_CONFIG_FILE.exists():
        content = MODSECURITY_CONFIG_FILE.read_text()
        return parse_modsecurity_config(content)
    return ModSecuritySettings()


def save_modsecurity_settings(settings: ModSecuritySettings) -> Path:
    MODSECURITY_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    content = generate_modsecurity_config(settings)
    MODSECURITY_CONFIG_FILE.write_text(content)
    return MODSECURITY_CONFIG_FILE
