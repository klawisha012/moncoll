import re
from pathlib import Path


class ConfigNotFoundError(Exception):
    pass


class InvalidRuleError(Exception):
    pass


class ModSecurityConfigError(Exception):
    pass


MODSECURITY_CONFIG_DIR = Path("/app/etc/angie/modsecurity")
MODSECURITY_CONFIG_FILE = MODSECURITY_CONFIG_DIR / "modsecurity.conf"
MODSECURITY_RULES_FILE = MODSECURITY_CONFIG_DIR / "rules.conf"


class ConfigService:
    def get_config(self) -> tuple[str, Path]:
        if MODSECURITY_CONFIG_FILE.exists():
            return MODSECURITY_CONFIG_FILE.read_text(), MODSECURITY_CONFIG_FILE
        raise ConfigNotFoundError("modsecurity.conf not found")

    def get_rules(self) -> tuple[str, Path]:
        if MODSECURITY_RULES_FILE.exists():
            return MODSECURITY_RULES_FILE.read_text(), MODSECURITY_RULES_FILE
        raise ConfigNotFoundError("rules.conf not found")

    def update_config(self, content: str) -> Path:
        MODSECURITY_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        MODSECURITY_CONFIG_FILE.write_text(content)
        return MODSECURITY_CONFIG_FILE

    def update_rules(self, content: str) -> Path:
        MODSECURITY_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
        MODSECURITY_RULES_FILE.write_text(content)
        return MODSECURITY_RULES_FILE

    def add_rule(self, rule: str) -> tuple[int, Path]:
        content, _ = self.get_rules()

        rule_id_match = re.search(r"id:(\d+)", rule)
        if not rule_id_match:
            raise InvalidRuleError("Rule must contain an id")

        rule_id = int(rule_id_match.group(1))
        new_content = content.rstrip() + "\n" + rule + "\n"

        self.update_rules(new_content)
        return rule_id, MODSECURITY_RULES_FILE

    def delete_rule(self, rule_id: int) -> bool:
        content, _ = self.get_rules()

        rule_pattern = re.compile(rf"^.*id:{rule_id}[,\s].*$", re.MULTILINE)
        new_content = rule_pattern.sub("", content)

        if content == new_content:
            return False

        self.update_rules(new_content)
        return True

    def list_rules(self) -> list[dict]:
        content, _ = self.get_rules()
        rules = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("Include"):
                continue
            rule_id_match = re.search(r"id:'?(\d+)'?", stripped)
            if rule_id_match:
                rule_id = int(rule_id_match.group(1))
                msg_match = re.search(r"msg:'([^']*)'", stripped)
                msg = msg_match.group(1) if msg_match else ""
                phase_match = re.search(r"phase:(\d+)", stripped)
                phase = int(phase_match.group(1)) if phase_match else None
                action_match = re.search(r"(deny|pass|drop|redirect|proxy)", stripped)
                action = action_match.group(1) if action_match else "pass"
                severity_match = re.search(r"severity:'?(\d+)'?", stripped)
                severity = int(severity_match.group(1)) if severity_match else None
                rules.append(
                    {
                        "id": rule_id,
                        "rule": stripped,
                        "message": msg,
                        "phase": phase,
                        "action": action,
                        "severity": severity,
                    }
                )
        return rules


config_service = ConfigService()
