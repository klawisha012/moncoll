import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from src.modsecurity.service import ConfigService


@pytest.fixture
def config_service():
    return ConfigService()


@pytest.fixture
def sample_rules():
    return """SecRule ARGS "@rx test" "id:1001,phase:2,deny,msg:'Test rule'"
SecRule ARGS "@rx sql" "id:1002,phase:2,deny,msg:'SQL rule'"
Include /etc/angie/modsecurity/crs-setup.conf
"""


class TestConfigService:
    def test_list_rules_parses_correctly(self, config_service, sample_rules, tmp_path):
        rules_file = tmp_path / "rules.conf"
        rules_file.write_text(sample_rules)

        with patch("src.modsecurity.service.MODSECURITY_RULES_FILE", rules_file):
            rules = config_service.list_rules()

        assert len(rules) == 2
        assert rules[0]["id"] == 1001
        assert rules[0]["message"] == "Test rule"
        assert rules[0]["action"] == "deny"
        assert rules[0]["phase"] == 2
        assert rules[1]["id"] == 1002

    def test_list_rules_skips_comments_and_empty_lines(self, config_service, tmp_path):
        content = """# This is a comment
Include /some/path.conf

SecRule ARGS "@rx test" "id:2001,phase:2,deny"
"""
        rules_file = tmp_path / "rules.conf"
        rules_file.write_text(content)

        with patch("src.modsecurity.service.MODSECURITY_RULES_FILE", rules_file):
            rules = config_service.list_rules()

        assert len(rules) == 1
        assert rules[0]["id"] == 2001

    def test_add_rule_requires_id(self, config_service, tmp_path):
        rules_file = tmp_path / "rules.conf"
        rules_file.write_text('SecRule ARGS "@rx test" "phase:2,deny"\n')

        with patch("src.modsecurity.service.MODSECURITY_RULES_FILE", rules_file):
            with pytest.raises(Exception):
                config_service.add_rule('SecRule ARGS "@rx bad" "phase:2,deny"')

    def test_delete_rule_removes_correct_rule(self, config_service, tmp_path):
        content = 'SecRule ARGS "@rx test1" "id:3001,phase:2,deny"\nSecRule ARGS "@rx test2" "id:3002,phase:2,deny"\n'
        rules_file = tmp_path / "rules.conf"
        rules_file.write_text(content)

        with patch("src.modsecurity.service.MODSECURITY_RULES_FILE", rules_file):
            result = config_service.delete_rule(3001)

        assert result is True
        remaining = rules_file.read_text()
        assert "3001" not in remaining
        assert "3002" in remaining

    def test_delete_nonexistent_rule_returns_false(self, config_service, tmp_path):
        content = 'SecRule ARGS "@rx test" "id:4001,phase:2,deny"\n'
        rules_file = tmp_path / "rules.conf"
        rules_file.write_text(content)

        with patch("src.modsecurity.service.MODSECURITY_RULES_FILE", rules_file):
            result = config_service.delete_rule(9999)

        assert result is False

    def test_get_config_not_found(self, config_service, tmp_path):
        missing_file = tmp_path / "nonexistent.conf"

        with patch("src.modsecurity.service.MODSECURITY_CONFIG_FILE", missing_file):
            with pytest.raises(Exception):
                config_service.get_config()

    def test_update_config_creates_file(self, config_service, tmp_path):
        config_file = tmp_path / "new.conf"

        with patch("src.modsecurity.service.MODSECURITY_CONFIG_FILE", config_file):
            config_service.update_config("SecRuleEngine On\n")

        assert config_file.read_text() == "SecRuleEngine On\n"
