"""Unit tests for connection-aware CrowdSec service."""

import pytest
from backend.src.crowdsec import service as crowdsec_service
from backend.src.crowdsec.schemas import CrowdSecStatus, DecisionItem


class _FakeContainer:
    def exec_run(self, *args, **kwargs):
        return (0, b"")


class _FakeContainers:
    def get(self, name):
        return _FakeContainer()


class _FakeClient:
    containers = _FakeContainers()


class _FakeDocker:
    @staticmethod
    def from_env():
        return _FakeClient()


def test_get_status_without_connection_id(monkeypatch):
    """Assert overall status returns count of all decisions."""
    monkeypatch.setattr(crowdsec_service, "_run_cscli", lambda args: (0, "CrowdSec version: v1.0.0", ""))
    
    decisions_mock = [
        {
            "id": 1,
            "source": {"value": "192.168.1.1"},
            "decisions": [{"id": 10, "origin": "cscli", "scope": "Ip", "value": "192.168.1.1", "type": "ban", "duration": "4h"}]
        },
        {
            "id": 2,
            "source": {"value": "192.168.1.2"},
            "decisions": [{"id": 11, "origin": "cscli", "scope": "Ip", "value": "192.168.1.2", "type": "ban", "duration": "4h"}]
        }
    ]
    
    def mock_run_json(args):
        if "decisions" in args:
            return decisions_mock
        elif "scenarios" in args:
            return []
        elif "alerts" in args:
            return []
        return {}

    monkeypatch.setattr(crowdsec_service, "_run_cscli_json", mock_run_json)
    
    status = crowdsec_service.get_status()
    assert status.running is True
    assert "v1.0.0" in status.version
    assert status.decisions_count == 2


def test_get_status_with_connection_id(monkeypatch):
    """Assert status counts only decisions targeting specified connection_id."""
    monkeypatch.setattr(crowdsec_service, "_run_cscli", lambda args: (0, "CrowdSec version: v1.0.0", ""))
    
    decisions_mock = [
        {
            "id": 1,
            "source": {"value": "192.168.1.1"},
            "decisions": [{"id": 10, "origin": "cscli", "scope": "Ip", "value": "192.168.1.1", "type": "ban", "duration": "4h"}]
        },
        {
            "id": 2,
            "source": {"value": "192.168.1.2"},
            "decisions": [{"id": 11, "origin": "cscli", "scope": "Ip", "value": "192.168.1.2", "type": "ban", "duration": "4h"}]
        }
    ]
    
    def mock_run_json(args):
        if "decisions" in args:
            return decisions_mock
        return []

    monkeypatch.setattr(crowdsec_service, "_run_cscli_json", mock_run_json)
    monkeypatch.setattr(crowdsec_service, "_load_connection_ids", lambda: [1, 2])
    monkeypatch.setattr(crowdsec_service, "_load_blocked_ips_mapping", lambda: {"192.168.1.1": [1]})
    monkeypatch.setattr(crowdsec_service, "_extract_target_hosts_from_alerts", lambda alerts: {"192.168.1.2": {"site2.com"}})
    monkeypatch.setattr(crowdsec_service, "_build_domain_to_conn_map", lambda: {"site2.com": 2})
    
    # 192.168.1.1 is blocked on connection 1 (manual mapping)
    # 192.168.1.2 is blocked on connection 2 (via host mapping)
    
    status_conn_1 = crowdsec_service.get_status(connection_id=1)
    assert status_conn_1.decisions_count == 1
    
    status_conn_2 = crowdsec_service.get_status(connection_id=2)
    assert status_conn_2.decisions_count == 1
    
    status_conn_3 = crowdsec_service.get_status(connection_id=3)
    assert status_conn_3.decisions_count == 0


def test_get_decisions_with_connection_id(monkeypatch):
    """Assert active decisions list is filtered by connection_id."""
    decisions_mock = [
        {
            "id": 1,
            "source": {"value": "192.168.1.1"},
            "decisions": [{"id": 10, "origin": "cscli", "scope": "Ip", "value": "192.168.1.1", "type": "ban", "duration": "4h"}]
        },
        {
            "id": 2,
            "source": {"value": "192.168.1.2"},
            "decisions": [{"id": 11, "origin": "cscli", "scope": "Ip", "value": "192.168.1.2", "type": "ban", "duration": "4h"}]
        }
    ]
    
    monkeypatch.setattr(crowdsec_service, "_run_cscli_json", lambda args: decisions_mock)
    monkeypatch.setattr(crowdsec_service, "_load_connection_ids", lambda: [1, 2])
    monkeypatch.setattr(crowdsec_service, "_load_blocked_ips_mapping", lambda: {"192.168.1.1": [1]})
    monkeypatch.setattr(crowdsec_service, "_extract_target_hosts_from_alerts", lambda alerts: {"192.168.1.2": {"site2.com"}})
    monkeypatch.setattr(crowdsec_service, "_build_domain_to_conn_map", lambda: {"site2.com": 2})
    monkeypatch.setattr(crowdsec_service, "_load_connections", lambda: [
        {"id": 1, "name": "site1"},
        {"id": 2, "name": "site2"}
    ])
    
    decisions_conn_1 = crowdsec_service.get_decisions(connection_id=1)
    assert len(decisions_conn_1) == 1
    assert decisions_conn_1[0].value == "192.168.1.1"
    
    decisions_conn_2 = crowdsec_service.get_decisions(connection_id=2)
    assert len(decisions_conn_2) == 1
    assert decisions_conn_2[0].value == "192.168.1.2"
    
    decisions_conn_3 = crowdsec_service.get_decisions(connection_id=3)
    assert len(decisions_conn_3) == 0


def _setup_sync(monkeypatch, tmp_path, banned_ip, mapping, connections):
    """Wire _sync_blocked_ips_conf against a temp tenants tree + fake docker."""
    monkeypatch.setattr(crowdsec_service, "TENANTS_BASE", str(tmp_path))
    monkeypatch.setattr(crowdsec_service, "docker", _FakeDocker)
    monkeypatch.setattr(
        crowdsec_service,
        "_run_cscli_json",
        lambda args: [
            {
                "source": {"value": banned_ip},
                "meta": [],
                "decisions": [{"type": "ban", "value": banned_ip}],
            }
        ],
    )
    monkeypatch.setattr(crowdsec_service, "_load_connections", lambda: connections)
    monkeypatch.setattr(crowdsec_service, "_load_blocked_ips_mapping", lambda: mapping)
    monkeypatch.setattr(crowdsec_service, "_extract_target_hosts_from_alerts", lambda alerts: {})
    # Materialize the per-connection config dirs Angie would include.
    for c in connections:
        (tmp_path / str(c["tenant_id"]) / "compose" / f"conn_{c['id']}").mkdir(parents=True)


def test_sync_scopes_ban_to_single_connection(monkeypatch, tmp_path):
    """A ban mapped to one connection must land ONLY in that connection's file,
    written to the tenants tree Angie actually includes — never on all domains."""
    connections = [
        {"id": 5, "tenant_id": 1, "name": "site1", "domain": "test1.zwarder.ru", "enabled": True},
        {"id": 6, "tenant_id": 1, "name": "site2", "domain": "test2.zwarder.ru", "enabled": True},
    ]
    _setup_sync(monkeypatch, tmp_path, "198.51.100.96", {"198.51.100.96": [5]}, connections)

    crowdsec_service._sync_blocked_ips_conf()

    conn5 = (tmp_path / "1" / "compose" / "conn_5" / "blocked_ips.conf").read_text()
    conn6 = (tmp_path / "1" / "compose" / "conn_6" / "blocked_ips.conf").read_text()
    assert "deny 198.51.100.96;" in conn5
    assert "deny 198.51.100.96;" not in conn6


def test_sync_writes_no_global_list(monkeypatch, tmp_path):
    """The legacy global blocked_ips.list must not be produced anymore."""
    connections = [
        {"id": 5, "tenant_id": 1, "name": "site1", "domain": "test1.zwarder.ru", "enabled": True},
    ]
    _setup_sync(monkeypatch, tmp_path, "203.0.113.7", {"203.0.113.7": [5]}, connections)

    crowdsec_service._sync_blocked_ips_conf()

    assert not (tmp_path / "blocked_ips.list").exists()
    assert not list(tmp_path.glob("**/blocked_ips.list"))


def test_write_connections_registry_roundtrip(monkeypatch, tmp_path):
    """Registry materialization persists tenant_id + domain and is reloadable."""
    registry = tmp_path / "connections.json"
    monkeypatch.setattr(crowdsec_service, "CONNECTIONS_JSON", str(registry))
    crowdsec_service._write_connections_registry(
        [{"id": 5, "tenant_id": 1, "name": "s1", "domain": "a.example", "enabled": True}]
    )
    loaded = crowdsec_service._load_connections()
    assert loaded[0]["tenant_id"] == 1
    assert "a.example" in crowdsec_service._conn_domains(loaded[0])
    assert crowdsec_service._build_conn_tenant_map() == {5: 1}
