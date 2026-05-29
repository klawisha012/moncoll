"""Unit tests for connection-aware CrowdSec service."""

import pytest
from backend.src.crowdsec import service as crowdsec_service
from backend.src.crowdsec.schemas import CrowdSecStatus, DecisionItem


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
