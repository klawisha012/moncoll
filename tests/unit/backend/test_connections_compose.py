"""Unit tests for the docker_compose source-type helpers in connections.service.

We exercise the pure helpers (compose YAML port detection, proxy-body
generation) without spinning up real containers or hitting the DB.
"""
from __future__ import annotations

from src.connections import service as cs


# ── compose port detection ──────────────────────────────────


def test_detect_compose_port_from_expose():
    yaml = """services:
  app:
    image: nginx:alpine
    expose:
      - "8080"
"""
    assert cs._detect_compose_service_port(yaml, "app") == 8080


def test_detect_compose_port_from_ports_mapping():
    yaml = """services:
  app:
    image: nginx
    ports:
      - "9000:8080"
"""
    assert cs._detect_compose_service_port(yaml, "app") == 8080


def test_detect_compose_port_missing_service_returns_none():
    yaml = """services:
  other:
    image: nginx
    expose:
      - "80"
"""
    assert cs._detect_compose_service_port(yaml, "missing") is None


def test_detect_compose_port_handles_no_ports():
    yaml = """services:
  app:
    image: nginx
"""
    assert cs._detect_compose_service_port(yaml, "app") is None


# ── proxy body generation should treat docker_compose like container ──


def test_proxy_body_used_for_docker_compose():
    conn = {
        "id": 1,
        "source_type": "docker_compose",
        "backend_url": "myapp:8080",
        "preserve_host": True,
    }
    body = cs._build_server_body(conn)
    joined = "\n".join(body)
    assert "proxy_pass http://myapp:8080;" in joined
    assert "location /" in joined


def test_proxy_body_used_for_container():
    conn = {
        "id": 1,
        "source_type": "container",
        "backend_url": "svc:80",
        "preserve_host": False,
    }
    body = cs._build_server_body(conn)
    joined = "\n".join(body)
    assert "proxy_pass http://svc:80;" in joined
    assert "Host $proxy_host" in joined


def test_normalize_backend_url_adds_scheme():
    assert cs._normalize_backend_url("svc:80") == "http://svc:80"
    assert cs._normalize_backend_url("https://svc:443") == "https://svc:443"
    assert cs._normalize_backend_url("  svc:80  ") == "http://svc:80"
    assert cs._normalize_backend_url("") == ""


# ── compose project naming is stable per connection id ──────


def test_compose_project_name_includes_conn_id():
    assert cs._compose_project_name(7) == "waf_conn_7"


def test_compose_project_dir_is_per_connection():
    d = cs._compose_project_dir(11)
    assert d.name == "conn_11"
    assert d.parent == cs.COMPOSE_PROJECTS_DIR
