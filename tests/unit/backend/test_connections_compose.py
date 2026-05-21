"""Unit tests for the docker_compose source-type helpers in connections.service.

We exercise the pure helpers (compose YAML port detection, proxy-body
generation) without spinning up real containers or hitting the DB.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from src.connections import service as cs
from src.connections.schemas import ConnectionUpdate


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


def test_proxy_body_emits_websocket_upgrade_headers():
    # Regression: without these headers Socket.IO / SSE / raw WS hang at the
    # proxy. Uptime Kuma's /dashboard surfaced this as
    # "Lost connection to the socket server. Reconnecting…".
    conn = {
        "id": 1,
        "source_type": "container",
        "backend_url": "app:3001",
        "preserve_host": True,
    }
    body = cs._build_server_body(conn)
    joined = "\n".join(body)
    assert "proxy_http_version 1.1;" in joined
    assert "proxy_set_header Upgrade $http_upgrade;" in joined
    assert "proxy_set_header Connection $connection_upgrade;" in joined
    # The old "Connection ''" line must not coexist — it would clobber the
    # upgrade header for non-WS traffic and was the original bug.
    assert "proxy_set_header Connection '';" not in joined


def test_proxy_body_carves_out_socket_io_from_modsecurity():
    # Regression: OWASP CRS rule 949110 (anomaly score >= 5) was returning
    # 403 on POST /socket.io/ polling frames from Uptime Kuma, blocking the
    # browser session. The `/socket.io/` location must exist before
    # `location /` (so it wins the longest-prefix match) AND must contain
    # `modsecurity off;` AND must still emit the WS upgrade headers.
    conn = {
        "id": 1,
        "source_type": "container",
        "backend_url": "app:3001",
        "preserve_host": True,
    }
    body = cs._build_server_body(conn)
    joined = "\n".join(body)
    assert "location /socket.io/ {" in joined
    socketio_idx = joined.index("location /socket.io/ {")
    root_idx = joined.index("location / {")
    assert socketio_idx < root_idx, "socket.io location must precede location /"
    # The Socket.IO block needs both the modsec bypass and full proxy setup.
    socketio_block = joined[socketio_idx:root_idx]
    assert "modsecurity off;" in socketio_block
    assert "proxy_pass http://app:3001;" in socketio_block
    assert "proxy_set_header Upgrade $http_upgrade;" in socketio_block


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


# ── compose YAML deny-list (host-escalation patterns) ──────


def test_validate_compose_yaml_accepts_benign():
    yaml = """services:
  app:
    image: nginx:alpine
    expose:
      - "80"
    environment:
      FOO: bar
"""
    assert cs._validate_compose_yaml(yaml) is None


def test_validate_compose_yaml_rejects_privileged():
    yaml = """services:
  pwn:
    image: alpine
    privileged: true
"""
    err = cs._validate_compose_yaml(yaml)
    assert err is not None and "privileged" in err.lower()


def test_validate_compose_yaml_rejects_docker_sock_mount():
    yaml = """services:
  pwn:
    image: alpine
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
    err = cs._validate_compose_yaml(yaml)
    assert err is not None
    assert (
        "docker.sock" in err
        or "host-mount" in err.lower()
        or "host-escalation" in err.lower()
    )


def test_validate_compose_yaml_rejects_root_mount():
    yaml = """services:
  pwn:
    image: alpine
    volumes:
      - /:/host
"""
    err = cs._validate_compose_yaml(yaml)
    assert err is not None


def test_validate_compose_yaml_rejects_host_pid():
    yaml = """services:
  pwn:
    image: alpine
    pid: host
"""
    err = cs._validate_compose_yaml(yaml)
    assert err is not None


def test_validate_compose_yaml_rejects_host_network():
    yaml = """services:
  pwn:
    image: alpine
    network_mode: host
"""
    err = cs._validate_compose_yaml(yaml)
    assert err is not None


def test_validate_compose_yaml_rejects_cap_add():
    yaml = """services:
  pwn:
    image: alpine
    cap_add:
      - SYS_ADMIN
"""
    err = cs._validate_compose_yaml(yaml)
    assert err is not None


def test_validate_compose_yaml_rejects_etc_mount():
    yaml = """services:
  pwn:
    image: alpine
    volumes:
      - /etc:/host_etc
"""
    err = cs._validate_compose_yaml(yaml)
    assert err is not None


def test_validate_compose_yaml_empty_is_ok():
    assert cs._validate_compose_yaml("") is None
    assert cs._validate_compose_yaml(None) is None  # type: ignore[arg-type]


# ── update_connection: source prep gated on enabled ──────────


def _fake_row(**overrides):
    """Build a stand-in ConnectionModel with the attributes the service touches."""
    base = dict(
        id=42,
        name="mode4-umami",
        domains=["zwarder.ru"],
        source_type="docker_compose",
        nginx_config_path=None,
        backend_url="umami:3000",
        static_dir=None,
        compose_yaml="services:\n  umami:\n    image: ghcr.io/umami-software/umami\n",
        compose_service="umami",
        compose_port=3000,
        http_versions="h1,h2",
        compression_algo="auto",
        enabled=True,
        ssl_enabled=False,
        ssl_cert_path=None,
        ssl_key_path=None,
        preserve_host=True,
        custom_nginx_config=None,
        created_at=datetime(2026, 5, 21, 4, 0, 0),
        updated_at=datetime(2026, 5, 21, 4, 0, 0),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


async def _run_update(row, update_payload):
    """Drive cs.update_connection against a mocked session.

    Returns the captured set of helper calls (_prepare_source / _delete_nginx_config
    / _write_nginx_config) so callers can assert which path the service took.
    """
    session = MagicMock()
    session.get = AsyncMock(return_value=row)
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with (
        patch.object(cs, "_ensure_dirs"),
        patch.object(cs, "_prepare_source", return_value=False) as prep,
        patch.object(cs, "_generate_certs_and_update_connection", new=AsyncMock()) as gen,
        patch.object(cs, "_write_nginx_config") as write_cfg,
        patch.object(cs, "_delete_nginx_config") as del_cfg,
        patch.object(cs, "_reload_angie") as reload_angie,
    ):
        result = await cs.update_connection(session, row.id, update_payload)
    return result, {
        "prepare_source": prep,
        "generate_certs": gen,
        "write_nginx_config": write_cfg,
        "delete_nginx_config": del_cfg,
        "reload_angie": reload_angie,
    }


async def test_update_disabling_compose_skips_prepare_source():
    """Regression: toggling enabled=False used to call _bring_up_compose via
    _prepare_source and crash with PermissionError on mkdir(/var/lib/waf/...),
    surfacing in the UI as "Failed to toggle connection".
    """
    row = _fake_row(enabled=True)
    _, calls = await _run_update(row, ConnectionUpdate(enabled=False))

    assert row.enabled is False
    calls["prepare_source"].assert_not_called()
    calls["delete_nginx_config"].assert_called_once_with(42)
    calls["write_nginx_config"].assert_not_called()
    calls["generate_certs"].assert_not_awaited()
    calls["reload_angie"].assert_called_once()


async def test_update_enabling_compose_runs_prepare_source():
    """Inverse direction: toggling enabled=True must prepare the source
    (which for docker_compose brings up the stack) before writing the config.
    """
    row = _fake_row(enabled=False)
    _, calls = await _run_update(row, ConnectionUpdate(enabled=True))

    assert row.enabled is True
    calls["prepare_source"].assert_called_once_with(row)
    # row has domains, so the cert-generating path is taken (not the bare write).
    calls["generate_certs"].assert_awaited_once()
    calls["delete_nginx_config"].assert_not_called()
    calls["reload_angie"].assert_called_once()
