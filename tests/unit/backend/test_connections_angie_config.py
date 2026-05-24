"""Unit tests for connections.angie_config.

Pure-function tests — render() takes a dict and returns a string, no IO.
We assert on structural properties of the generated config rather than
brittle full-string snapshots so layout tweaks don't churn the suite.
"""

from __future__ import annotations

import pytest

from src.connections import angie_config as ac


def _base_conn(**overrides) -> dict:
    """Minimal connection dict that renders cleanly."""
    base = {
        "id": 7,
        "tenant_id": 42,
        "name": "acme prod",
        "domain": "acme.com",
        "origin_hosts": ["1.1.1.1"],
        "origin_port": 443,
        "origin_tls_mode": "strict",
        "status": "pending_dns",
        "http_versions": "h1,h2",
        "compression_algo": "auto",
        "ssl_cert_path": None,
        "ssl_key_path": None,
    }
    base.update(overrides)
    return base


# ── State: pending_dns / pending_verification (HTTP only) ────────────────────


def test_pending_dns_emits_only_port_80():
    out = ac.render(_base_conn(status="pending_dns"))
    assert "listen 80;" in out
    assert "listen 443" not in out
    assert "ssl_certificate" not in out


def test_pending_dns_includes_acme_challenge():
    out = ac.render(_base_conn(status="pending_dns"))
    assert "/.well-known/acme-challenge/" in out
    # Webroot must use per-tenant path (Phase 13):
    # /etc/angie/tenants/<tenant_id>/compose/conn_<id>/site
    assert "/etc/angie/tenants/42/compose/conn_7/site" in out


def test_pending_dns_proxies_immediately():
    """Even before cert, port-80 block must proxy traffic so DNS-flip works."""
    out = ac.render(_base_conn(status="pending_dns"))
    assert "proxy_pass" in out
    assert "https://conn_7_origin" in out
    # And it must NOT be a 301 redirect (that would 502 every visitor pre-cert)
    assert "return 301" not in out


# ── State: active (HTTPS) ────────────────────────────────────────────────────


def test_active_emits_both_blocks():
    out = ac.render(
        _base_conn(
            status="active",
            ssl_cert_path="/etc/angie/tenants/42/compose/conn_7/7.crt",
            ssl_key_path="/etc/angie/tenants/42/compose/conn_7/7.key",
        )
    )
    assert "listen 80;" in out
    assert "listen 443 ssl;" in out
    assert "return 301 https://" in out  # port 80 → 443 redirect
    assert "ssl_certificate     /etc/angie/tenants/42/compose/conn_7/7.crt;" in out


def test_active_hsts_header():
    out = ac.render(
        _base_conn(
            status="active",
            ssl_cert_path="/x.crt",
            ssl_key_path="/x.key",
        )
    )
    assert "Strict-Transport-Security" in out


@pytest.mark.parametrize(
    "http_versions,expect_http2,expect_http3",
    [
        ("h1", False, False),
        ("h1,h2", True, False),
        ("h1,h2,h3", True, True),
        ("h2,h3", True, True),
    ],
)
def test_active_listens_per_http_versions(http_versions, expect_http2, expect_http3):
    out = ac.render(
        _base_conn(
            status="active",
            ssl_cert_path="/x.crt",
            ssl_key_path="/x.key",
            http_versions=http_versions,
        )
    )
    assert ("http2 on;" in out) is expect_http2
    assert ("http3 on;" in out) is expect_http3
    if expect_http3:
        assert "listen 443 quic;" in out
        assert "Alt-Svc" in out


# ── Upstream ─────────────────────────────────────────────────────────────────


def test_upstream_pools_multiple_a_records():
    out = ac.render(_base_conn(origin_hosts=["1.1.1.1", "1.0.0.1", "8.8.8.8"]))
    assert "upstream conn_7_origin {" in out
    assert "server 1.1.1.1:443 max_fails=3 fail_timeout=30s;" in out
    assert "server 1.0.0.1:443 max_fails=3 fail_timeout=30s;" in out
    assert "server 8.8.8.8:443 max_fails=3 fail_timeout=30s;" in out
    assert "keepalive 16;" in out


def test_upstream_empty_origin_is_safe_fail():
    """Empty origin_hosts must produce config that fails Angie's -t test
    rather than silently passing with no backend."""
    out = ac.render(_base_conn(origin_hosts=[]))
    # The safety sentinel uses 127.0.0.1:1 with `down;` so Angie config-test
    # catches it before any traffic gets routed.
    assert "127.0.0.1:1 down" in out


# ── TLS mode ─────────────────────────────────────────────────────────────────


def test_strict_tls_verifies_origin_cert():
    out = ac.render(_base_conn(origin_tls_mode="strict"))
    assert "proxy_ssl_verify                 on;" in out
    assert "proxy_ssl_trusted_certificate" in out


def test_lenient_tls_skips_verify_keeps_encryption():
    out = ac.render(_base_conn(origin_tls_mode="lenient"))
    assert "proxy_ssl_verify                 off;" in out
    # Still HTTPS — lenient ≠ HTTP
    assert "https://conn_7_origin" in out


# ── Compression ──────────────────────────────────────────────────────────────


def test_compression_auto_emits_nothing():
    out = ac.render(
        _base_conn(
            status="active",
            ssl_cert_path="/x.crt",
            ssl_key_path="/x.key",
            compression_algo="auto",
        )
    )
    # 'auto' relies on the global angie.conf negotiation — no per-server overrides.
    assert "gzip on;" not in out
    assert "brotli on;" not in out
    assert "zstd on;" not in out


def test_compression_pin_disables_others():
    out = ac.render(
        _base_conn(
            status="active",
            ssl_cert_path="/x.crt",
            ssl_key_path="/x.key",
            compression_algo="brotli",
        )
    )
    assert "brotli on;" in out
    assert "gzip off;" in out
    assert "zstd off;" in out


def test_compression_none_disables_all():
    out = ac.render(
        _base_conn(
            status="active",
            ssl_cert_path="/x.crt",
            ssl_key_path="/x.key",
            compression_algo="none",
        )
    )
    assert "gzip off;" in out
    assert "brotli off;" in out
    assert "zstd off;" in out


# ── Header forwarding ────────────────────────────────────────────────────────


def test_websocket_upgrade_headers():
    out = ac.render(_base_conn())
    assert "proxy_set_header Upgrade         $http_upgrade;" in out
    assert "proxy_set_header Connection      $connection_upgrade;" in out


def test_socket_io_bypass_modsecurity():
    out = ac.render(_base_conn())
    # /socket.io/ block must turn ModSecurity off (Socket.IO frames trip CRS).
    assert "location /socket.io/" in out
    socketio_section = out.split("location /socket.io/")[1].split("location /")[0]
    assert "modsecurity off;" in socketio_section


# ── Phase 13: per-tenant path construction ───────────────────────────────────


def test_render_uses_tenant_scoped_paths():
    """All in-config paths must use /etc/angie/tenants/<tid>/compose/..."""
    conn = _base_conn(tenant_id=5, id=3)
    out = ac.render(conn)
    # Blocked IPs include should reference the tenant-scoped dir.
    assert "/etc/angie/tenants/5/compose/conn_3/blocked_ips.conf" in out
    # Must NOT reference old legacy path.
    assert "/etc/angie/http.d/conn_" not in out


def test_render_different_tenants_have_different_paths():
    """Two tenants' configs must have separate include paths."""
    out_a = ac.render(_base_conn(tenant_id=1, id=10))
    out_b = ac.render(_base_conn(tenant_id=2, id=10))
    assert "/etc/angie/tenants/1/compose" in out_a
    assert "/etc/angie/tenants/2/compose" in out_b
    # Tenant A's output must not contain tenant B's path.
    assert "/etc/angie/tenants/2/compose" not in out_a
    assert "/etc/angie/tenants/1/compose" not in out_b


def test_conn_dir_path_construction():
    """_conn_dir returns path under TENANTS_BASE."""
    from pathlib import Path
    d = ac._conn_dir(tenant_id=7, conn_id=42)
    assert d == Path("/var/lib/waf/tenants/7/compose/conn_42")


def test_acme_dir_path_construction():
    from pathlib import Path
    d = ac._acme_dir(tenant_id=7, conn_id=42)
    assert d == Path("/var/lib/waf/tenants/7/compose/conn_42/site")
