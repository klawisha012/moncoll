"""Unit tests for HTTP-version / compression helpers in connections.service.

These cover the pure functions added for the 2026-05 release:

* ``_parse_http_versions``
* ``_normalize_compression_algo``
* ``_emit_listen_directives``
* ``_emit_compression_overrides``
* config generation (listen + Alt-Svc + compression overrides)
* schema validation (``ConnectionCreate.http_versions`` coercion)
"""

from __future__ import annotations

import pytest

from src.connections import service as cs
from src.connections.schemas import ConnectionCreate


# ── _parse_http_versions ────────────────────────────────────


def test_parse_http_versions_default_when_empty():
    assert cs._parse_http_versions(None) == ["h1", "h2"]
    assert cs._parse_http_versions("") == ["h1", "h2"]


def test_parse_http_versions_drops_unknown_tokens():
    assert cs._parse_http_versions("h1,foo,h2,bar") == ["h1", "h2"]


def test_parse_http_versions_dedupes_and_preserves_order():
    assert cs._parse_http_versions("h3,h1,h3,h2") == ["h3", "h1", "h2"]


def test_parse_http_versions_falls_back_when_all_unknown():
    assert cs._parse_http_versions("garbage,nothing") == ["h1", "h2"]


# ── _normalize_compression_algo ─────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, "auto"),
        ("", "auto"),
        ("auto", "auto"),
        ("gzip", "gzip"),
        ("brotli", "brotli"),
        ("zstd", "zstd"),
        ("none", "none"),
        ("  ZSTD  ", "zstd"),
        ("bogus", "auto"),
    ],
)
def test_normalize_compression_algo(raw, expected):
    assert cs._normalize_compression_algo(raw) == expected


# ── _emit_listen_directives ─────────────────────────────────


def test_emit_listen_h1_only_no_ssl():
    plain, tls = cs._emit_listen_directives(http_versions=["h1"], has_ssl=False)
    assert plain == ["    listen 80;"]
    assert tls == []


def test_emit_listen_h1_h2_with_ssl():
    plain, tls = cs._emit_listen_directives(http_versions=["h1", "h2"], has_ssl=True)
    assert "    listen 80;" in plain
    assert "    listen 443 ssl;" in tls
    assert "    http2 on;" in tls


def test_emit_listen_h3_emits_quic_and_alt_svc():
    plain, tls = cs._emit_listen_directives(
        http_versions=["h1", "h2", "h3"], has_ssl=True
    )
    # reuseport is intentionally NOT emitted per-connection — it must appear
    # on only one listen directive across the entire angie config, so the
    # global angie.conf owns it (see service.py:_emit_listen_directives).
    assert any("listen 443 quic" in line for line in tls)
    assert not any("reuseport" in line for line in tls)
    assert any("http3 on;" in line for line in tls)
    assert any("Alt-Svc" in line and 'h3=":443"' in line for line in tls)


def test_emit_listen_no_h1_still_emits_tls_when_ssl():
    plain, tls = cs._emit_listen_directives(http_versions=["h2", "h3"], has_ssl=True)
    assert plain == []  # no plain block
    assert "    listen 443 ssl;" in tls


# ── _emit_compression_overrides ─────────────────────────────


def test_compression_auto_emits_no_overrides():
    assert cs._emit_compression_overrides("auto") == []


def test_compression_none_disables_everything():
    out = cs._emit_compression_overrides("none")
    assert "    gzip off;" in out
    assert "    brotli off;" in out
    assert "    zstd off;" in out


@pytest.mark.parametrize("algo", ["gzip", "brotli", "zstd"])
def test_compression_pinned_disables_others(algo):
    out = cs._emit_compression_overrides(algo)
    assert f"    {algo} on;" in out
    for other in ("gzip", "brotli", "zstd"):
        if other != algo:
            assert f"    {other} off;" in out


# ── _generate_nginx_config integration ──────────────────────


def _base_conn(**overrides) -> dict:
    base = {
        "id": 42,
        "name": "test",
        "domains": ["example.com"],
        "source_type": "static_generate",
        "backend_url": "",
        "preserve_host": True,
        "http_versions": "h1,h2",
        "compression_algo": "auto",
        "ssl_cert_path": None,
        "ssl_key_path": None,
        "custom_nginx_config": None,
    }
    base.update(overrides)
    return base


def test_generate_config_plain_h1_only():
    conn = _base_conn(http_versions="h1")
    out = cs._generate_nginx_config(conn)
    assert "listen 80;" in out
    assert "listen 443" not in out
    assert "http3" not in out
    assert "Alt-Svc" not in out


def test_generate_config_h3_emits_quic_when_ssl():
    conn = _base_conn(
        http_versions="h1,h2,h3",
        ssl_cert_path="/x/cert.pem",
        ssl_key_path="/x/key.pem",
    )
    out = cs._generate_nginx_config(conn)
    assert "listen 80;" in out
    assert "listen 443 ssl;" in out
    assert "listen 443 quic;" in out
    assert "reuseport" not in out
    assert "http3 on;" in out
    assert 'h3=":443"' in out


def test_generate_config_compression_pinned_brotli():
    conn = _base_conn(compression_algo="brotli")
    out = cs._generate_nginx_config(conn)
    assert "brotli on;" in out
    assert "gzip off;" in out
    assert "zstd off;" in out


def test_generate_config_compression_auto_emits_nothing_pinned():
    conn = _base_conn(compression_algo="auto")
    out = cs._generate_nginx_config(conn)
    # auto: no per-server override; global angie.conf decides
    assert "brotli off;" not in out
    assert "gzip off;" not in out
    assert "zstd off;" not in out


def test_generate_config_header_records_settings():
    conn = _base_conn(http_versions="h1,h2,h3", compression_algo="zstd")
    out = cs._generate_nginx_config(conn)
    assert "HTTP versions: h1,h2,h3" in out
    assert "compression: zstd" in out


# ── schema validation ────────────────────────────────────────


def test_schema_accepts_list_of_versions():
    c = ConnectionCreate(name="x", http_versions=["h1", "h2"])
    assert c.http_versions == "h1,h2"


def test_schema_normalizes_string_csv_with_whitespace():
    c = ConnectionCreate(name="x", http_versions=" h2 , h3 ")
    assert c.http_versions == "h2,h3"


def test_schema_rejects_unknown_http_version():
    with pytest.raises(ValueError):
        ConnectionCreate(name="x", http_versions=["h1", "h4"])


def test_schema_compression_algo_default_is_auto():
    c = ConnectionCreate(name="x")
    assert c.compression_algo == "auto"


def test_schema_compression_algo_rejects_invalid():
    with pytest.raises(Exception):
        # Pydantic will raise on Literal type mismatch.
        ConnectionCreate(name="x", compression_algo="lzma")  # type: ignore[arg-type]


def test_schema_empty_http_versions_falls_back_to_default():
    c = ConnectionCreate(name="x", http_versions="")
    assert c.http_versions == "h1,h2"
