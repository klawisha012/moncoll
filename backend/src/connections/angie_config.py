"""Render Angie server-block configuration for a connection.

Two states are emitted depending on `status`:

  - pending_dns / pending_verification / provisioning_cert  →  HTTP-only block,
    serves ACME challenges on /.well-known/acme-challenge/, proxies the rest
    over HTTPS to origin (so the site already works while we wait for cert).

  - active  →  port-80 redirect block + port-443 TLS block with full WAF
    coverage (ModSecurity, compression, HSTS, blocked-IP includes).

The render functions are pure: they take a row dict (no DB / IO) and return
a string. _write_nginx_config is the only side-effecting wrapper.

See spec §6 (Angie config — two states) and §7.1 (token bindings).
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

CONNECTIONS_DIR = Path("/var/lib/angie")
CONNECTIONS_D_DIR = CONNECTIONS_DIR / "http.d"
ACME_TRUSTED_CA = "/etc/ssl/certs/ca-certificates.crt"

_VALID_HTTP_VERSIONS = ("h1", "h2", "h3")
_VALID_COMPRESSION = ("auto", "gzip", "brotli", "zstd", "none")


def _ensure_dirs() -> None:
    CONNECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    CONNECTIONS_D_DIR.mkdir(parents=True, exist_ok=True)


def _conn_dir(conn_id: int) -> Path:
    return CONNECTIONS_D_DIR / f"conn_{conn_id}"


def _acme_dir(conn_id: int) -> Path:
    # Must match certificates.service.trigger_acme_request webroot:
    #   /var/lib/angie/http.d/conn_<id>/site  (host volume mount)
    # → /etc/angie/http.d/conn_<id>/site      (Angie container view)
    # certbot writes /.well-known/acme-challenge/<token> under this root,
    # so the Angie location block has to use the same root or HTTP-01 fails.
    return _conn_dir(conn_id) / "site"


def _parse_http_versions(value: str | None) -> list[str]:
    if not value:
        return ["h1", "h2"]
    out: list[str] = []
    seen: set[str] = set()
    for tok in value.split(","):
        t = tok.strip().lower()
        if t in _VALID_HTTP_VERSIONS and t not in seen:
            seen.add(t)
            out.append(t)
    return out or ["h1", "h2"]


def _norm_compression(value: str | None) -> str:
    v = (value or "auto").strip().lower()
    return v if v in _VALID_COMPRESSION else "auto"


def _emit_compression_overrides(algo: str) -> list[str]:
    if algo == "auto":
        return []
    if algo == "none":
        return [
            "    # compression_algo=none — disable all encoders",
            "    gzip off;",
            "    brotli off;",
            "    zstd off;",
        ]
    others = [a for a in ("gzip", "brotli", "zstd") if a != algo]
    out = [f"    # compression_algo={algo} — pin encoder, disable others", f"    {algo} on;"]
    out.extend(f"    {o} off;" for o in others)
    return out


def _emit_upstream(conn_id: int, origin_hosts: list[str], origin_port: int) -> list[str]:
    """Build `upstream conn_<id>_origin { server X:port; ... }` block."""
    if not origin_hosts:
        # Should be unreachable — service.py rejects rows with empty origin_hosts.
        # Emit a deliberately-broken upstream so Angie config-test fails loudly
        # rather than silently passing with no backend.
        return [f"upstream conn_{conn_id}_origin {{ server 127.0.0.1:1 down; }}"]
    lines = [f"upstream conn_{conn_id}_origin {{"]
    for ip in origin_hosts:
        lines.append(f"    server {ip}:{origin_port} max_fails=3 fail_timeout=30s;")
    lines.append("    keepalive 16;")
    lines.append("}")
    return lines


def _emit_proxy_block(conn_id: int, domain: str, tls_mode: str) -> list[str]:
    """Common reverse-proxy directives. Always HTTPS to origin (Full TLS).

    `tls_mode='strict'` verifies the origin certificate against the system
    CA bundle; `'lenient'` skips verification but keeps the channel encrypted
    (Cloudflare's 'Full' tier).
    """
    verify = "on" if tls_mode == "strict" else "off"
    lines = [
        f"        proxy_pass                       https://conn_{conn_id}_origin;",
        "        proxy_ssl_server_name            on;",
        f"        proxy_ssl_name                   {domain};",
        f"        proxy_ssl_verify                 {verify};",
    ]
    if tls_mode == "strict":
        lines.append(f"        proxy_ssl_trusted_certificate    {ACME_TRUSTED_CA};")
    lines.extend(
        [
            f"        proxy_set_header Host            {domain};",
            "        proxy_set_header X-Real-IP       $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Upgrade         $http_upgrade;",
            "        proxy_set_header Connection      $connection_upgrade;",
            "        proxy_buffering off;",
            "        proxy_request_buffering off;",
            "        proxy_redirect off;",
            "        proxy_read_timeout 3600s;",
            "        proxy_send_timeout 3600s;",
        ]
    )
    return lines


def render(conn: dict) -> str:
    """Render the full Angie config for *conn*. Pure function — no IO."""
    conn_id = conn["id"]
    domain = conn["domain"]
    origin_hosts = conn.get("origin_hosts") or []
    origin_port = int(conn.get("origin_port") or 443)
    status = conn.get("status", "pending_verification")
    tls_mode = conn.get("origin_tls_mode") or "strict"
    http_versions = _parse_http_versions(conn.get("http_versions"))
    compression = _norm_compression(conn.get("compression_algo"))
    cert_path = conn.get("ssl_cert_path")
    key_path = conn.get("ssl_key_path")
    has_cert = bool(cert_path and key_path) and status == "active"
    # HSTS pins the domain to HTTPS for a year. Emitting it alongside a
    # self-signed cert is a foot-gun: the browser caches HSTS, then refuses
    # to bypass the cert warning on subsequent visits even though there's
    # nothing wrong with the site. Only safe to send when the cert chains
    # to a trusted root — i.e. when ACME succeeded.
    is_self_signed = "self-signed" in (conn.get("status_detail") or "").lower()
    emit_hsts = has_cert and not is_self_signed

    lines: list[str] = []
    lines.append(f"## conn_{conn_id}: {conn.get('name', '')} | {domain} | status={status}")
    lines.append(f"## origin={','.join(origin_hosts)}:{origin_port} | tls={tls_mode}")
    lines.append(f"## Generated at: {datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.extend(_emit_upstream(conn_id, origin_hosts, origin_port))
    lines.append("")

    blocked_ips_include = f"    include http.d/conn_{conn_id}/blocked_ips.conf;"
    acme_root = f"/etc/angie/http.d/conn_{conn_id}/site"
    proxy_block = _emit_proxy_block(conn_id, domain, tls_mode)

    # ── Plain HTTP server block (always emitted; ACME + either proxy or redirect) ──
    lines.append("server {")
    lines.append("    listen 80;")
    lines.append(f"    server_name {domain};")
    lines.append("")
    lines.append("    access_log /var/log/angie/geoip.log with_geoip_json;")
    lines.append("    access_log /var/log/angie/access.log combined;")
    lines.append("")
    lines.append(blocked_ips_include)
    lines.append("")
    lines.append("    location ^~ /.well-known/acme-challenge/ {")
    lines.append(f"        root {acme_root};")
    lines.append("        try_files $uri =404;")
    lines.append("    }")
    lines.append("")
    if has_cert:
        # Active: port 80 only serves ACME + redirects everything else.
        lines.append("    location / {")
        lines.append("        return 301 https://$host$request_uri;")
        lines.append("    }")
    else:
        # Pre-active: HTTP-only proxy so traffic flows immediately after DNS flip.
        lines.append("    modsecurity on;")
        lines.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")
        lines.append("")
        lines.append("    location /socket.io/ {")
        lines.append("        modsecurity off;")
        lines.extend(proxy_block)
        lines.append("    }")
        lines.append("")
        lines.append("    location / {")
        lines.extend(proxy_block)
        lines.append("    }")
    lines.append("}")

    # ── TLS server block (active only) ──
    if has_cert:
        lines.append("")
        lines.append("server {")
        if "h1" in http_versions:
            lines.append("    listen 443 ssl;")
        else:
            lines.append("    listen 443 ssl;")
        if "h2" in http_versions:
            lines.append("    http2 on;")
        if "h3" in http_versions:
            lines.append("    listen 443 quic;")
            lines.append("    http3 on;")
            lines.append("    add_header Alt-Svc 'h3=\":443\"; ma=86400' always;")
        lines.append(f"    server_name {domain};")
        lines.append(f"    ssl_certificate     {cert_path};")
        lines.append(f"    ssl_certificate_key {key_path};")
        if emit_hsts:
            lines.append(
                '    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
            )
        else:
            lines.append(
                "    # HSTS suppressed: cert is self-signed; emitting it would lock browsers out."
            )
        lines.append("")
        lines.append("    access_log /var/log/angie/geoip.log with_geoip_json;")
        lines.append("    access_log /var/log/angie/access.log combined;")
        lines.append(blocked_ips_include)
        lines.append("")
        lines.append("    modsecurity on;")
        lines.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")
        comp = _emit_compression_overrides(compression)
        if comp:
            lines.append("")
            lines.extend(comp)
        lines.append("")
        lines.append("    location /socket.io/ {")
        lines.append("        modsecurity off;")
        lines.extend(proxy_block)
        lines.append("    }")
        lines.append("")
        lines.append("    location / {")
        lines.extend(proxy_block)
        lines.append("    }")
        lines.append("}")

    return "\n".join(lines) + "\n"


def write_config(conn: dict) -> None:
    """Write conf + ensure on-disk skeleton (acme dir + blocked_ips stub)."""
    _ensure_dirs()
    conn_id = conn["id"]
    conn_dir = _conn_dir(conn_id)
    conn_dir.mkdir(parents=True, exist_ok=True)
    _acme_dir(conn_id).mkdir(parents=True, exist_ok=True)
    (conn_dir / f"{conn_id}.conf").write_text(render(conn))
    blocked = conn_dir / "blocked_ips.conf"
    if not blocked.exists():
        blocked.write_text("# Auto-generated — blocked IPs for this connection\n")


def delete_config(conn_id: int) -> None:
    conn_dir = _conn_dir(conn_id)
    if conn_dir.exists():
        shutil.rmtree(conn_dir, ignore_errors=True)
