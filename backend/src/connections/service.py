import json
import logging
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from .schemas import Connection, ConnectionCreate, ConnectionUpdate
from ..certificates import service as cert_service

logger = logging.getLogger(__name__)

CONNECTIONS_DIR = Path("/var/lib/angie")
CONNECTIONS_FILE = CONNECTIONS_DIR / "connections.json"
CONNECTIONS_D_DIR = CONNECTIONS_DIR / "http.d"

# ── Static site default source (backend container path) ──
DEFAULT_STATIC_SOURCE = Path("/app/site-templates/examples")


def _ensure_dirs():
    """Ensure connections directory and http.d directory exist."""
    CONNECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    CONNECTIONS_D_DIR.mkdir(parents=True, exist_ok=True)


def _load_connections() -> list[dict]:
    """Load connections from JSON file."""
    if not CONNECTIONS_FILE.exists():
        return []
    try:
        content = CONNECTIONS_FILE.read_text()
        data = json.loads(content)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def _save_connections(connections: list[dict]):
    """Save connections list to JSON file."""
    CONNECTIONS_FILE.write_text(json.dumps(connections, indent=2))


def _get_ssl_paths(conn_id: int) -> tuple[str, str]:
    """Get certificate and key paths as seen from inside the Angie container."""
    cert_path = f"/etc/angie/http.d/conn_{conn_id}/{conn_id}.crt"
    key_path = f"/etc/angie/http.d/conn_{conn_id}/{conn_id}.key"
    return cert_path, key_path


def _generate_nginx_config(conn: dict) -> str:
    """Generate Nginx server block configuration for a connection."""
    domains = " ".join(conn["domains"]) if conn["domains"] else "_"
    mode = conn.get("mode", "proxy")
    is_static = mode == "static"

    # Build server block
    lines = []
    lines.append(f"## Connection: {conn['name']} (ID: {conn['id']})")
    lines.append(f"## Mode: {mode}")
    lines.append(f"## Generated at: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    # ── Location block content (proxy or static) ──
    conn_id = conn["id"]

    def _build_location_block(is_ssl: bool = False) -> list[str]:
        """Build the main location / block based on mode."""
        loc_lines = []
        loc_lines.append("    location / {")

        if is_static:
            # Use the copied site inside the connection directory
            static_root = f"/etc/angie/http.d/conn_{conn_id}/site"
            loc_lines.append(f"        root {static_root};")
            loc_lines.append("        index index.html index.htm;")
            loc_lines.append("        try_files $uri $uri/ =404;")
        else:
            backend_url = conn.get("backend_url", "")
            if backend_url and not backend_url.startswith(("http://", "https://")):
                backend_url = f"http://{backend_url}"
            loc_lines.append(f"        proxy_pass {backend_url};")
            if conn.get("preserve_host", True):
                loc_lines.append("        proxy_set_header Host $host;")
            else:
                loc_lines.append("        proxy_set_header Host $proxy_host;")
            loc_lines.append("        proxy_set_header X-Real-IP $remote_addr;")
            loc_lines.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
            loc_lines.append("        proxy_set_header X-Forwarded-Proto $scheme;")
            loc_lines.append("        proxy_http_version 1.1;")
            loc_lines.append("        proxy_set_header Connection '';")
            loc_lines.append("        proxy_buffering off;")
            loc_lines.append("        proxy_request_buffering off;")
            loc_lines.append("        proxy_redirect off;")

        loc_lines.append("    }")
        return loc_lines

    blocked_ips_include = f"    include http.d/conn_{conn_id}/blocked_ips.conf;"

    # ── HTTP server ──
    lines.append("server {")
    lines.append("    listen 80;")
    lines.append(f"    server_name {domains};")
    lines.append("")
    lines.append(blocked_ips_include)
    lines.append("")

    if conn.get("ssl_enabled"):
        lines.append("    location / {")
        lines.append("        return 301 https://$host$request_uri;")
        lines.append("    }")
        lines.append("}")
        lines.append("")

        # ── HTTPS server block ──
        cert_path, key_path = _get_ssl_paths(conn["id"])
        lines.append("server {")
        lines.append("    listen 443 ssl;")
        lines.append(f"    server_name {domains};")
        lines.append("")
        lines.append(blocked_ips_include)
        lines.append("")

        ssl_cert_path = conn.get("ssl_cert_path") or cert_path
        ssl_key_path = conn.get("ssl_key_path") or key_path
        lines.append(f"    ssl_certificate {ssl_cert_path};")
        lines.append(f"    ssl_certificate_key {ssl_key_path};")

        lines.append("")
        lines.append("    # ModSecurity integration")
        lines.append("    modsecurity on;")
        lines.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")
        lines.append("")

        lines.extend(_build_location_block(is_ssl=True))
    else:
        # Non-SSL
        lines.append(blocked_ips_include)
        lines.append("")
        lines.append("    # ModSecurity integration")
        lines.append("    modsecurity on;")
        lines.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")
        lines.append("")

        lines.extend(_build_location_block())

    lines.append("}")

    return "\n".join(lines)


def _conn_dir(conn_id: int) -> Path:
    """Get the connection-specific subdirectory path."""
    return CONNECTIONS_D_DIR / f"conn_{conn_id}"


def _site_dir(conn_id: int) -> Path:
    """Get the static site subdirectory inside the connection directory."""
    return _conn_dir(conn_id) / "site"


def _resolve_static_source(source: str | Path | None) -> Path | None:
    """Resolve *source* to an existing backend-accessible directory.

    Rules (tried in order):
    1. ``None`` or empty → DEFAULT_STATIC_SOURCE
    2. Relative path → resolved against ``/app/site-templates/``
    3. Absolute path that exists → used as-is
    4. Absolute path that does NOT exist → take its leaf name and
       try it relative to ``/app/site-templates/`` (this handles
       legacy Angie-container paths like ``/var/www/examples``).
    5. Fallback → DEFAULT_STATIC_SOURCE
    """
    if not source:
        return _existing_or_none(DEFAULT_STATIC_SOURCE)

    source_path = Path(source)
    if not source_path.is_absolute():
        resolved = DEFAULT_STATIC_SOURCE.parent / source_path
        return _existing_or_none(resolved)

    if source_path.is_dir():
        return source_path

    # Absolute but missing — try the leaf name under site-templates
    leaf = source_path.name
    if leaf:
        resolved = DEFAULT_STATIC_SOURCE.parent / leaf
        if resolved.is_dir():
            logger.info("Mapped legacy static_dir %s → %s", source, resolved)
            return resolved

    logger.warning("Static source %s not found, falling back to %s", source, DEFAULT_STATIC_SOURCE)
    return _existing_or_none(DEFAULT_STATIC_SOURCE)


def _existing_or_none(path: Path) -> Path | None:
    """Return *path* if it exists, otherwise ``None``."""
    return path if path.is_dir() else None


def _copy_static_site(conn_id: int, source: str | Path) -> Path | None:
    """Copy static site files from *source* into http.d/conn_<id>/site/.

    Returns the destination directory path, or ``None`` if the source
    could not be found (in which case any existing site is left untouched).
    """
    source_path = _resolve_static_source(source)
    if source_path is None:
        logger.warning("Cannot copy static site for conn %s: no valid source", conn_id)
        return None

    dest = _site_dir(conn_id)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(source_path, dest)
    logger.info("Copied static site %s → %s", source_path, dest)
    return dest


def _write_nginx_config(conn: dict):
    """Write Nginx config file for a connection."""
    config = _generate_nginx_config(conn)
    conn_dir = _conn_dir(conn["id"])
    conn_dir.mkdir(parents=True, exist_ok=True)
    config_file = conn_dir / f"{conn['id']}.conf"
    config_file.write_text(config)
    # Ensure blocked_ips.conf exists (empty) so Nginx doesn't fail on include
    blocked_ips_file = conn_dir / "blocked_ips.conf"
    if not blocked_ips_file.exists():
        blocked_ips_file.write_text(
            "# Auto-generated by WAF backend — blocked IPs for this connection\n"
        )


def _delete_nginx_config(conn_id: int):
    """Delete Nginx config file, blocked_ips.conf, and static site for a connection."""
    conn_dir = _conn_dir(conn_id)
    config_file = conn_dir / f"{conn_id}.conf"
    if config_file.exists():
        config_file.unlink()
    blocked_ips_file = conn_dir / "blocked_ips.conf"
    if blocked_ips_file.exists():
        blocked_ips_file.unlink()
    # Remove static site
    site_dir = _site_dir(conn_id)
    if site_dir.exists():
        shutil.rmtree(site_dir)
    # Remove connection directory if empty
    _rmdir_if_empty(conn_dir)


def list_connections() -> list[Connection]:
    """List all connections."""
    connections = _load_connections()
    return [Connection(**conn) for conn in connections]


def get_connection(conn_id: int) -> Connection | None:
    """Get a specific connection by ID."""
    connections = _load_connections()
    for conn in connections:
        if conn.get("id") == conn_id:
            return Connection(**conn)
    return None


def _generate_certs_and_update_connection(conn: dict, connections: list[dict]):
    """Generate SSL certificates and persist paths back to the connection JSON."""
    conn_id = conn["id"]
    domains = conn.get("domains", [])
    if not domains:
        return

    result = cert_service.trigger_acme_request(conn_id, domains)
    if result.get("success"):
        cert_path = result.get("certificate_path")
        key_path = result.get("key_path")
        if cert_path and key_path:
            conn["ssl_cert_path"] = cert_path
            conn["ssl_key_path"] = key_path
            conn["updated_at"] = datetime.utcnow().isoformat()
            _save_connections(connections)
            # Regenerate nginx config with the new cert paths
            _write_nginx_config(conn)


def create_connection(conn_in: ConnectionCreate) -> Connection:
    """Create a new connection."""
    _ensure_dirs()
    connections = _load_connections()

    new_id = max([c.get("id", 0) for c in connections] + [0]) + 1

    now = datetime.utcnow()
    new_conn = {
        "id": new_id,
        "name": conn_in.name,
        "domains": conn_in.domains,
        "mode": conn_in.mode,
        "backend_url": conn_in.backend_url,
        "static_dir": conn_in.static_dir,
        "enabled": conn_in.enabled,
        "ssl_enabled": conn_in.ssl_enabled,
        "ssl_cert_path": conn_in.ssl_cert_path,
        "ssl_key_path": conn_in.ssl_key_path,
        "preserve_host": conn_in.preserve_host,
        "custom_nginx_config": conn_in.custom_nginx_config,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    connections.append(new_conn)
    _save_connections(connections)

    # Copy static site content into the connection directory
    if new_conn["mode"] == "static":
        source = new_conn.get("static_dir") or "examples"
        _copy_static_site(new_id, source)

    # Generate Nginx config
    if new_conn["enabled"]:
        # Generate certificates first if SSL is enabled (so nginx config references them)
        if new_conn["ssl_enabled"] and new_conn["domains"]:
            _generate_certs_and_update_connection(new_conn, connections)
        else:
            _write_nginx_config(new_conn)

    return Connection(**new_conn)


def update_connection(conn_id: int, conn_in: ConnectionUpdate) -> Connection | None:
    """Update an existing connection."""
    _ensure_dirs()
    connections = _load_connections()

    for idx, conn in enumerate(connections):
        if conn.get("id") == conn_id:
            # Update fields
            update_data = conn_in.model_dump(exclude_unset=True)
            conn.update(update_data)
            conn["updated_at"] = datetime.utcnow().isoformat()

            _save_connections(connections)

            # Re-copy static site if mode changed to static or static_dir updated
            if conn.get("mode") == "static":
                # Always re-copy on mode=static (idempotent)
                source = conn.get("static_dir") or "examples"
                _copy_static_site(conn_id, source)

            # Regenerate or delete Nginx config based on enabled status
            if conn.get("enabled"):
                # Generate certificates first if SSL is enabled (so nginx config references them)
                if conn.get("ssl_enabled") and conn.get("domains"):
                    _generate_certs_and_update_connection(conn, connections)
                else:
                    _write_nginx_config(conn)
            else:
                _delete_nginx_config(conn_id)

            return Connection(**conn)

    return None


def _delete_ssl_certs(conn_id: int):
    """Delete SSL certificate and key files for a connection."""
    conn_dir = _conn_dir(conn_id)
    cert_file = conn_dir / f"{conn_id}.crt"
    key_file = conn_dir / f"{conn_id}.key"
    if cert_file.exists():
        cert_file.unlink()
    if key_file.exists():
        key_file.unlink()
    # Remove connection directory if empty
    _rmdir_if_empty(conn_dir)


def _rmdir_if_empty(dir_path: Path):
    """Remove a directory if it exists and is empty."""
    try:
        if dir_path.exists():
            dir_path.rmdir()  # only succeeds if empty
    except OSError:
        pass  # directory not empty, that's fine


def delete_connection(conn_id: int) -> bool:
    """Delete a connection."""
    _ensure_dirs()
    connections = _load_connections()

    for idx, conn in enumerate(connections):
        if conn.get("id") == conn_id:
            connections.pop(idx)
            _save_connections(connections)
            _delete_nginx_config(conn_id)
            _delete_ssl_certs(conn_id)
            return True

    return False


def reload_connections_config() -> dict:
    """Regenerate all Nginx config files and return status."""
    try:
        _ensure_dirs()
        connections = _load_connections()

        # Clear existing connection configs (both old top-level and new subdirectory patterns)
        for f in CONNECTIONS_D_DIR.glob("*.conf"):
            f.unlink()
        # Remove conn_* subdirectories
        for d in CONNECTIONS_D_DIR.glob("conn_*"):
            if d.is_dir():
                shutil.rmtree(d)

        # Generate new configs for enabled connections & re-copy static sites
        for conn in connections:
            if conn.get("enabled"):
                if conn.get("mode") == "static":
                    source = conn.get("static_dir") or "examples"
                    _copy_static_site(conn["id"], source)
                _write_nginx_config(conn)

        return {"success": True, "message": f"Generated {len(connections)} connection configs"}
    except Exception as e:
        return {"success": False, "message": str(e)}
