import json
import uuid
from datetime import datetime
from pathlib import Path

from .schemas import Connection, ConnectionCreate, ConnectionUpdate
from ..certificates import service as cert_service

CONNECTIONS_DIR = Path("/var/lib/angie")
CONNECTIONS_FILE = CONNECTIONS_DIR / "connections.json"
CONNECTIONS_D_DIR = CONNECTIONS_DIR / "http.d"


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
    cert_path = f"/etc/angie/http.d/{conn_id}.crt"
    key_path = f"/etc/angie/http.d/{conn_id}.key"
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
    def _build_location_block(is_ssl: bool = False) -> list[str]:
        """Build the main location / block based on mode."""
        loc_lines = []
        loc_lines.append("    location / {")

        if is_static:
            static_dir = conn.get("static_dir", "/usr/share/angie/html")
            # Strip filename — nginx root directive needs a directory, not a file
            if static_dir and "." in static_dir.rsplit("/", 1)[-1]:
                static_dir = "/".join(static_dir.split("/")[:-1]) or "/usr/share/angie/html"
            loc_lines.append(f"        root {static_dir};")
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

    # ── HTTP server ──
    lines.append("server {")
    lines.append("    listen 80;")

    if conn.get("ssl_enabled") and conn.get("domains"):
        lines.append("    acme default;")

    lines.append(f"    server_name {domains};")
    lines.append("")

    if conn.get("ssl_enabled"):
        # ACME challenge location
        lines.append("    location /.well-known/acme-challenge/ {")
        lines.append("        # ACME challenge handled by Angie ACME module")
        lines.append("    }")
        lines.append("")
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

        if conn.get("ssl_cert_path") and conn.get("ssl_key_path"):
            lines.append(f"    ssl_certificate {conn['ssl_cert_path']};")
            lines.append(f"    ssl_certificate_key {conn['ssl_key_path']};")
        else:
            lines.append("    ssl_certificate $acme_cert_default;")
            lines.append("    ssl_certificate_key $acme_cert_key_default;")

        lines.append("")
        lines.append("    # ModSecurity integration")
        lines.append("    modsecurity on;")
        lines.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")
        lines.append("")

        lines.extend(_build_location_block(is_ssl=True))
    else:
        # Non-SSL
        lines.append("    # ModSecurity integration")
        lines.append("    modsecurity on;")
        lines.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")
        lines.append("")

        lines.extend(_build_location_block())

    lines.append("}")

    return "\n".join(lines)


def _write_nginx_config(conn: dict):
    """Write Nginx config file for a connection."""
    config = _generate_nginx_config(conn)
    config_file = CONNECTIONS_D_DIR / f"{conn['id']}.conf"
    config_file.write_text(config)


def _delete_nginx_config(conn_id: int):
    """Delete Nginx config file for a connection."""
    config_file = CONNECTIONS_D_DIR / f"{conn_id}.conf"
    if config_file.exists():
        config_file.unlink()


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
    # Backend paths (where files are stored)
    cert_file = CONNECTIONS_D_DIR / f"{conn_id}.crt"
    key_file = CONNECTIONS_D_DIR / f"{conn_id}.key"
    if cert_file.exists():
        cert_file.unlink()
    if key_file.exists():
        key_file.unlink()


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

        # Clear existing config files
        for f in CONNECTIONS_D_DIR.glob("*.conf"):
            f.unlink()

        # Generate new configs for enabled connections
        for conn in connections:
            if conn.get("enabled"):
                _write_nginx_config(conn)

        return {"success": True, "message": f"Generated {len(connections)} connection configs"}
    except Exception as e:
        return {"success": False, "message": str(e)}
