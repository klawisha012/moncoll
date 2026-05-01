import json
import uuid
from datetime import datetime
from pathlib import Path

from .schemas import Connection, ConnectionCreate, ConnectionUpdate

CONNECTIONS_DIR = Path("/app/etc/angie")
CONNECTIONS_FILE = CONNECTIONS_DIR / "connections.json"
CONNECTIONS_D_DIR = CONNECTIONS_DIR / "connections.d"


def _ensure_dirs():
    """Ensure connections directory and connections.d directory exist."""
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


def _generate_nginx_config(conn: dict) -> str:
    """Generate Nginx server block configuration for a connection."""
    domains = " ".join(conn["domains"]) if conn["domains"] else "_"

    # Ensure backend_url has a scheme
    backend_url = conn["backend_url"]
    if not backend_url.startswith(("http://", "https://")):
        backend_url = f"http://{backend_url}"

    # Build server block
    lines = []
    lines.append(f"## Connection: {conn['name']} (ID: {conn['id']})")
    lines.append(f"## Generated at: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    # Server block
    lines.append(f"server {{")
    lines.append(f"    listen 80;")
    if conn["ssl_enabled"]:
        lines.append(f"    listen 443 ssl;")
        if conn["ssl_cert_path"]:
            lines.append(f"    ssl_certificate {conn['ssl_cert_path']};")
        if conn["ssl_key_path"]:
            lines.append(f"    ssl_certificate_key {conn['ssl_key_path']};")

    lines.append(f"    server_name {domains};")
    lines.append("")

    # Location block with proxy settings
    lines.append(f"    location / {{")

    # ModSecurity integration (using Angie/ModSecurity v2 directives)
    lines.append(f"    modsecurity on;")
    lines.append(f"    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")

    # Proxy settings
    lines.append(f"    proxy_pass {backend_url};")
    if conn["preserve_host"]:
        lines.append(f"    proxy_set_header Host $host;")
    else:
        lines.append(f"    proxy_set_header Host $proxy_host;")

    lines.append(f"    proxy_set_header X-Real-IP $remote_addr;")
    lines.append(f"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    lines.append(f"    proxy_set_header X-Forwarded-Proto $scheme;")
    lines.append(f"    proxy_http_version 1.1;")
    lines.append(f"    proxy_set_header Connection '';")
    lines.append(f"    proxy_buffering off;")
    lines.append(f"    proxy_request_buffering off;")
    lines.append(f"    proxy_redirect off;")

    lines.append(f"    }}")
    lines.append("")

    # Custom nginx config if provided
    if conn.get("custom_nginx_config"):
        lines.append("    ## Custom configuration")
        custom_lines = conn["custom_nginx_config"].strip().split("\n")
        for custom_line in custom_lines:
            if custom_line.strip():
                lines.append(f"    {custom_line}")

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
        "backend_url": conn_in.backend_url,
        "enabled": conn_in.enabled,
        "ssl_enabled": conn_in.ssl_enabled,
        "ssl_cert_path": conn_in.ssl_cert_path,
        "ssl_key_path": conn_in.ssl_key_path,
        "preserve_host": conn_in.preserve_host,
        "custom_nginx_config": conn_in.custom_nginx_config,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    # If not enabled, add disabled marker to filename
    connections.append(new_conn)
    _save_connections(connections)

    # Generate Nginx config
    if new_conn["enabled"]:
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
                _write_nginx_config(conn)
            else:
                _delete_nginx_config(conn_id)

            return Connection(**conn)

    return None


def delete_connection(conn_id: int) -> bool:
    """Delete a connection."""
    _ensure_dirs()
    connections = _load_connections()

    for idx, conn in enumerate(connections):
        if conn.get("id") == conn_id:
            connections.pop(idx)
            _save_connections(connections)
            _delete_nginx_config(conn_id)
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
