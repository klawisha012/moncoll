import json
import logging
import re
import shutil
from datetime import datetime
from pathlib import Path

from ..certificates import service as cert_service
from .schemas import Connection, ConnectionCreate, ConnectionUpdate

logger = logging.getLogger(__name__)

CONNECTIONS_DIR = Path("/var/lib/angie")
CONNECTIONS_FILE = CONNECTIONS_DIR / "connections.json"
CONNECTIONS_D_DIR = CONNECTIONS_DIR / "http.d"

# ── Static site default source (backend container path) ──
DEFAULT_STATIC_SOURCE = Path("/app/site-templates/examples")
SITE_TEMPLATES_DIR = DEFAULT_STATIC_SOURCE.parent  # /app/site-templates
UPLOADS_DIR = SITE_TEMPLATES_DIR / "uploads"

# ── Directives to strip from extracted server blocks (we supply our own) ──
_STRIP_DIRECTIVES = {"listen", "server_name", "ssl_certificate", "ssl_certificate_key"}


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
    except (OSError, json.JSONDecodeError):
        return []


def _save_connections(connections: list[dict]):
    """Save connections list to JSON file."""
    CONNECTIONS_FILE.write_text(json.dumps(connections, indent=2))


def _get_ssl_paths(conn_id: int) -> tuple[str, str]:
    """Get certificate and key paths as seen from inside the Angie container."""
    cert_path = f"/etc/angie/http.d/conn_{conn_id}/{conn_id}.crt"
    key_path = f"/etc/angie/http.d/conn_{conn_id}/{conn_id}.key"
    return cert_path, key_path


def _extract_nginx_server_blocks(config_text: str) -> list[str]:
    """Extract the *body* (content between braces) of every ``server { … }``
    block found in *config_text*.  Returns a list of server-block-body strings
    (whitespace-trimmed).  If no blocks are found the list is empty.
    """
    blocks: list[str] = []
    for match in re.finditer(r'\bserver\s*\{', config_text):
        start = match.end()
        depth = 1
        i = start
        while i < len(config_text) and depth > 0:
            ch = config_text[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            i += 1
        body = config_text[start:i - 1].strip()
        if body:
            blocks.append(body)
    return blocks


def _find_site_server_blocks(site_dir: Path) -> list[str]:
    """Recursively walk *site_dir*, read every ``*.conf`` file and collect
    all server-block bodies found in them.  Returns a (possibly empty) list.
    """
    if not site_dir.is_dir():
        return []
    bodies: list[str] = []
    for conf_file in sorted(site_dir.rglob("*.conf")):
        try:
            text = conf_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        bodies.extend(_extract_nginx_server_blocks(text))
    return bodies


def _extract_server_names_from_body(body: str) -> list[str]:
    """Extract ``server_name`` values from a single server-block body.

    Returns a list of domain names (e.g. ``["example.com", "www.example.com"]``).
    If no ``server_name`` directive is found the list is empty.
    """
    for line in body.splitlines():
        stripped = line.strip()
        # Match "server_name value1 value2 …;" possibly with leading whitespace
        if re.match(r'\bserver_name\b', stripped):
            parts = stripped.split()
            # parts[0] = "server_name", parts[1:] = domain names (last one may end with ';')
            names: list[str] = []
            for token in parts[1:]:
                name = token.rstrip(';')
                if name:
                    names.append(name)
            return names
    return []


def _parse_domains_from_site(site_dir: Path) -> list[str]:
    """Recursively walk *site_dir*, find every ``server { … }`` block in
    ``*.conf`` files and collect all ``server_name`` values.

    Returns a deduplicated list (order preserved — first occurrence wins).
    If no site directory or no configs are found, returns an empty list.
    """
    if not site_dir.is_dir():
        return []
    domains: list[str] = []
    for conf_file in sorted(site_dir.rglob("*.conf")):
        try:
            text = conf_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for body in _extract_nginx_server_blocks(text):
            domains.extend(_extract_server_names_from_body(body))
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


def _clean_server_block_body(body: str, conn_id: int) -> str:
    """Strip directives that the WAF connection manages itself
    (``listen``, ``server_name``, SSL paths) and adjust any ``root``
    directive to point inside the connection's static site directory.

    Returns a multi-line string ready to drop into a generated
    ``server {}`` block.  Original indentation is preserved so that
    nested ``location`` / ``if`` blocks stay correctly aligned.
    """
    conn_site_root = f"/etc/angie/http.d/conn_{conn_id}/site"
    out_lines: list[str] = []
    for raw_line in body.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#'):
            # empty / comment — keep the line as-is
            out_lines.append(raw_line)
            continue

        # Detect directive name (first token, trailing ';' optional for matching)
        tokens = stripped.split()
        directive = tokens[0].rstrip(';') if tokens else ''

        if directive in _STRIP_DIRECTIVES:
            continue  # drop the line entirely

        # Rewrite 'root' to the connection's static site directory
        if directive == 'root' and len(tokens) >= 2:
            # Preserve the original indentation of the root line
            leading = raw_line[: len(raw_line) - len(raw_line.lstrip())]
            out_lines.append(f"{leading}root {conn_site_root};")
            continue

        # All other lines — keep exactly as they were (indentation preserved)
        out_lines.append(raw_line)

    return "\n".join(out_lines)


def _generate_nginx_config(conn: dict) -> str:
    """Generate Angie server-block configuration for a connection.

    For *static* mode the site directory is scanned recursively for
    ``*.conf`` files containing ``server { … }`` blocks.  If any are found
    their bodies (minus listen / server_name / ssl_* directives) are
    embedded directly inside the generated server blocks — so the site's
    own nginx routing is preserved and the WAF only adds its security
    wrapper (ModSecurity, CrowdSec blocked-IPs, SSL).

    For *proxy* mode, or when no site-side server blocks exist, a sensible
    default ``location / { proxy_pass … }`` or ``root …`` block is generated.
    """
    domains = " ".join(conn["domains"]) if conn["domains"] else "_"
    mode = conn.get("mode", "proxy")
    is_static = mode == "static"
    conn_id = conn["id"]

    # ── Try to discover server-block bodies from the copied site ──
    site_server_bodies: list[str] = []
    if is_static:
        site_dir = _site_dir(conn_id)
        if site_dir.is_dir():
            site_server_bodies = _find_site_server_blocks(site_dir)
            if site_server_bodies:
                logger.info(
                    "Conn %d: found %d server block(s) in %s — using site config",
                    conn_id, len(site_server_bodies), site_dir,
                )

    # ── Build the output ──
    lines: list[str] = []
    lines.append(f"## Connection: {conn['name']} (ID: {conn_id})")
    lines.append(f"## Mode: {mode}")
    lines.append(f"## Generated at: {datetime.utcnow().isoformat()}Z")
    if site_server_bodies:
        lines.append(
            f"## Server blocks sourced from site/{len(site_server_bodies)} conf file(s)"
        )
    lines.append("")

    # ── helpers ──
    blocked_ips_include = f"    include http.d/conn_{conn_id}/blocked_ips.conf;"

    def _emit_server_body_for_proxy() -> list[str]:
        """Fallback proxy location block (used when no site server blocks exist)."""
        backend_url = conn.get("backend_url", "")
        if backend_url and not backend_url.startswith(("http://", "https://")):
            backend_url = f"http://{backend_url}"
        preserve = conn.get("preserve_host", True)
        host_directive = "$host" if preserve else "$proxy_host"
        return [
            "    location / {",
            f"        proxy_pass {backend_url};",
            f"        proxy_set_header Host {host_directive};",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Connection '';",
            "        proxy_buffering off;",
            "        proxy_request_buffering off;",
            "        proxy_redirect off;",
            "    }",
        ]

    def _emit_server_body_for_static() -> list[str]:
        """Fallback static root/index block."""
        root = f"/etc/angie/http.d/conn_{conn_id}/site"
        return [
            f"    root {root};",
            "    index index.html index.htm;",
            "    try_files $uri $uri/ =404;",
        ]

    def _append_modsecurity(target: list[str]):
        target.append("")
        target.append("    # ModSecurity integration")
        target.append("    modsecurity on;")
        target.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")

    def _build_server_body() -> list[str]:
        """Return the inner lines (already 4-space indented) for the server block."""
        if site_server_bodies:
            # Use the first discovered server block (most sites define one)
            body = _clean_server_block_body(site_server_bodies[0], conn_id)
            return body.splitlines()

        if is_static:
            return _emit_server_body_for_static()
        return _emit_server_body_for_proxy()

    # ── HTTP server (always present) ──
    lines.append("server {")
    lines.append("    listen 80;")
    lines.append(f"    server_name {domains};")
    lines.append("")
    lines.append("    # GeoIP JSON access log for dashboard analytics")
    lines.append("    access_log /var/log/angie/geoip.log with_geoip_json;")
    lines.append("")
    lines.append(blocked_ips_include)
    lines.append("")

    # ACME challenge for Let's Encrypt (served from site/ before any redirect)
    lines.append("    # Let's Encrypt HTTP-01 challenge")
    lines.append("    location ^~ /.well-known/acme-challenge/ {")
    lines.append(f"        root /etc/angie/http.d/conn_{conn_id}/site;")
    lines.append("        try_files $uri =404;")
    lines.append("    }")
    lines.append("")

    if conn.get("ssl_enabled"):
        # HTTP → HTTPS redirect
        lines.append("    location / {")
        lines.append("        return 301 https://$host$request_uri;")
        lines.append("    }")
        lines.append("}")
        lines.append("")

        # ── HTTPS server ──
        cert_path, key_path = _get_ssl_paths(conn["id"])
        lines.append("server {")
        lines.append("    listen 443 ssl;")
        lines.append(f"    server_name {domains};")
        lines.append("")
        lines.append("    # GeoIP JSON access log for dashboard analytics")
        lines.append("    access_log /var/log/angie/geoip.log with_geoip_json;")
        lines.append("")
        lines.append(blocked_ips_include)
        ssl_cert_path = conn.get("ssl_cert_path") or cert_path
        ssl_key_path = conn.get("ssl_key_path") or key_path
        lines.append(f"    ssl_certificate {ssl_cert_path};")
        lines.append(f"    ssl_certificate_key {ssl_key_path};")
        lines.append("")
        lines.append("    # HSTS (force HTTPS, prevent downgrade attacks)")
        lines.append("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;")
        _append_modsecurity(lines)
        lines.append("")
        lines.extend(_build_server_body())
    else:
        _append_modsecurity(lines)
        lines.append("")
        lines.extend(_build_server_body())

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
    2. If *source* points to a file (e.g. from a file-picker), take its parent directory
    3. Relative path → resolved against ``/app/site-templates/``
    4. Absolute path that exists as a directory → used as-is
    5. Absolute path that does NOT exist → take its leaf name and
       try it relative to ``/app/site-templates/`` (this handles
       legacy Angie-container paths like ``/var/www/examples``).
    6. Fallback → DEFAULT_STATIC_SOURCE
    """
    if not source:
        return _existing_or_none(DEFAULT_STATIC_SOURCE)

    source_path = Path(source)

    # If the source itself is a file, use its parent directory
    if source_path.is_file():
        parent = source_path.parent
        if parent.is_dir():
            logger.info("Static source is a file (%s) — using parent directory %s", source_path, parent)
            return parent
        # If parent doesn't exist, fall through

    if not source_path.is_absolute():
        resolved = DEFAULT_STATIC_SOURCE.parent / source_path
        # If resolved is a file, use its parent
        if resolved.is_file():
            parent = resolved.parent
            if parent.is_dir():
                logger.info("Static source resolved to file (%s) — using parent directory %s", resolved, parent)
                return parent
        return _existing_or_none(resolved)

    if source_path.is_dir():
        return source_path

    # Absolute path that is a file — use parent
    if source_path.is_file():
        parent = source_path.parent
        if parent.is_dir():
            logger.info("Static source is a file (%s) — using parent directory %s", source_path, parent)
            return parent

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
    """Generate SSL certificates and persist paths back to the connection JSON.

    Always writes the nginx config afterwards (even if cert generation fails)
    so the site stays reachable with whatever cert is on disk."""
    conn_id = conn["id"]
    domains = conn.get("domains", [])
    if not domains:
        _write_nginx_config(conn)
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

    # Always write config — the existing cert on disk (if any) will be used
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

        # Auto-populate domains from site configs if not explicitly provided
        if not new_conn["domains"]:
            site_dir = _site_dir(new_id)
            parsed_domains = _parse_domains_from_site(site_dir)
            if parsed_domains:
                new_conn["domains"] = parsed_domains
                _save_connections(connections)
                logger.info(
                    "Conn %d: auto-populated domains from site configs: %s",
                    new_id, parsed_domains,
                )

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

    for conn in connections:
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


def _find_existing_template_dir(filename: str) -> str | None:
    """Search /app/site-templates/ subdirectories for *filename*.

    Returns the leaf directory name (e.g. ``"examples"``) of the first
    match, or ``None`` if no existing template contains the file.
    Skips the ``uploads`` directory itself and hidden entries.
    """
    clean = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if not SITE_TEMPLATES_DIR.is_dir():
        return None
    for entry in sorted(SITE_TEMPLATES_DIR.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith(".") or entry.name == "uploads":
            continue
        candidate = entry / clean
        if candidate.is_file():
            logger.info("Found existing template %s containing %s", entry.name, clean)
            return entry.name
    return None


def save_uploaded_static(file_content: bytes, filename: str, connection_id: int | None = None) -> dict:
    """Save an uploaded static file and return the source path usable as static_dir.

    If a file with the same name already exists in one of the template
    directories under ``/app/site-templates/`` (e.g. ``examples/index.html``),
    that directory's relative name is returned — so the field shows the
    *original* source path the user expects.

    Otherwise the file is stored under ``uploads/<name>/`` and a fallback
    relative path is returned.

    Returns dict with keys: path (relative), filename.
    """
    from datetime import datetime as dt

    # Always persist the uploaded file so it is available for later use
    safe_name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] or "index.html"
    stem = safe_name.rsplit(".", 1)[0] if "." in safe_name else safe_name
    stem = stem.replace(" ", "_").replace(".", "_") or "index"
    ts = dt.utcnow().strftime("%Y%m%d_%H%M%S")
    dir_name = f"{stem}_{ts}"

    upload_dir = UPLOADS_DIR / dir_name
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_path = upload_dir / safe_name
    file_path.write_bytes(file_content)
    logger.info("Saved uploaded static file %s → %s", filename, file_path)

    # Check whether an existing template directory already contains this file.
    # If so, return the template name (e.g. "examples") — that is the
    # "original path" the user wants to see in the UI.
    existing = _find_existing_template_dir(safe_name)
    if existing:
        return {
            "path": existing,
            "filename": safe_name,
        }

    # Fallback — use the uploads/ directory as the source
    return {
        "path": f"uploads/{dir_name}",
        "filename": safe_name,
    }


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
                # Re-generate SSL certs if enabled (they were deleted above)
                if conn.get("ssl_enabled") and conn.get("domains"):
                    _generate_certs_and_update_connection(conn, connections)
                else:
                    _write_nginx_config(conn)

        return {"success": True, "message": f"Generated {len(connections)} connection configs"}
    except Exception as e:
        return {"success": False, "message": str(e)}
