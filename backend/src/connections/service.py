import logging
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import docker
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..certificates import service as cert_service
from ..db.models import Connection as ConnectionModel
from .schemas import Connection, ConnectionCreate, ConnectionUpdate

logger = logging.getLogger(__name__)

CONNECTIONS_DIR = Path("/var/lib/angie")
CONNECTIONS_D_DIR = CONNECTIONS_DIR / "http.d"

ANGIE_CONTAINER_NAME = "waf-angie-1"

# ── Static site default source (backend container path) ──
DEFAULT_STATIC_SOURCE = Path("/app/site-templates/examples")
SITE_TEMPLATES_DIR = DEFAULT_STATIC_SOURCE.parent  # /app/site-templates
UPLOADS_DIR = SITE_TEMPLATES_DIR / "uploads"

# ── docker-compose projects (one per docker_compose connection) ──
COMPOSE_PROJECTS_DIR = Path("/var/lib/waf/compose")

# Directives stripped from extracted server blocks (we supply our own).
_STRIP_DIRECTIVES = {"listen", "server_name", "ssl_certificate", "ssl_certificate_key"}

# Hard ceiling on include expansion to defuse pathological/cyclic configs.
_MAX_INCLUDE_DEPTH = 8


def _ensure_dirs():
    CONNECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    CONNECTIONS_D_DIR.mkdir(parents=True, exist_ok=True)


def _to_dict(c: ConnectionModel) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "domains": list(c.domains or []),
        "source_type": c.source_type,
        "nginx_config_path": c.nginx_config_path,
        "backend_url": c.backend_url,
        "static_dir": c.static_dir,
        "compose_yaml": c.compose_yaml,
        "compose_service": c.compose_service,
        "compose_port": c.compose_port,
        "http_versions": getattr(c, "http_versions", None) or "h1,h2",
        "compression_algo": getattr(c, "compression_algo", None) or "auto",
        "enabled": c.enabled,
        "ssl_enabled": c.ssl_enabled,
        "ssl_cert_path": c.ssl_cert_path,
        "ssl_key_path": c.ssl_key_path,
        "preserve_host": c.preserve_host,
        "custom_nginx_config": c.custom_nginx_config,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP version + compression helpers
# ─────────────────────────────────────────────────────────────────────────────

_VALID_HTTP_VERSIONS = ("h1", "h2", "h3")
_VALID_COMPRESSION_ALGOS = ("auto", "gzip", "brotli", "zstd", "none")


def _parse_http_versions(value: str | None) -> list[str]:
    """Return a list of {'h1','h2','h3'} preserving order, defaulting to h1+h2.

    Tolerant of malformed values (silently drops unknown tokens); returns the
    default ``['h1','h2']`` if nothing parses out.
    """
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


def _normalize_compression_algo(value: str | None) -> str:
    """Return one of _VALID_COMPRESSION_ALGOS, defaulting to 'auto'."""
    v = (value or "auto").strip().lower()
    return v if v in _VALID_COMPRESSION_ALGOS else "auto"


def _emit_compression_overrides(algo: str) -> list[str]:
    """Return server-block directives that pin one compression algorithm.

    For ``algo='auto'`` we emit nothing — the global config in angie.conf
    has gzip+brotli+zstd all enabled, so Angie negotiates per request via
    the client's Accept-Encoding header (zstd > brotli > gzip).
    """
    if algo == "auto":
        return []
    if algo == "none":
        return [
            "    # compression_algo=none — disable all encoders for this server",
            "    gzip off;",
            "    brotli off;",
            "    zstd off;",
        ]
    # Pinned: disable the other two so only the chosen encoder fires.
    others = [a for a in ("gzip", "brotli", "zstd") if a != algo]
    lines = [f"    # compression_algo={algo} — pin this encoder, disable others"]
    lines.append(f"    {algo} on;")
    for other in others:
        lines.append(f"    {other} off;")
    return lines


def _emit_listen_directives(
    *,
    http_versions: list[str],
    has_ssl: bool,
) -> tuple[list[str], list[str]]:
    """Build the listen directives for the plain (port 80) and TLS (443) blocks.

    Returns ``(plain_listens, tls_listens)``.

      * ``h1`` → ``listen 80;`` on the plain block, ``listen 443 ssl;`` on TLS
      * ``h2`` → adds ``http2 on;`` on TLS (no-op on plain — HTTP/2 cleartext
        is not standardised in Angie)
      * ``h3`` → adds ``listen 443 quic reuseport;`` + ``http3 on;`` on TLS
    """
    plain: list[str] = []
    tls: list[str] = []

    if "h1" in http_versions:
        plain.append("    listen 80;")
        if has_ssl:
            tls.append("    listen 443 ssl;")
    elif has_ssl:
        # If the operator dropped h1 but kept TLS, we still need a 443 listener.
        tls.append("    listen 443 ssl;")

    if has_ssl and "h2" in http_versions:
        tls.append("    http2 on;")

    if has_ssl and "h3" in http_versions:
        # reuseport must appear on only ONE listen directive across the entire
        # angie config — emitting it per-connection caused "duplicate listen
        # options" errors when more than one h3-enabled site existed. Without
        # reuseport all workers share a single UDP socket, which still serves
        # HTTP/3 correctly (just without per-worker socket affinity).
        tls.append("    listen 443 quic;")
        tls.append("    http3 on;")
        # Advertise HTTP/3 via Alt-Svc so HTTP/2 clients upgrade on subsequent hits.
        tls.append("    add_header Alt-Svc 'h3=\":443\"; ma=86400' always;")

    return plain, tls


def _get_ssl_paths(conn_id: int) -> tuple[str, str]:
    cert_path = f"/etc/angie/http.d/conn_{conn_id}/{conn_id}.crt"
    key_path = f"/etc/angie/http.d/conn_{conn_id}/{conn_id}.key"
    return cert_path, key_path


def _conn_dir(conn_id: int) -> Path:
    return CONNECTIONS_D_DIR / f"conn_{conn_id}"


def _site_dir(conn_id: int) -> Path:
    return _conn_dir(conn_id) / "site"


def _reload_angie() -> None:
    """Reload the running Angie process so newly-written conn configs take effect.

    Best-effort: errors are logged but never raised — a failed reload should not
    break the API response after a successful DB write.
    """
    try:
        client = docker.from_env()
        container = client.containers.get(ANGIE_CONTAINER_NAME)
        code, out = container.exec_run(["angie", "-t"])
        if code != 0:
            logger.warning("Angie config test failed: %s", out.decode(errors="replace"))
            return
        code, out = container.exec_run(["angie", "-s", "reload"])
        if code != 0:
            logger.warning("Angie reload failed: %s", out.decode(errors="replace"))
    except Exception:
        logger.exception("Failed to reload Angie after connection change")


# ─────────────────────────────────────────────────────────────────────────────
# nginx config parsing helpers
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_nginx_includes(
    config_path: Path,
    *,
    _visited: set[Path] | None = None,
    _depth: int = 0,
    _prefix: Path | None = None,
) -> str:
    """Read *config_path* and recursively expand ``include`` directives.

    Relative includes are resolved against the *prefix* directory — i.e. the
    parent of the top-level config file (mirroring nginx's ``--prefix`` /
    ``-p`` flag). This matches real nginx behavior: e.g. ``h5bp/basic.conf``
    itself contains ``include h5bp/security/referrer-policy.conf;`` and
    expects that path to resolve from the same prefix as the entrypoint,
    not from its own parent dir.

    Globs (``*.conf``) are supported. Cyclic includes and depths above
    ``_MAX_INCLUDE_DEPTH`` are silently skipped (with a log line). If the
    prefix-relative resolution misses, we fall back to the including file's
    directory so simple flat configs still work.
    """
    if _visited is None:
        _visited = set()

    try:
        resolved = config_path.resolve()
    except OSError:
        return ""

    if resolved in _visited or _depth > _MAX_INCLUDE_DEPTH:
        logger.warning("Skipping include %s (cycle or depth>%d)", resolved, _MAX_INCLUDE_DEPTH)
        return ""

    try:
        text = resolved.read_text()
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Cannot read nginx config %s: %s", resolved, exc)
        return ""

    _visited.add(resolved)
    # The prefix is fixed at the first (top-level) call and inherited by
    # every nested include — matching `nginx -p <prefix>` semantics.
    if _prefix is None:
        _prefix = resolved.parent
    base_dir = resolved.parent

    out: list[str] = []
    for line in text.splitlines():
        m = re.match(r"^\s*include\s+([^;]+);\s*$", line)
        if not m:
            out.append(line)
            continue
        pattern = m.group(1).strip().strip('"').strip("'")
        inc_path = Path(pattern)

        if inc_path.is_absolute():
            candidates = [inc_path]
        else:
            # Prefix-anchored first (real nginx semantics), then fall back
            # to including-file's dir for flat layouts that worked under
            # the old behavior.
            candidates = [_prefix / inc_path]
            if base_dir != _prefix:
                candidates.append(base_dir / inc_path)

        is_glob = any(ch in pattern for ch in "*?[")

        # Resolve to the first candidate that actually has a match — both
        # for globs and exact paths. This keeps the fallback behavior
        # contained: if the prefix-anchored path is wrong, we don't echo
        # an empty include marker.
        chosen: Path | None = None
        for cand in candidates:
            if is_glob:
                if any(cand.parent.glob(cand.name)):
                    chosen = cand
                    break
            elif cand.exists():
                chosen = cand
                break
        if chosen is None:
            chosen = candidates[0]

        if is_glob:
            for match in sorted(chosen.parent.glob(chosen.name)):
                out.append(f"# >>> include {match}")
                out.append(
                    _resolve_nginx_includes(
                        match, _visited=_visited, _depth=_depth + 1, _prefix=_prefix
                    )
                )
                out.append(f"# <<< include {match}")
        else:
            out.append(f"# >>> include {chosen}")
            out.append(
                _resolve_nginx_includes(
                    chosen, _visited=_visited, _depth=_depth + 1, _prefix=_prefix
                )
            )
            out.append(f"# <<< include {chosen}")
    return "\n".join(out)


def _is_in_line_comment(config_text: str, pos: int) -> bool:
    """Return True if *pos* lies inside a ``# …`` line comment.

    Walks back to the previous newline and looks for an un-escaped ``#`` on
    the same line at an earlier column. Conservative: a ``#`` that is itself
    inside an nginx regex (e.g. ``location ~* (?:#…)`` ) would be flagged as
    a comment, so we accept a small false-positive risk where a regex with
    ``#`` precedes a ``server {`` on the same line — which is implausible in
    practice (regex location blocks never carry an inline ``server {``).
    """
    line_start = config_text.rfind("\n", 0, pos) + 1
    return "#" in config_text[line_start:pos]


def _extract_nginx_server_blocks(config_text: str) -> list[str]:
    """Extract the body (between braces) of every ``server { ... }`` block.

    A ``server`` keyword appearing inside a ``# …`` line comment is skipped
    so a stray comment like ``# example: server { proxy_pass … }`` cannot
    masquerade as a real block.  Brace-counting runs on the original text
    (untouched) so embedded regexes / comments inside the real block do not
    perturb the depth counter — the assumption is that real nginx configs
    keep their braces balanced.
    """
    blocks: list[str] = []
    for match in re.finditer(r"\bserver\s*\{", config_text):
        if _is_in_line_comment(config_text, match.start()):
            continue
        start = match.end()
        depth = 1
        i = start
        while i < len(config_text) and depth > 0:
            ch = config_text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = config_text[start : i - 1].strip()
        if body:
            blocks.append(body)
    return blocks


def _extract_server_names_from_body(body: str) -> list[str]:
    for line in body.splitlines():
        stripped = line.strip()
        if re.match(r"\bserver_name\b", stripped):
            parts = stripped.split()
            return [tok.rstrip(";") for tok in parts[1:] if tok.rstrip(";")]
    return []


def _clean_server_block_body(body: str, conn_id: int) -> str:
    """Strip WAF-managed directives and rewrite ``root`` to the conn site dir."""
    conn_site_root = f"/etc/angie/http.d/conn_{conn_id}/site"
    out_lines: list[str] = []
    for raw_line in body.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(raw_line)
            continue
        tokens = stripped.split()
        directive = tokens[0].rstrip(";") if tokens else ""
        if directive in _STRIP_DIRECTIVES:
            continue
        if directive == "root" and len(tokens) >= 2:
            leading = raw_line[: len(raw_line) - len(raw_line.lstrip())]
            out_lines.append(f"{leading}root {conn_site_root};")
            continue
        out_lines.append(raw_line)
    return "\n".join(out_lines)


# ─────────────────────────────────────────────────────────────────────────────
# Static-site source resolution + copying
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_static_source(source: str | Path | None) -> Path | None:
    """Resolve *source* to an existing backend-accessible directory.

    Accepts:
      * absolute or relative directory paths
      * a path to an ``index.html`` (its parent directory is used)
      * names of template dirs under ``/app/site-templates/``
    """
    if not source:
        return _existing_or_none(DEFAULT_STATIC_SOURCE)

    source_path = Path(source)
    if source_path.is_file():
        parent = source_path.parent
        if parent.is_dir():
            return parent

    if not source_path.is_absolute():
        resolved = SITE_TEMPLATES_DIR / source_path
        if resolved.is_file():
            return resolved.parent if resolved.parent.is_dir() else None
        return _existing_or_none(resolved)

    if source_path.is_dir():
        return source_path

    leaf = source_path.name
    if leaf:
        resolved = SITE_TEMPLATES_DIR / leaf
        if resolved.is_dir():
            return resolved

    logger.warning("Static source %s not found, falling back to %s", source, DEFAULT_STATIC_SOURCE)
    return _existing_or_none(DEFAULT_STATIC_SOURCE)


def _existing_or_none(path: Path) -> Path | None:
    return path if path.is_dir() else None


# Common SSG output directories — if an uploaded site contains exactly one
# of these and nothing else at the top level (besides hidden files), we
# transparently hoist its contents to fix the "user uploaded the project
# root instead of the build output" pitfall. Order doesn't matter; it's a
# set of recognised wrappers.
_BUILD_WRAPPER_DIRS = {"dist", "build", "out", "public", "_site"}


def _smart_flatten_site_dir(site_dir: Path) -> None:
    """If *site_dir* looks like ``<wrapper>/…`` for a known SSG wrapper,
    hoist the wrapper's contents into *site_dir* and remove the wrapper.

    Triggers only when:
      * exactly one visible entry exists at the top of *site_dir*,
      * that entry is a directory named ``dist`` / ``build`` / ``out`` /
        ``public`` / ``_site``, and
      * the wrapper itself contains an ``index.html``.

    No-op otherwise — a flat layout (index.html at the root) or anything
    ambiguous is left untouched so we never reshape a layout the user
    deliberately chose.
    """
    if not site_dir.is_dir():
        return
    visible = [p for p in site_dir.iterdir() if not p.name.startswith(".")]
    if len(visible) != 1:
        return
    wrapper = visible[0]
    if not wrapper.is_dir() or wrapper.name not in _BUILD_WRAPPER_DIRS:
        return
    if not (wrapper / "index.html").is_file():
        return

    for item in list(wrapper.iterdir()):
        target = site_dir / item.name
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        shutil.move(str(item), str(target))
    wrapper.rmdir()
    logger.info("Smart-flattened %s wrapper inside %s", wrapper.name, site_dir)


def _copy_dir_contents(src: Path, dest: Path) -> None:
    """Copy files and subdirectories from *src* into *dest* (overlay/merge).

    Unlike ``shutil.copytree`` this does **not** require *dest* to be absent;
    existing files with the same name are overwritten.
    """
    if not src.is_dir():
        return
    dest.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dest / item.name
        if item.is_dir():
            if target.is_dir():
                shutil.rmtree(target)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def _copy_static_site(conn_id: int, source: str | Path) -> Path | None:
    source_path = _resolve_static_source(source)
    dest = _site_dir(conn_id)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    if source_path is None:
        logger.warning("Cannot copy static site for conn %s: no valid source", conn_id)
        _write_fallback_index(dest, conn_id)
        return dest

    try:
        shutil.copytree(source_path, dest, dirs_exist_ok=True)
        logger.info("Copied static site %s → %s", source_path, dest)
    except Exception:
        logger.exception("Failed to copy static site %s → %s", source_path, dest)
        _write_fallback_index(dest, conn_id)
    _smart_flatten_site_dir(dest)
    return dest


def _write_fallback_index(site_dir: Path, conn_id: int) -> None:
    """Write a minimal index.html so the site never returns 403."""
    index_html = site_dir / "index.html"
    if not index_html.exists():
        index_html.write_text(
            '<!DOCTYPE html>\n<html lang="en">\n'
            '<head><meta charset="utf-8"><title>Site</title></head>\n'
            f"<body><h1>Connection {conn_id}</h1><p>Site is being configured.</p></body>\n"
            "</html>\n"
        )
        logger.info("Conn %d: wrote fallback index.html", conn_id)


# ─────────────────────────────────────────────────────────────────────────────
# nginx config generation (per source_type)
# ─────────────────────────────────────────────────────────────────────────────


def _normalize_backend_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url


def _emit_proxy_body(conn: dict) -> list[str]:
    backend_url = _normalize_backend_url(conn.get("backend_url", ""))
    preserve = conn.get("preserve_host", True)
    host_directive = "$host" if preserve else "$proxy_host"

    def _proxy_headers() -> list[str]:
        # WebSocket support: forward the Upgrade header verbatim and set
        # Connection from the `$connection_upgrade` map (defined in
        # angie.conf). Without these, Socket.IO / SSE / raw WS hang at the
        # proxy and clients see "Lost connection to the socket server.
        # Reconnecting…" — exactly what Uptime Kuma's /dashboard reports.
        return [
            f"        proxy_pass {backend_url};",
            f"        proxy_set_header Host {host_directive};",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Upgrade $http_upgrade;",
            "        proxy_set_header Connection $connection_upgrade;",
            "        proxy_buffering off;",
            "        proxy_request_buffering off;",
            "        proxy_redirect off;",
            # Long read timeout so idle WebSocket connections don't get
            # killed mid-session (default 60s drops long-lived sockets
            # like uptime monitors and chat). 1h is the conventional
            # reverse-proxy value.
            "        proxy_read_timeout 3600s;",
            "        proxy_send_timeout 3600s;",
        ]

    out: list[str] = []
    # ── Socket.IO / Engine.IO control channel ──
    # The Socket.IO HTTP-polling fallback POSTs short JSON frames like
    # `42["evt", {...}]` that routinely trip OWASP CRS rule 949110 (anomaly
    # score >= 5) for false-positive XSS/RCE hits, returning 403 and breaking
    # the browser's Socket.IO session. Bypass ModSecurity on the well-known
    # `/socket.io/` path — the upstream app validates its own frames, and
    # this carve-out keeps WAF coverage on every other request.
    out.append("    location /socket.io/ {")
    out.append("        modsecurity off;")
    out.extend(_proxy_headers())
    out.append("    }")
    out.append("")
    out.append("    location / {")
    out.extend(_proxy_headers())
    out.append("    }")
    return out


def _emit_static_body(conn_id: int) -> list[str]:
    root = f"/etc/angie/http.d/conn_{conn_id}/site"
    # Route fallback chain covers the common static-site-generator shapes:
    #   $uri        — exact file match (asset, /index.html)
    #   $uri.html   — file-format SSGs (Astro build.format='file', /blog → /blog.html)
    #   $uri/       — directory-format SSGs (Astro default, /blog → /blog/ + index)
    #   =404        — give up
    return [
        f"    root {root};",
        "    index index.html index.htm;",
        "    try_files $uri $uri.html $uri/ =404;",
    ]


def _emit_nginx_config_body(conn: dict) -> list[str]:
    """Use the user-supplied nginx config: expand includes, embed the
    first ``server { … }`` body (minus WAF-managed directives).
    """
    config_path = conn.get("nginx_config_path")
    if not config_path:
        logger.warning("Conn %s: source_type=nginx_config but no nginx_config_path", conn["id"])
        return _emit_static_body(conn["id"])
    expanded = _resolve_nginx_includes(Path(config_path))
    bodies = _extract_nginx_server_blocks(expanded)
    if not bodies:
        logger.warning(
            "Conn %s: no server{...} block found in %s — falling back to static body",
            conn["id"],
            config_path,
        )
        return _emit_static_body(conn["id"])
    cleaned = _clean_server_block_body(bodies[0], conn["id"])
    return cleaned.splitlines()


_SAFE_LOCATION_RE = re.compile(
    r"^(?P<indent>\s*)location\s+(?:=\s+|\^~\s+|~\*?\s+)?"
    r"/(?:probe|healthz|health|ping|liveness|readiness)"
    r"/?\s*\{\s*$"
)


def _inject_modsec_bypass(body_lines: list[str]) -> list[str]:
    """Insert ``modsecurity off;`` inside benign healthcheck location blocks.

    Healthcheck/liveness endpoints don't carry user-controlled payloads, so
    running OWASP CRS on them only burns CPU. Bypass ModSecurity on any
    location matching /probe, /healthz, /health, /ping, /liveness, /readiness.
    """
    out: list[str] = []
    for line in body_lines:
        out.append(line)
        match = _SAFE_LOCATION_RE.match(line)
        if match:
            inner_indent = match.group("indent") + "    "
            out.append(f"{inner_indent}modsecurity off;")
    return out


def _build_server_body(conn: dict) -> list[str]:
    st = conn.get("source_type", "static_generate")
    if st in ("container", "docker_compose"):
        body = _emit_proxy_body(conn)
    elif st == "nginx_config":
        body = _emit_nginx_config_body(conn)
    else:
        body = _emit_static_body(conn["id"])
    return _inject_modsec_bypass(body)


def _generate_nginx_config(conn: dict) -> str:
    """Generate Angie server-block configuration for a connection."""
    domains = " ".join(conn["domains"]) if conn["domains"] else "_"
    conn_id = conn["id"]
    source_type = conn.get("source_type", "static_generate")
    http_versions = _parse_http_versions(conn.get("http_versions"))
    compression_algo = _normalize_compression_algo(conn.get("compression_algo"))

    lines: list[str] = []
    lines.append(f"## Connection: {conn['name']} (ID: {conn_id})")
    lines.append(f"## Source: {source_type}")
    lines.append(f"## HTTP versions: {','.join(http_versions)} | compression: {compression_algo}")
    lines.append(f"## Generated at: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    blocked_ips_include = f"    include http.d/conn_{conn_id}/blocked_ips.conf;"

    def _append_modsecurity(target: list[str]):
        target.append("")
        target.append("    # ModSecurity integration")
        target.append("    modsecurity on;")
        target.append("    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;")

    def _append_compression(target: list[str]):
        overrides = _emit_compression_overrides(compression_algo)
        if not overrides:
            return
        target.append("")
        target.extend(overrides)

    def _append_custom_nginx(target: list[str], connection: dict):
        custom = (connection.get("custom_nginx_config") or "").strip()
        if not custom:
            return
        target.append("")
        target.append("    # Custom nginx directives")
        for line in custom.splitlines():
            stripped = line.strip()
            if stripped:
                target.append(f"    {stripped}")

    body_lines = _build_server_body(conn)

    # SSL is enabled implicitly whenever we have cert+key paths on the row.
    # Cert generation runs unconditionally for any enabled connection with
    # domains, so most configs emit the 80→443 redirect + ssl server block.
    has_ssl = bool(conn.get("ssl_cert_path") and conn.get("ssl_key_path"))

    plain_listens, tls_listens = _emit_listen_directives(
        http_versions=http_versions, has_ssl=has_ssl
    )

    # ── Plain HTTP server block ──
    # Emit only when 'h1' is in http_versions (else we'd open an empty server).
    emit_plain = bool(plain_listens)
    if emit_plain:
        lines.append("server {")
        lines.extend(plain_listens)
        lines.append(f"    server_name {domains};")
        lines.append("")
        lines.append("    # GeoIP JSON access log for dashboard analytics")
        lines.append("    access_log /var/log/angie/geoip.log with_geoip_json;")
        lines.append("    # Combined-format log for CrowdSec ingestion (nginx-logs parser)")
        lines.append("    access_log /var/log/angie/access.log combined;")
        lines.append("")
        lines.append(blocked_ips_include)
        lines.append("")
        lines.append("    # Let's Encrypt HTTP-01 challenge")
        lines.append("    location ^~ /.well-known/acme-challenge/ {")
        lines.append(f"        root /etc/angie/http.d/conn_{conn_id}/site;")
        lines.append("        try_files $uri =404;")
        lines.append("    }")
        lines.append("")

        if has_ssl:
            lines.append("    location / {")
            lines.append("        return 301 https://$host$request_uri;")
            lines.append("    }")
            lines.append("}")
            lines.append("")
        else:
            _append_modsecurity(lines)
            _append_compression(lines)
            lines.append("")
            lines.extend(body_lines)
            _append_custom_nginx(lines, conn)
            lines.append("}")

    if has_ssl:
        cert_path, key_path = _get_ssl_paths(conn_id)
        lines.append("server {")
        lines.extend(tls_listens)
        lines.append(f"    server_name {domains};")
        lines.append("")
        lines.append("    # GeoIP JSON access log for dashboard analytics")
        lines.append("    access_log /var/log/angie/geoip.log with_geoip_json;")
        lines.append("    # Combined-format log for CrowdSec ingestion (nginx-logs parser)")
        lines.append("    access_log /var/log/angie/access.log combined;")
        lines.append("")
        lines.append(blocked_ips_include)
        ssl_cert_path = conn.get("ssl_cert_path") or cert_path
        ssl_key_path = conn.get("ssl_key_path") or key_path
        lines.append(f"    ssl_certificate {ssl_cert_path};")
        lines.append(f"    ssl_certificate_key {ssl_key_path};")
        lines.append("")
        lines.append("    # HSTS (force HTTPS, prevent downgrade attacks)")
        lines.append(
            '    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
        )
        _append_modsecurity(lines)
        _append_compression(lines)
        lines.append("")
        lines.extend(body_lines)
        _append_custom_nginx(lines, conn)
        lines.append("}")

    return "\n".join(lines)


def _write_nginx_config(conn: dict):
    config = _generate_nginx_config(conn)
    conn_dir = _conn_dir(conn["id"])
    conn_dir.mkdir(parents=True, exist_ok=True)
    config_file = conn_dir / f"{conn['id']}.conf"
    config_file.write_text(config)
    blocked_ips_file = conn_dir / "blocked_ips.conf"
    if not blocked_ips_file.exists():
        blocked_ips_file.write_text(
            "# Auto-generated by WAF backend — blocked IPs for this connection\n"
        )


def _delete_nginx_config(conn_id: int):
    conn_dir = _conn_dir(conn_id)
    config_file = conn_dir / f"{conn_id}.conf"
    if config_file.exists():
        config_file.unlink()
    blocked_ips_file = conn_dir / "blocked_ips.conf"
    if blocked_ips_file.exists():
        blocked_ips_file.unlink()
    site_dir = _site_dir(conn_id)
    if site_dir.exists():
        shutil.rmtree(site_dir)
    _rmdir_if_empty(conn_dir)


# ─────────────────────────────────────────────────────────────────────────────
# Source-prep dispatch (runs before config generation)
# ─────────────────────────────────────────────────────────────────────────────


def _prepare_source(row: ConnectionModel) -> bool:
    """Materialize on-disk artifacts for the connection's source_type.

    Returns True if the row was mutated (caller should commit).
    """
    mutated = False
    site_dest = _site_dir(row.id)

    if row.source_type == "static_generate":
        source = row.static_dir or "examples"
        _copy_static_site(row.id, source)
    elif row.source_type == "nginx_config":
        # ── Step 1: copy the uploaded nginx config directory (skip *.conf) ──
        nginx_dir = None
        if row.nginx_config_path:
            src_dir = Path(row.nginx_config_path).parent
            if src_dir.is_dir():
                if site_dest.exists():
                    shutil.rmtree(site_dest)
                shutil.copytree(
                    src_dir,
                    site_dest,
                    ignore=shutil.ignore_patterns("*.conf"),
                )
                nginx_dir = src_dir
                logger.info("Copied nginx_config site %s → %s (skipped *.conf)", src_dir, site_dest)
            else:
                site_dest.mkdir(parents=True, exist_ok=True)
        else:
            site_dest.mkdir(parents=True, exist_ok=True)

        # ── Step 2: overlay static_dir content (if set) on top of nginx config dir ──
        if row.static_dir:
            overlay = _resolve_static_source(row.static_dir)
            if overlay is not None and overlay != nginx_dir:
                site_dest.mkdir(parents=True, exist_ok=True)
                _copy_dir_contents(overlay, site_dest)
                logger.info(
                    "Conn %d: overlaid static_dir %s onto site %s",
                    row.id,
                    overlay,
                    site_dest,
                )

        # ── Step 3: ensure site dir is never empty (prevents 403) ──
        _ensure_site_not_empty(site_dest, row.id)

        if not row.domains and row.nginx_config_path:
            expanded = _resolve_nginx_includes(Path(row.nginx_config_path))
            parsed: list[str] = []
            seen: set[str] = set()
            for body in _extract_nginx_server_blocks(expanded):
                for name in _extract_server_names_from_body(body):
                    if name not in seen and name != "_":
                        seen.add(name)
                        parsed.append(name)
            if parsed:
                row.domains = parsed
                mutated = True
                logger.info(
                    "Conn %d: auto-populated domains from nginx config: %s",
                    row.id,
                    parsed,
                )
    elif row.source_type == "container":
        site_dest.mkdir(parents=True, exist_ok=True)
    elif row.source_type == "docker_compose":
        site_dest.mkdir(parents=True, exist_ok=True)
        derived = _bring_up_compose(row)
        if derived and derived != row.backend_url:
            row.backend_url = derived
            mutated = True

    return mutated


# ─────────────────────────────────────────────────────────────────────────────
# docker-compose support
# ─────────────────────────────────────────────────────────────────────────────


def _compose_project_dir(conn_id: int) -> Path:
    return COMPOSE_PROJECTS_DIR / f"conn_{conn_id}"


def _compose_project_name(conn_id: int) -> str:
    return f"waf_conn_{conn_id}"


# Patterns that grant container → host-root escalation. Defense-in-depth
# even though docker_compose connections are admin-only: any one of these
# breaks the WAF's isolation guarantees.
_COMPOSE_DENYLIST_PATTERNS = (
    re.compile(r"^\s*privileged\s*:\s*true\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*pid\s*:\s*['\"]?host['\"]?\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(
        r"^\s*network_mode\s*:\s*['\"]?host['\"]?\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(r"^\s*ipc\s*:\s*['\"]?host['\"]?\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*userns_mode\s*:\s*['\"]?host['\"]?\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*cap_add\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*-\s*/var/run/docker\.sock", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*-\s*/etc(/|:)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*-\s*/proc(/|:)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*-\s*/sys(/|:)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*-\s*/root(/|:)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*-\s*/:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*devices\s*:", re.IGNORECASE | re.MULTILINE),
)


def _validate_compose_yaml(yaml_text: str) -> str | None:
    """Return an error message if *yaml_text* uses a host-escalation pattern.

    Returns ``None`` when the YAML passes the deny-list. The check is a
    string scan — it is intentionally conservative, may false-positive on
    comments containing the same substrings, and is meant as one layer of
    defense in depth (not a hardened parser).
    """
    if not yaml_text:
        return None
    for pattern in _COMPOSE_DENYLIST_PATTERNS:
        m = pattern.search(yaml_text)
        if m:
            snippet = m.group(0).strip()[:80]
            return (
                f"Compose YAML rejected: host-escalation pattern '{snippet}' "
                "is not allowed (privileged/host-namespace/host-mount/docker.sock)."
            )
    return None


# Compose timeouts are sized for the slow case: cold-pulling a multi-hundred-MB
# image plus running its initial setup (e.g. umami runs `prisma migrate deploy`
# on first boot, which can take 30-60s on its own). 120s used to be the limit
# and routinely timed out on first deploy of real-world apps; 600s is a safe
# upper bound that still surfaces genuine hangs.
_COMPOSE_TIMEOUT_SECONDS = 600


def _run_compose(project_dir: Path, project_name: str, *args: str) -> tuple[int, str]:
    """Run a docker-compose command. Returns (returncode, combined stdout+stderr).

    Tries ``docker compose`` first, then falls back to ``docker-compose``.
    """
    cmds = [
        ["docker", "compose", "-p", project_name, *args],
        ["docker-compose", "-p", project_name, *args],
    ]
    last_out = ""
    for cmd in cmds:
        try:
            proc = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=_COMPOSE_TIMEOUT_SECONDS,
                check=False,
            )
            last_out = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode == 0:
                return 0, last_out
        except FileNotFoundError:
            continue
        except (subprocess.SubprocessError, OSError) as exc:
            return 1, f"{type(exc).__name__}: {exc}"
    return 1, last_out or "docker compose not available"


def _bring_up_compose(row: ConnectionModel) -> str | None:
    """Materialize compose project, ``docker compose up -d``, return backend_url.

    Returns the derived ``service:port`` backend URL, or ``None`` on failure
    (caller keeps the existing ``backend_url`` so the connection is still
    editable).
    """
    if not row.compose_yaml or not row.compose_service:
        logger.warning(
            "Conn %s: source_type=docker_compose but compose_yaml/service missing",
            row.id,
        )
        return None

    # ── Defense-in-depth: reject host-escalation patterns ──
    err = _validate_compose_yaml(row.compose_yaml)
    if err:
        logger.warning("Conn %s: %s", row.id, err)
        return row.backend_url or None

    project_dir = _compose_project_dir(row.id)
    project_dir.mkdir(parents=True, exist_ok=True)
    # Restrict perms so other processes sharing the volume can't read
    # the YAML body (it may contain secrets in `environment:` blocks).
    try:
        project_dir.chmod(0o700)
    except OSError:
        # chmod is best-effort on filesystems that don't support POSIX modes
        pass
    compose_file = project_dir / "docker-compose.yml"
    compose_file.write_text(row.compose_yaml)
    try:
        compose_file.chmod(0o600)
    except OSError:
        pass

    project_name = _compose_project_name(row.id)
    code, out = _run_compose(project_dir, project_name, "up", "-d", "--remove-orphans")
    if code != 0:
        logger.warning("Conn %s: docker compose up failed: %s", row.id, out.strip()[:500])
        return row.backend_url or None

    port = row.compose_port or _detect_compose_service_port(row.compose_yaml, row.compose_service)
    if not port:
        logger.warning(
            "Conn %s: could not derive port for service %s — keeping backend_url=%s",
            row.id,
            row.compose_service,
            row.backend_url,
        )
        return row.backend_url or None

    return f"{row.compose_service}:{port}"


def _detect_compose_service_port(yaml_text: str, service: str) -> int | None:
    """Best-effort port detection without requiring PyYAML.

    Scans for the ``services: <service>:`` block and the first port mapping
    or ``expose`` entry. Returns the *container* port (right side of ``:``).
    """
    in_block = False
    indent = 0
    for raw_line in yaml_text.splitlines():
        stripped = raw_line.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue
        leading = len(raw_line) - len(raw_line.lstrip())
        if stripped.lstrip().startswith(f"{service}:") and leading <= 4:
            in_block = True
            indent = leading
            continue
        if in_block:
            if (
                leading <= indent
                and stripped.lstrip().endswith(":")
                and not stripped.lstrip().startswith(("ports", "expose"))
            ):
                # Reached the next service block
                break
            m = re.search(r'"?(\d{2,5})"?\s*$', stripped)
            if m and ("- " in stripped or stripped.lstrip().startswith('"')):
                try:
                    port = int(m.group(1))
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    return port
    return None


def _bring_down_compose(conn_id: int) -> None:
    project_dir = _compose_project_dir(conn_id)
    if not project_dir.is_dir():
        return
    project_name = _compose_project_name(conn_id)
    _run_compose(project_dir, project_name, "down", "-v", "--remove-orphans")
    try:
        shutil.rmtree(project_dir)
    except OSError:
        logger.warning("Conn %d: failed to remove compose project dir %s", conn_id, project_dir)


def _ensure_site_not_empty(site_dir: Path, conn_id: int) -> None:
    """Guarantee the site directory contains at least an index.html.

    An empty root directory causes Angie/nginx to return 403 Forbidden
    (directory index forbidden) instead of a meaningful response.
    """
    if not site_dir.exists():
        site_dir.mkdir(parents=True, exist_ok=True)
    # Count web-content files — ignore .conf, .well-known, and hidden files.
    _web_exts = {
        ".html",
        ".htm",
        ".css",
        ".js",
        ".json",
        ".xml",
        ".txt",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pdf",
    }
    has_web_content = (
        any(p.is_file() and p.suffix.lower() in _web_exts for p in site_dir.iterdir())
        if site_dir.exists()
        else False
    )
    if not has_web_content:
        _write_fallback_index(site_dir, conn_id)


def parse_nginx_config_preview(nginx_config_path: str) -> dict:
    """Parse an uploaded nginx config and return extracted fields for form pre-fill.

    Returns a dict with ``domains``, ``backend_url``, ``index``, and ``root``
    so the frontend can auto-populate the connection form before creation.
    """
    result: dict = {"domains": [], "backend_url": "", "index": "index.html", "root": ""}
    try:
        config_path = Path(nginx_config_path)
        if not config_path.is_file():
            return result
        expanded = _resolve_nginx_includes(config_path)
        bodies = _extract_nginx_server_blocks(expanded)
        if not bodies:
            return result
        body = bodies[0]

        # ── server_name → domains
        names: list[str] = []
        seen: set[str] = set()
        for name in _extract_server_names_from_body(body):
            if name not in seen and name != "_":
                seen.add(name)
                names.append(name)
        result["domains"] = names

        # ── scan body for proxy_pass, index, root
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            m = re.match(r"proxy_pass\s+(https?://\S+|\S+)\s*;", line)
            if m:
                url = m.group(1)
                if not url.startswith(("http://", "https://")):
                    url = f"http://{url}"
                result["backend_url"] = url
                continue

            m = re.match(r"index\s+(.+?)\s*;", line)
            if m:
                result["index"] = m.group(1)
                continue

            m = re.match(r"root\s+(\S+)\s*;", line)
            if m:
                result["root"] = m.group(1)
                continue

        logger.info(
            "Parsed nginx config %s → domains=%s backend=%s",
            nginx_config_path,
            names,
            result["backend_url"],
        )
    except Exception:
        logger.exception("Failed to parse nginx config %s", nginx_config_path)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


async def list_connections(session: AsyncSession) -> list[Connection]:
    result = await session.execute(select(ConnectionModel).order_by(ConnectionModel.id))
    return [Connection.model_validate(_to_dict(row)) for row in result.scalars().all()]


async def get_connection(session: AsyncSession, conn_id: int) -> Connection | None:
    row = await session.get(ConnectionModel, conn_id)
    if row is None:
        return None
    return Connection.model_validate(_to_dict(row))


async def _generate_certs_and_update_connection(session: AsyncSession, row: ConnectionModel):
    domains = list(row.domains or [])
    if not domains:
        _write_nginx_config(_to_dict(row))
        return

    # ── Phase 1: write config without SSL so the ACME challenge
    #    location is live *before* certbot tries to verify ──
    _write_nginx_config(_to_dict(row))
    _reload_angie()

    # ── Phase 2: obtain certificate (ACME or self-signed) ──
    result = cert_service.trigger_acme_request(row.id, domains)
    if not result.get("success"):
        logger.warning(
            "Conn %d: ACME request failed (%s), falling back to self-signed certificate",
            row.id,
            result.get("message", "unknown error"),
        )
        result = cert_service.generate_self_signed_certificate(row.id, domains)

    if result.get("success"):
        cert_path = result.get("certificate_path")
        key_path = result.get("key_path")
        if cert_path and key_path:
            row.ssl_cert_path = cert_path
            row.ssl_key_path = key_path
            await session.commit()
            await session.refresh(row)
    else:
        logger.error(
            "Conn %d: both ACME and self-signed certificate generation failed: %s",
            row.id,
            result.get("message", "unknown error"),
        )

    # ── Phase 3: rewrite config with the newly-obtained certificate ──
    _write_nginx_config(_to_dict(row))


async def create_connection(session: AsyncSession, conn_in: ConnectionCreate) -> Connection:
    _ensure_dirs()

    row = ConnectionModel(
        name=conn_in.name,
        domains=list(conn_in.domains),
        source_type=conn_in.source_type,
        nginx_config_path=conn_in.nginx_config_path,
        backend_url=conn_in.backend_url,
        static_dir=conn_in.static_dir,
        compose_yaml=conn_in.compose_yaml,
        compose_service=conn_in.compose_service,
        compose_port=conn_in.compose_port,
        http_versions=conn_in.http_versions,
        compression_algo=conn_in.compression_algo,
        enabled=conn_in.enabled,
        ssl_enabled=conn_in.ssl_enabled,
        ssl_cert_path=conn_in.ssl_cert_path,
        ssl_key_path=conn_in.ssl_key_path,
        preserve_host=conn_in.preserve_host,
        custom_nginx_config=conn_in.custom_nginx_config,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)

    # Source materialization is expensive and (for docker_compose) starts
    # real containers — skip it on disabled rows. They go live on toggle-on.
    if row.enabled:
        mutated = _prepare_source(row)
        if mutated:
            await session.commit()
            await session.refresh(row)

        if row.domains:
            await _generate_certs_and_update_connection(session, row)
        else:
            _write_nginx_config(_to_dict(row))

    _reload_angie()
    return Connection.model_validate(_to_dict(row))


async def update_connection(
    session: AsyncSession, conn_id: int, conn_in: ConnectionUpdate
) -> Connection | None:
    _ensure_dirs()

    row = await session.get(ConnectionModel, conn_id)
    if row is None:
        return None

    update_data = conn_in.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(row, key, value)
    await session.commit()
    await session.refresh(row)

    if row.enabled:
        # _prepare_source brings up docker_compose stacks and copies static
        # sites — only run when the connection is actually going live.
        # Running it on disable used to crash mkdir("/var/lib/waf/compose")
        # in setups where the path wasn't volume-mounted, surfacing as
        # "Failed to toggle connection" in the UI.
        mutated = _prepare_source(row)
        if mutated:
            await session.commit()
            await session.refresh(row)

        if row.domains:
            await _generate_certs_and_update_connection(session, row)
        else:
            _write_nginx_config(_to_dict(row))
    else:
        _delete_nginx_config(conn_id)

    _reload_angie()
    return Connection.model_validate(_to_dict(row))


def _delete_ssl_certs(conn_id: int):
    conn_dir = _conn_dir(conn_id)
    cert_file = conn_dir / f"{conn_id}.crt"
    key_file = conn_dir / f"{conn_id}.key"
    if cert_file.exists():
        cert_file.unlink()
    if key_file.exists():
        key_file.unlink()
    _rmdir_if_empty(conn_dir)


def _rmdir_if_empty(dir_path: Path):
    try:
        if dir_path.exists():
            dir_path.rmdir()
    except OSError:
        pass


async def delete_connection(session: AsyncSession, conn_id: int) -> bool:
    _ensure_dirs()

    row = await session.get(ConnectionModel, conn_id)
    if row is None:
        return False

    await session.delete(row)
    await session.commit()
    _delete_nginx_config(conn_id)
    _delete_ssl_certs(conn_id)
    if row.source_type == "docker_compose":
        _bring_down_compose(conn_id)
    _reload_angie()
    return True


def _find_existing_template_dir(filename: str) -> str | None:
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
            return entry.name
    return None


def save_uploaded_static(
    file_content: bytes, filename: str, connection_id: int | None = None
) -> dict:
    from datetime import datetime as dt

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

    existing = _find_existing_template_dir(safe_name)
    if existing:
        return {"path": existing, "filename": safe_name}
    return {"path": f"uploads/{dir_name}", "filename": safe_name}


def write_static_dir_to_conn(conn_id: int, files: list[tuple[str, bytes]]) -> dict:
    """Write an uploaded static-site directory **straight into**
    ``conn_<id>/site/``, replacing whatever was there.

    Used by the per-connection upload endpoint so users don't need a
    round-trip through ``site-templates/uploads/``. Smart-flattens common
    SSG wrappers (``dist``/``build``/``out``/``public``/``_site``) and
    reloads Angie so the new content goes live immediately.

    Returns ``{"path": "<absolute conn site path>", "files": <count>}``.
    """
    if not files:
        raise ValueError("No files provided for static directory upload")

    site_dir = _site_dir(conn_id)
    # Replace any existing site content — a partial overlay would leave
    # stale files from a previous build (e.g. an old hashed asset) lying
    # around forever.
    if site_dir.exists():
        shutil.rmtree(site_dir)
    site_dir.mkdir(parents=True, exist_ok=True)

    saved_count = 0
    for rel_path, content in files:
        clean = rel_path.replace("\\", "/").lstrip("/")
        if clean.startswith("__MACOSX") or clean.startswith("."):
            continue
        parts = [p for p in clean.split("/") if p and p != ".."]
        if not parts:
            continue
        safe_name = parts[-1]
        sub_dir = site_dir
        for part in parts[:-1]:
            sub_dir = sub_dir / part
        sub_dir.mkdir(parents=True, exist_ok=True)
        (sub_dir / safe_name).write_bytes(content)
        saved_count += 1

    if saved_count == 0:
        raise ValueError("No usable files found in uploaded directory")

    _smart_flatten_site_dir(site_dir)
    _ensure_site_not_empty(site_dir, conn_id)
    _reload_angie()

    logger.info(
        "Conn %d: wrote %d files directly into %s",
        conn_id,
        saved_count,
        site_dir,
    )
    return {"path": str(site_dir), "files": saved_count}


def save_uploaded_static_dir(files: list[tuple[str, bytes]]) -> dict:
    """Save an uploaded static-site directory (e.g. an Astro/Vite ``dist/``).

    Accepts a list of ``(relative_path, content)`` tuples — typically from a
    folder picker (``webkitdirectory``). All files are stored under one
    timestamped directory, preserving subdirectory structure. Returns
    ``{"path": "uploads/static_<ts>", "filename": "<dir_name>"}`` — the
    ``path`` is a backend-template-relative directory suitable for use as
    ``static_dir`` on a connection (resolved against
    ``/app/site-templates/``).
    """
    from datetime import datetime as dt

    if not files:
        raise ValueError("No files provided for static directory upload")

    ts = dt.utcnow().strftime("%Y%m%d_%H%M%S")
    dir_name = f"static_{ts}"
    upload_dir = UPLOADS_DIR / dir_name
    upload_dir.mkdir(parents=True, exist_ok=True)

    saved_count = 0
    for rel_path, content in files:
        clean = rel_path.replace("\\", "/").lstrip("/")
        if clean.startswith("__MACOSX") or clean.startswith("."):
            continue
        parts = [p for p in clean.split("/") if p and p != ".."]
        if not parts:
            continue
        safe_name = parts[-1]
        sub_dir = upload_dir
        for part in parts[:-1]:
            sub_dir = sub_dir / part
        sub_dir.mkdir(parents=True, exist_ok=True)
        file_path = sub_dir / safe_name
        file_path.write_bytes(content)
        saved_count += 1
        logger.debug("Saved uploaded static file %s → %s", clean, file_path)

    if saved_count == 0:
        raise ValueError("No usable files found in uploaded directory")

    logger.info(
        "Saved uploaded static directory (%d files) → %s",
        saved_count,
        upload_dir,
    )

    return {"path": f"uploads/{dir_name}", "filename": dir_name}


def save_uploaded_nginx_config(files: list[tuple[str, bytes]]) -> dict:
    """Save uploaded nginx config directory under the backend uploads tree.

    Accepts a list of ``(relative_path, content)`` tuples — typically from a
    folder picker (``webkitdirectory``).  All files are stored under one
    timestamped directory, preserving subdirectory structure.  The return
    value contains the absolute path to the *main* ``.conf`` file so it can
    be used directly as ``nginx_config_path`` on a connection.
    """
    from datetime import datetime as dt

    if not files:
        raise ValueError("No files provided for nginx config upload")

    ts = dt.utcnow().strftime("%Y%m%d_%H%M%S")
    dir_name = f"nginx_config_{ts}"
    upload_dir = UPLOADS_DIR / "configs" / dir_name
    upload_dir.mkdir(parents=True, exist_ok=True)

    main_conf_path: str | None = None
    saved_count = 0

    for rel_path, content in files:
        # Normalise path separators and strip leading slashes / dots
        clean = rel_path.replace("\\", "/").lstrip("/")
        # Skip macOS resource-fork turds
        if clean.startswith("__MACOSX") or clean.startswith("."):
            continue
        parts = [p for p in clean.split("/") if p and p != ".."]
        if not parts:
            continue
        safe_name = parts[-1]
        sub_dir = upload_dir
        for part in parts[:-1]:
            sub_dir = sub_dir / part
        sub_dir.mkdir(parents=True, exist_ok=True)
        file_path = sub_dir / safe_name
        file_path.write_bytes(content)

        # Pick the main config: prefer nginx.conf, otherwise first .conf file
        if main_conf_path is None or safe_name == "nginx.conf":
            main_conf_path = str(file_path)
            if safe_name == "nginx.conf":
                # Keep scanning — nginx.conf was found, but don't break
                # in case a more specific one comes later (unlikely).
                pass

        saved_count += 1
        logger.debug("Saved uploaded config file %s → %s", clean, file_path)

    if main_conf_path is None:
        raise ValueError("No .conf file found in uploaded directory")

    logger.info(
        "Saved uploaded nginx config directory (%d files) → %s (main: %s)",
        saved_count,
        upload_dir,
        main_conf_path,
    )

    return {"path": main_conf_path, "filename": Path(main_conf_path).name}


async def reload_connections_config(session: AsyncSession) -> dict:
    try:
        _ensure_dirs()
        result = await session.execute(select(ConnectionModel).order_by(ConnectionModel.id))
        rows = list(result.scalars().all())

        for f in CONNECTIONS_D_DIR.glob("*.conf"):
            f.unlink()
        for d in CONNECTIONS_D_DIR.glob("conn_*"):
            if d.is_dir():
                shutil.rmtree(d)

        for row in rows:
            if not row.enabled:
                continue
            mutated = _prepare_source(row)
            if mutated:
                await session.commit()
                await session.refresh(row)
            if row.domains:
                await _generate_certs_and_update_connection(session, row)
            else:
                _write_nginx_config(_to_dict(row))

        _reload_angie()
        return {"success": True, "message": f"Generated {len(rows)} connection configs"}
    except Exception as e:
        logger.exception("Failed to reload connections config")
        return {"success": False, "message": str(e)}
