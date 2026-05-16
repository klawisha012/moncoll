import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Backend-container paths (for file operations — /var/lib/angie/http.d)
BACKEND_HTTPD_DIR = Path("/var/lib/angie/http.d")

# Angie-container paths (for nginx config directives — /etc/angie/http.d)
ANGIE_HTTPD_DIR = "/etc/angie/http.d"

# Default ACME registration email (fallback when none configured)
_ACME_EMAIL = os.getenv("ACME_EMAIL", "admin@localhost")


def _ensure_ssl_dirs():
    """Ensure SSL directory exists."""
    BACKEND_HTTPD_DIR.mkdir(parents=True, exist_ok=True)


def get_backend_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths for backend file operations."""
    cert_path = f"/var/lib/angie/http.d/conn_{connection_id}/{connection_id}.crt"
    key_path = f"/var/lib/angie/http.d/conn_{connection_id}/{connection_id}.key"
    return cert_path, key_path


def get_angie_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths as seen from inside the Angie container."""
    cert_path = f"{ANGIE_HTTPD_DIR}/conn_{connection_id}/{connection_id}.crt"
    key_path = f"{ANGIE_HTTPD_DIR}/conn_{connection_id}/{connection_id}.key"
    return cert_path, key_path


# Keep backward-compatible alias
def get_connection_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths for a connection (backend container paths)."""
    return get_backend_ssl_paths(connection_id)


def generate_self_signed_certificate(connection_id: int, domains: list[str]) -> dict:
    """Generate certificate signed by the local CA (or self-signed as fallback).

    Writes files using backend-container paths, but returns Angie-container
    paths so they can be used directly in nginx config directives.
    """
    _ensure_ssl_dirs()

    backend_cert, backend_key = get_backend_ssl_paths(connection_id)
    angie_cert, angie_key = get_angie_ssl_paths(connection_id)

    # CA paths (backend-container view)
    ca_cert_path = "/var/lib/angie/http.d/ca.crt"
    ca_key_path = "/var/lib/angie/http.d/ca.key"

    # Ensure connection subdirectory exists
    Path(backend_cert).parent.mkdir(parents=True, exist_ok=True)

    try:
        # Generate private key
        subprocess.run([
            "openssl", "genrsa", "-out", backend_key, "2048"
        ], check=True, capture_output=True)

        if Path(ca_cert_path).exists() and Path(ca_key_path).exists():
            # Sign with local CA
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".cnf", delete=False
            ) as cnf:
                cnf.write("[req]\n")
                cnf.write("distinguished_name = req_distinguished_name\n")
                cnf.write("req_extensions = v3_req\n")
                cnf.write("prompt = no\n")
                cnf.write("[req_distinguished_name]\n")
                cnf.write(f"CN = {domains[0]}\n")
                cnf.write("[v3_req]\n")
                cnf.write("subjectAltName = " + ",".join(f"DNS:{d}" for d in domains) + "\n")
                san_cnf = cnf.name

            csr_path = f"/tmp/conn_{connection_id}.csr"
            subprocess.run([
                "openssl", "req", "-new",
                "-key", backend_key,
                "-out", csr_path,
                "-config", san_cnf,
            ], check=True, capture_output=True)

            subprocess.run([
                "openssl", "x509", "-req", "-days", "365",
                "-in", csr_path,
                "-CA", ca_cert_path,
                "-CAkey", ca_key_path,
                "-CAcreateserial",
                "-out", backend_cert,
                "-extfile", san_cnf,
                "-extensions", "v3_req",
            ], check=True, capture_output=True)

            # Cleanup
            Path(csr_path).unlink(missing_ok=True)
            Path(san_cnf).unlink(missing_ok=True)
        else:
            # Fallback: self-signed
            subj = f"/C=US/ST=State/L=City/O=Organization/CN={domains[0]}"
            alt_names = "subjectAltName=" + ",".join(f"DNS:{domain}" for domain in domains)
            subprocess.run([
                "openssl", "req", "-new", "-x509", "-key", backend_key, "-out", backend_cert,
                "-days", "365", "-subj", subj, "-addext", alt_names
            ], check=True, capture_output=True)

        return {
            "success": True,
            "message": f"Certificate generated for domains: {', '.join(domains)}",
            "certificate_path": angie_cert,
            "key_path": angie_key,
            "backend_cert_path": backend_cert,
            "backend_key_path": backend_key,
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "message": f"Failed to generate certificate: {e}"
        }


def _ensure_acme_challenge_dir(conn_id: int):
    """Create the ACME challenge directory inside the site folder
    so certbot can write HTTP-01 challenge tokens."""
    challenge_dir = BACKEND_HTTPD_DIR / f"conn_{conn_id}" / "site" / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True, exist_ok=True)


def _find_existing_le_cert(domains: list[str]) -> Path | None:
    """Search /etc/letsencrypt/live/ for a certificate covering the requested
    domains.  Returns the live-dir Path of the first match, or None.

    When a connection is re-created it gets a new numeric ID, but the old
    Let's Encrypt certificate (named after the old ID, e.g. ``conn_1``)
    is still valid for the same domains.  This function bridges the gap so
    the cert is re-copied instead of falling back to a self-signed one.
    """
    live_root = Path("/etc/letsencrypt/live")
    if not live_root.is_dir():
        return None
    domain_set = set(d.lower() for d in domains)
    for candidate in sorted(live_root.iterdir()):
        if not candidate.is_dir():
            continue
        fullchain = candidate / "fullchain.pem"
        if not fullchain.is_file():
            continue
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", str(fullchain), "-text", "-noout"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                continue
            # Extract DNS names from the SAN extension and CN from Subject
            import re
            san_match = re.findall(r"DNS:([^\s,]+)", result.stdout)
            cn_match = re.search(r"Subject:.*?CN\s*=\s*([^\s,]+)", result.stdout)
            cert_domains = {d.lower().rstrip(".") for d in san_match}
            if cn_match:
                cert_domains.add(cn_match.group(1).lower().rstrip("."))
            if domain_set.issubset(cert_domains) or domain_set & cert_domains:
                return candidate
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


def trigger_acme_request(connection_id: int, domains: list[str]) -> dict:
    """Request a real Let's Encrypt certificate via certbot (webroot mode).

    If a valid certificate already exists on disk this function simply
    re-copies it from the certbot live directory (idempotent).  A new
    certificate is only requested when none exists yet.
    """
    _ensure_ssl_dirs()
    _ensure_acme_challenge_dir(connection_id)

    backend_cert, backend_key = get_backend_ssl_paths(connection_id)
    angie_cert, angie_key = get_angie_ssl_paths(connection_id)

    # Ensure connection subdirectory exists
    Path(backend_cert).parent.mkdir(parents=True, exist_ok=True)

    cert_name = f"conn_{connection_id}"
    live_dir = Path(f"/etc/letsencrypt/live/{cert_name}")

    # Already have a cert from a previous run? -> re-copy it
    if live_dir.is_dir() and (live_dir / "fullchain.pem").exists():
        logger.info("Conn %d: cert already exists, re-copying from %s", connection_id, live_dir)
        shutil.copy2(str(live_dir / "fullchain.pem"), backend_cert)
        shutil.copy2(str(live_dir / "privkey.pem"), backend_key)
        os.chmod(backend_key, 0o600)
        return {
            "success": True,
            "message": f"Let's Encrypt certificate reused for {', '.join(domains)}",
            "certificate_path": angie_cert,
            "key_path": angie_key,
            "backend_cert_path": backend_cert,
            "backend_key_path": backend_key,
        }

    # No cert at the expected name -> search existing LE certs by domain
    existing = _find_existing_le_cert(domains)
    if existing is not None:
        logger.info(
            "Conn %d: found matching LE cert at %s, copying to %s",
            connection_id, existing, backend_cert,
        )
        shutil.copy2(str(existing / "fullchain.pem"), backend_cert)
        shutil.copy2(str(existing / "privkey.pem"), backend_key)
        os.chmod(backend_key, 0o600)
        return {
            "success": True,
            "message": (
                f"Let's Encrypt certificate reused from {existing.name} "
                f"for {', '.join(domains)}"
            ),
            "certificate_path": angie_cert,
            "key_path": angie_key,
            "backend_cert_path": backend_cert,
            "backend_key_path": backend_key,
        }

    # ── No cert yet → request a new one ──
    webroot = str(BACKEND_HTTPD_DIR / f"conn_{connection_id}" / "site")
    email = _ACME_EMAIL
    domain_args: list[str] = []
    for d in domains:
        domain_args.extend(["-d", d])

    try:
        logger.info(
            "Requesting Let's Encrypt cert for conn %d: domains=%s, webroot=%s",
            connection_id, domains, webroot,
        )
        result = subprocess.run(
            [
                "certbot", "certonly",
                "--webroot",
                "-w", webroot,
                *domain_args,
                "--non-interactive",
                "--agree-tos",
                "-m", email,
                "--cert-name", cert_name,
                "--key-type", "rsa",
                "--preferred-challenges", "http",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            logger.error("certbot failed for conn %d:\n%s", connection_id, result.stderr)
            return {
                "success": False,
                "message": f"certbot failed: {result.stderr.strip().splitlines()[-1]}",
            }

        logger.info("certbot success for conn %d:\n%s", connection_id, result.stdout)

        if not live_dir.is_dir():
            return {
                "success": False,
                "message": f"certbot output missing: {live_dir}",
            }

        shutil.copy2(str(live_dir / "fullchain.pem"), backend_cert)
        shutil.copy2(str(live_dir / "privkey.pem"), backend_key)
        os.chmod(backend_key, 0o600)

        return {
            "success": True,
            "message": f"Let's Encrypt certificate issued for {', '.join(domains)}",
            "certificate_path": angie_cert,
            "key_path": angie_key,
            "backend_cert_path": backend_cert,
            "backend_key_path": backend_key,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "certbot timed out after 120 seconds",
        }
    except FileNotFoundError:
        return {
            "success": False,
            "message": "certbot is not installed in the backend container",
        }


def check_certificate_status(connection_id: int) -> dict:
    """Check if certificate exists for connection."""
    cert_path, key_path = get_backend_ssl_paths(connection_id)
    angie_cert, angie_key = get_angie_ssl_paths(connection_id)

    cert_exists = Path(cert_path).exists()
    key_exists = Path(key_path).exists()

    return {
        "certificate_exists": cert_exists,
        "key_exists": key_exists,
        "certificate_path": angie_cert if cert_exists else None,
        "key_path": angie_key if key_exists else None,
        "backend_cert_path": cert_path if cert_exists else None,
        "backend_key_path": key_path if key_exists else None,
    }


def regenerate_certificate(connection_id: int, domains: list[str]) -> dict:
    """Regenerate certificate for a connection."""
    _ensure_ssl_dirs()

    cert_path, key_path = get_backend_ssl_paths(connection_id)

    # Ensure connection subdirectory exists
    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)

    # Remove existing certificates
    cert_file = Path(cert_path)
    key_file = Path(key_path)

    if cert_file.exists():
        cert_file.unlink()
    if key_file.exists():
        key_file.unlink()

    # Trigger new ACME request
    result = trigger_acme_request(connection_id, domains)

    return result
