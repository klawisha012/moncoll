import json
import uuid
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

# Backend-container paths (for file operations — /var/lib/angie/http.d)
BACKEND_HTTPD_DIR = Path("/var/lib/angie/http.d")
ACME_DIR = Path("/var/lib/angie/acme")

# Angie-container paths (for nginx config directives — /etc/angie/http.d)
ANGIE_HTTPD_DIR = "/etc/angie/http.d"


def _ensure_ssl_dirs():
    """Ensure SSL and ACME directories exist."""
    BACKEND_HTTPD_DIR.mkdir(parents=True, exist_ok=True)
    ACME_DIR.mkdir(parents=True, exist_ok=True)


def get_backend_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths for backend file operations."""
    cert_path = f"/var/lib/angie/http.d/{connection_id}.crt"
    key_path = f"/var/lib/angie/http.d/{connection_id}.key"
    return cert_path, key_path


def get_angie_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths as seen from inside the Angie container."""
    cert_path = f"{ANGIE_HTTPD_DIR}/{connection_id}.crt"
    key_path = f"{ANGIE_HTTPD_DIR}/{connection_id}.key"
    return cert_path, key_path


# Keep backward-compatible alias
def get_connection_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths for a connection (backend container paths)."""
    return get_backend_ssl_paths(connection_id)


def generate_self_signed_certificate(connection_id: int, domains: list[str]) -> dict:
    """Generate self-signed certificate for testing.

    Writes files using backend-container paths, but returns Angie-container
    paths so they can be used directly in nginx config directives.
    """
    _ensure_ssl_dirs()

    backend_cert, backend_key = get_backend_ssl_paths(connection_id)
    angie_cert, angie_key = get_angie_ssl_paths(connection_id)

    # Use openssl to generate self-signed cert
    try:
        # Generate private key (genrsa for broader OpenSSL compatibility)
        subprocess.run([
            "openssl", "genrsa", "-out", backend_key, "2048"
        ], check=True)

        # Generate certificate
        subj = f"/C=US/ST=State/L=City/O=Organization/CN={domains[0]}"
        alt_names = "subjectAltName=" + ",".join(f"DNS:{domain}" for domain in domains)

        subprocess.run([
            "openssl", "req", "-new", "-x509", "-key", backend_key, "-out", backend_cert,
            "-days", "365", "-subj", subj, "-addext", alt_names
        ], check=True)

        return {
            "success": True,
            "message": f"Self-signed certificate generated for domains: {', '.join(domains)}",
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


def trigger_acme_request(connection_id: int, domains: list[str]) -> dict:
    """Trigger ACME certificate request for domains.

    For testing, generate self-signed certificate instead.
    Returns Angie-container paths suitable for nginx config.
    """
    # For testing purposes, generate self-signed certificate
    return generate_self_signed_certificate(connection_id, domains)


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
