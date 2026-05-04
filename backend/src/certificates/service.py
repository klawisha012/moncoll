import json
import uuid
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

CONNECTION_SSL_DIR = Path("/etc/angie/connections.d")
ACME_DIR = Path("/etc/angie/acme")


def _ensure_ssl_dirs():
    """Ensure SSL and ACME directories exist."""
    CONNECTION_SSL_DIR.mkdir(parents=True, exist_ok=True)
    ACME_DIR.mkdir(parents=True, exist_ok=True)


def get_connection_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths for a connection."""
    cert_path = f"/var/lib/angie/connections.d/{connection_id}.crt"
    key_path = f"/var/lib/angie/connections.d/{connection_id}.key"
    return cert_path, key_path


def generate_self_signed_certificate(connection_id: int, domains: list[str]) -> dict:
    """Generate self-signed certificate for testing."""
    _ensure_ssl_dirs()

    cert_path, key_path = get_connection_ssl_paths(connection_id)

    # Use openssl to generate self-signed cert
    try:
        # Generate private key
        subprocess.run([
            "openssl", "genpkey", "-algorithm", "RSA", "-out", key_path, "-pkcs8"
        ], check=True)

        # Generate certificate
        subj = f"/C=US/ST=State/L=City/O=Organization/CN={domains[0]}"
        alt_names = "subjectAltName=" + ",".join(f"DNS:{domain}" for domain in domains)

        subprocess.run([
            "openssl", "req", "-new", "-x509", "-key", key_path, "-out", cert_path,
            "-days", "365", "-subj", subj, "-addext", alt_names
        ], check=True)

        return {
            "success": True,
            "message": f"Self-signed certificate generated for domains: {', '.join(domains)}",
            "certificate_path": cert_path,
            "key_path": key_path
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "message": f"Failed to generate certificate: {e}"
        }


def trigger_acme_request(connection_id: int, domains: list[str]) -> dict:
    """Trigger ACME certificate request for domains.

    For testing, generate self-signed certificate instead.
    """
    # For testing purposes, generate self-signed certificate
    return generate_self_signed_certificate(connection_id, domains)


def check_certificate_status(connection_id: int) -> dict:
    """Check if certificate exists for connection."""
    cert_path, key_path = get_connection_ssl_paths(connection_id)
    
    cert_exists = Path(cert_path).exists()
    key_exists = Path(key_path).exists()
    
    return {
        "certificate_exists": cert_exists,
        "key_exists": key_exists,
        "certificate_path": cert_path if cert_exists else None,
        "key_path": key_path if key_exists else None
    }


def regenerate_certificate(connection_id: int, domains: list[str]) -> dict:
    """Regenerate certificate for a connection."""
    _ensure_ssl_dirs()
    
    cert_path, key_path = get_connection_ssl_paths(connection_id)
    
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
