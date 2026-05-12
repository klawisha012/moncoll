import json
import uuid
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

# Backend-container paths (for file operations — /var/lib/angie/http.d)
BACKEND_HTTPD_DIR = Path("/var/lib/angie/http.d")

# Angie-container paths (for nginx config directives — /etc/angie/http.d)
ANGIE_HTTPD_DIR = "/etc/angie/http.d"


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
