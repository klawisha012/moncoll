import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

CONNECTION_SSL_DIR = Path("/var/lib/angie/connections.d")
ACME_DIR = Path("/var/lib/angie/acme")


def _ensure_ssl_dirs():
    """Ensure SSL and ACME directories exist."""
    CONNECTION_SSL_DIR.mkdir(parents=True, exist_ok=True)
    ACME_DIR.mkdir(parents=True, exist_ok=True)


def get_connection_ssl_paths(connection_id: int) -> tuple[str, str]:
    """Get certificate and key paths for a connection."""
    cert_path = f"/var/lib/angie/connections.d/{connection_id}.crt"
    key_path = f"/var/lib/angie/connections.d/{connection_id}.key"
    return cert_path, key_path


def trigger_acme_request(connection_id: int, domains: list[str]) -> dict:
    """Trigger ACME certificate request for domains.
    
    This creates the necessary structure for Angie ACME module to pick up.
    """
    _ensure_ssl_dirs()
    
    client_name = f"conn_{connection_id}"
    client_dir = ACME_DIR / client_name
    client_dir.mkdir(parents=True, exist_ok=True)
    
    # Create domains list for ACME client
    domains_config = {
        "client_name": client_name,
        "domains": domains,
        "connection_id": connection_id,
        "requested_at": datetime.utcnow().isoformat()
    }
    
    config_file = client_dir / "domains.json"
    config_file.write_text(json.dumps(domains_config, indent=2))
    
    domains_str = ", ".join(domains)
    return {
        "success": True,
        "message": f"ACME request triggered for domains: {domains_str}",
        "client_name": client_name
    }


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
