# ca_app/handlers/certificate_handler.py

import os
import sys
from typing import Dict, Any, Tuple
from datetime import datetime, timezone

# --- Path setup ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# --- Cryptography Imports ---
from cryptography import x509
from cryptography.x509.oid import NameOID

# --- Constants ---
CA_CERT_PATH = os.path.join(os.path.dirname(__file__), "..", "ca.cert.pem")

def get_root_certificate_details() -> Tuple[Dict[str, Any] | None, str | None]:
    """
    Parses the root CA certificate from its PEM file into a structured dictionary.
    """
    if not os.path.exists(CA_CERT_PATH):
        return None, f"Root certificate not found at {CA_CERT_PATH}"

    try:
        with open(CA_CERT_PATH, "rb") as f:
            cert_pem = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_pem)
        
        subject = {attr.oid._name: attr.value for attr in cert.subject}
        issuer = {attr.oid._name: attr.value for attr in cert.issuer}
        
        valid_from = cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
        valid_to = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')

        parsed_data = {
            "subject": subject,
            "issuer": issuer,
            "serial_number": cert.serial_number,
            "version": cert.version.name,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "expires_in_days": (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        }
        return parsed_data, None
    except Exception as e:
        return None, f"Failed to parse certificate: {e}"

