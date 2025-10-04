# Provides read-only access to CA server endpoints (certs, CRL, root).
# verif_app/utils/ca_sync.py

"""
Read-only CA sync for Verifier (V3 endpoints)
- Endpoints expected relative to CA_API_URL (which already ends with /api):
    GET /certificates/<email> -> { ok, certificate_pem, cert_serial, ... }
    GET /trust/crl            -> { ok, revoked_serials: [...], version, issued_at_utc }
    GET /trust/root           -> { ok, certificate_pem }
"""

from __future__ import annotations
import requests
import json
from urllib.parse import quote
from typing import Tuple, Dict, Any
from config import CA_API_URL

REQUEST_TIMEOUT = 10  # seconds

def _req(endpoint: str) -> Tuple[Dict[str, Any] | None, str | None]:
    url = f"{CA_API_URL}{endpoint}"
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except requests.exceptions.Timeout:
        return None, "Connection timed out. The CA server may be busy or offline."
    except requests.exceptions.ConnectionError:
        return None, "Connection failed. Ensure the Verifier is on the same network as the CA server."
    except requests.exceptions.HTTPError as e:
        try:
            msg = e.response.json().get("message", "HTTP error")
            return None, f"{msg} (Status {e.response.status_code})"
        except json.JSONDecodeError:
            return None, f"HTTP error: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"

def fetch_certificate(email: str) -> Tuple[str | None, str | None]:
    data, err = _req(f"/certificates/{quote(email)}")
    if err:
        return None, err
    if data.get("ok") is False:
        return None, data.get("error", {}).get("message")
    return data.get("certificate_pem"), None

def get_crl() -> Tuple[Dict[str, Any] | None, str | None]:
    """
    Returns a dict with CRL data and metadata:
      { "crl": <...>, "version": "...", "issued_at_utc": "..." }
    """
    data, err = _req("/trust/crl")
    if err:
        return None, err
    if data.get("ok") is False:
        return None, data.get("error", {}).get("message")
    return data, None

def get_ca_root() -> Tuple[str | None, str | None]:
    """
    Returns root certificate PEM string (expects /ca-root endpoint).
    """
    data, err = _req("/trust/root")
    if err:
        return None, err
    if data.get("ok") is False:
        return None, data.get("error", {}).get("message")
    return data.get("certificate_pem"), None
