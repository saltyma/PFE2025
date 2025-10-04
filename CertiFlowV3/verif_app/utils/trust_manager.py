# verif_app/utils/trust_manager.py

"""
Trust Manager (Verifier)
------------------------
- Fetches CA root certificate and CRL from the CA server (read-only).
- Validates basic structure (non-empty PEM/fields).
- Saves a snapshot to the local DB for offline verification.
- Provides helpers to get the latest snapshot.

Depends on:
    - ver_db_helper.py  (save_trust_snapshot, get_latest_trust_snapshot)
    - utils/ca_sync.py  (get_ca_root, get_crl)
"""

from __future__ import annotations
from typing import Dict, Any, Tuple, Optional
import json
from datetime import datetime, timezone

from ver_db_helper import save_trust_snapshot, get_latest_trust_snapshot
from utils import ca_sync

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def refresh_trust() -> Tuple[bool, str | None]:
    """
    Downloads CA root + CRL from the CA server and stores a snapshot locally.

    Returns:
        (success: bool, error_message: str | None)
    """
    # --- Fetch CA root ---
    ca_root_pem, err = ca_sync.get_ca_root()
    if err:
        return False, f"Failed to fetch CA root: {err}"
    if not ca_root_pem or "BEGIN CERTIFICATE" not in ca_root_pem:
        return False, "Invalid CA root received."

    # --- Fetch CRL (optional but recommended) ---
    crl_bundle, err = ca_sync.get_crl()
    if err:
        # Allow operation to succeed with only the root; warn via return message
        crl_pem = None
        crl_version = None
        crl_issued_at = None
        warning = f" (Warning: CRL not available: {err})"
    else:
        # CRL shape is expected to be: {"revoked_serials": [...], "version": "...", "issued_at_utc": "..."}
        revoked_serials = crl_bundle.get("revoked_serials") if isinstance(crl_bundle, dict) else None
        crl_pem = json.dumps(revoked_serials) if revoked_serials is not None else None
        crl_version = crl_bundle.get("version") if isinstance(crl_bundle, dict) else None
        crl_issued_at = crl_bundle.get("issued_at_utc") if isinstance(crl_bundle, dict) else None
        warning = ""

    # --- Save snapshot ---
    snapshot_id = save_trust_snapshot(
        ca_root_pem=ca_root_pem,
        crl_pem=crl_pem,
        crl_version=crl_version,
        crl_issued_at_utc=crl_issued_at,
        last_sync_utc=_utcnow_iso(),
    )

    return True, f"Trust snapshot saved (id={snapshot_id}).{warning}"

def get_current_trust() -> Optional[Dict[str, Any]]:
    """
    Returns the most recent trust snapshot, or None if not present.
    Keys: ca_root_pem, crl_pem, crl_version, crl_issued_at_utc, last_sync_utc
    """
    return get_latest_trust_snapshot()

def ensure_trust_ready(auto_refresh: bool = True) -> Tuple[bool, str | None]:
    """
    Ensures the verifier has at least one trust snapshot.
    If missing and auto_refresh is True, attempts to refresh from the CA.

    Returns:
        (ready: bool, message: str | None)
    """
    snap = get_current_trust()
    if snap and snap.get("ca_root_pem"):
        return True, "Trust is ready."

    if not auto_refresh:
        return False, "No trust snapshot found. Please refresh in Settings."

    ok, msg = refresh_trust()
    if not ok:
        return False, msg
    return True, "Trust refreshed."
