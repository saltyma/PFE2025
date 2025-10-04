# user_app/utils/logging_handler.py

import json
from enum import Enum
from datetime import datetime
from typing import List, Tuple

# --- App Imports ---
# Using a relative import is standard practice within a package.
try:
    from .. import db_helper
except ImportError:
    # This block allows the script to be run standalone for testing.
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import db_helper


# --- Standardized Log Actions ---

class LogAction(Enum):
    """
    Defines standardized actions for the User App's local logs.
    This ensures consistency across all handlers and pages.
    """
    # --- Application Lifecycle ---
    APP_START = "APP_START"
    APP_CLOSE = "APP_CLOSE"

    # --- Registration Flow ---
    REGISTRATION_STARTED = "REGISTRATION_STARTED"
    KEY_PAIR_GENERATED = "KEY_PAIR_GENERATED"
    KEY_PAIR_LOADED = "KEY_PAIR_LOADED"                  # NEW (V3)
    CSR_CREATED = "CSR_CREATED"
    CERT_REQUEST_SENT = "CERT_REQUEST_SENT"

    # --- Login Flow ---
    LOGIN_STARTED = "LOGIN_STARTED"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_PENDING = "LOGIN_PENDING"
    LOGIN_REJECTED = "LOGIN_REJECTED"
    LOGIN_FAILURE = "LOGIN_FAILURE"

    # --- Document Actions ---
    SIGN_DOCUMENT_SUCCESS = "SIGN_DOCUMENT_SUCCESS"
    SIGN_DOCUMENT_FAILURE = "SIGN_DOCUMENT_FAILURE"
    VERIFY_SIGNATURE_SUCCESS = "VERIFY_SIGNATURE_SUCCESS"
    VERIFY_SIGNATURE_FAILURE = "VERIFY_SIGNATURE_FAILURE"

    # --- Certificate Renewal ---
    CERT_RENEWAL_REQUESTED = "CERT_RENEWAL_REQUESTED"
    CERT_RENEWAL_SENT = "CERT_RENEWAL_SENT"

    # --- Hardware & HSM (V3 additions) ---
    HSM_NOT_FOUND = "HSM_NOT_FOUND"                      # NEW (V3)
    HSM_UNLOCKED = "HSM_UNLOCKED"                        # NEW (V3)
    HSM_ACTIVATE_OK = "HSM_ACTIVATE_OK"                  # NEW (V3, optional)
    HSM_ACTIVATE_FAIL = "HSM_ACTIVATE_FAIL"              # NEW (V3, optional)
    HSM_REMOVED = "HSM_REMOVED"
    KEY_PAIR_LOAD_FAILURE = "KEY_PAIR_LOAD_FAILURE"

    # --- Email / Verification (V3 addition) ---
    EMAIL_VERIFICATION_SENT = "EMAIL_VERIFICATION_SENT"  # NEW (V3)

    # --- General Errors ---
    APPLICATION_ERROR = "APPLICATION_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"


def log(action: LogAction, details: dict = None):
    """
    Creates a structured log entry in the local user cache.

    Args:
        action: A member of the LogAction Enum defining the event.
        details: An optional dictionary containing contextual information.
    """
    if not isinstance(action, LogAction):
        print(f"[Logging Error] Invalid action type: {type(action)}")
        return

    try:
        # Convert details dict to a JSON string for storage
        details_json = json.dumps(details) if details else "{}"
        db_helper.log_action(action.value, details_json)
    except Exception as e:
        print(f"[Logging Error] Failed to write log to database: {e}")


# --- Log Retrieval Function ---

def get_local_logs() -> list[dict]:
    """
    Retrieves all logs from the local cache database.

    Returns:
        A list of log dictionaries. The 'details' field is parsed from JSON.
    """
    try:
        logs_from_db = db_helper.get_logs()
        for log_entry in logs_from_db:
            try:
                log_entry['details'] = json.loads(log_entry['details'])
            except json.JSONDecodeError:
                pass
        return logs_from_db
    except Exception as e:
        print(f"[ERROR] Failed to retrieve logs: {e}")
        return []


def _parse_details(raw_details):
    if raw_details in (None, ""):
        return {}
    if isinstance(raw_details, dict):
        return dict(raw_details)
    if isinstance(raw_details, (bytes, bytearray)):
        raw_details = raw_details.decode("utf-8", errors="ignore")
    if isinstance(raw_details, str):
        try:
            return json.loads(raw_details) if raw_details.strip() else {}
        except json.JSONDecodeError:
            return {"message": raw_details}
    return {"message": str(raw_details)}


def _prepare_logs_for_sync(source: str = "user_app") -> Tuple[List[dict], List[int]]:
    rows = db_helper.get_logs()
    if not rows:
        return [], []

    payload: List[dict] = []
    ids: List[int] = []

    for row in reversed(rows):  # oldest first for chronological ordering
        log_id = row.get("id")
        action = row.get("action")
        timestamp = row.get("timestamp")
        if not action or not timestamp:
            continue

        details = _parse_details(row.get("details"))
        if not isinstance(details, dict):
            details = {"message": str(details)}

        details = {
            **details,
            "source": details.get("source") or source,
            "local_log_id": log_id,
        }

        payload.append({
            "action": action,
            "timestamp": timestamp,
            "details": details,
        })

        if isinstance(log_id, int):
            ids.append(log_id)

    return payload, ids


def sync_with_ca(email: str, *, source: str = "user_app") -> Tuple[bool, str]:
    """Push local logs to the CA owner database via the API."""

    if not email:
        return False, "Email is required to synchronize logs."

    entries, ids = _prepare_logs_for_sync(source=source)
    if not entries:
        return True, "No pending logs to sync."

    try:
        from utils import ca_sync_handler  # deferred import to avoid cycles during startup

        ok, msg = ca_sync_handler.sync_user_logs(email, entries)
    except Exception as exc:  # pragma: no cover - network errors, etc.
        return False, f"Failed to push logs to CA: {exc}"

    if ok:
        try:
            db_helper.delete_logs_by_ids(ids)
        except Exception as cleanup_err:
            return True, f"Logs synchronized but cleanup failed: {cleanup_err}"

    return ok, msg


# ---------- Example Usage (for standalone testing) ----------
if __name__ == "__main__":
    print("--- Logging Handler Test ---")

    print("\n[1] Logging a successful user login...")
    log(
        LogAction.LOGIN_SUCCESS,
        details={"email": "user@uit.ac.ma", "source_ip": "192.168.1.10"}
    )
    print("   ✅ Log entry created.")

    print("\n--- Retrieving all logs from local cache ---")
    all_logs = get_local_logs()
    if all_logs:
        for entry in all_logs:
            print(f"  - ID: {entry['id']}, Action: {entry['action']}, Details: {entry['details']}")
    else:
        print("   No logs found or an error occurred.")
