# ca_app/handlers/log_handler.py

import json
from enum import Enum
from datetime import datetime
import sys
import os

# Path setup to import the database helper
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app import ca_db_helper


class LogAction(Enum):
    """
    Standardized, system-wide actions for logging in the CA application.
    """

    # --- Admin Session ---
    ADMIN_LOGIN_SUCCESS = "ADMIN_LOGIN_SUCCESS"
    ADMIN_LOGIN_FAILURE = "ADMIN_LOGIN_FAILURE"
    ADMIN_LOGOUT = "ADMIN_LOGOUT"
    ADMIN_PASSWORD_CHANGED = "ADMIN_PASSWORD_CHANGED"

    # --- User & Certificate Management ---
    USER_REQUEST_APPROVED = "USER_REQUEST_APPROVED"
    USER_REQUEST_REJECTED = "USER_REQUEST_REJECTED"
    USER_CERT_REVOKED = "USER_CERT_REVOKED"

    # --- Email Verification ---
    EMAIL_VERIFICATION_SENT = "EMAIL_VERIFICATION_SENT"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"

    # --- HSM Lifecycle (added) ---
    HSM_DETECTED = "HSM_DETECTED"
    HSM_BOUND = "HSM_BOUND"
    HSM_ACTIVATED = "HSM_ACTIVATED"
    HSM_CODE_REGENERATED = "HSM_CODE_REGENERATED"
    HSM_REVOKED = "HSM_REVOKED"

    # --- System & Admin Management ---
    ROOT_CA_GENERATED = "ROOT_CA_GENERATED"
    NEW_ADMIN_ADDED = "NEW_ADMIN_ADDED"
    ADMIN_REMOVED = "ADMIN_REMOVED"
    SYSTEM_BACKUP_SUCCESS = "SYSTEM_BACKUP_SUCCESS"
    SYSTEM_BACKUP_FAILURE = "SYSTEM_BACKUP_FAILURE"
    SYSTEM_RESTORE_SUCCESS = "SYSTEM_RESTORE_SUCCESS"
    SYSTEM_RESTORE_FAILURE = "SYSTEM_RESTORE_FAILURE"

    # --- General Errors ---
    APPLICATION_ERROR = "CA_APPLICATION_ERROR"
    DATABASE_ERROR = "CA_DATABASE_ERROR"


def _to_json(details) -> str:
    if details is None:
        return "{}"
    if isinstance(details, str):
        # assume it is already JSON or a raw message
        try:
            json.loads(details)
            return details
        except Exception:
            return json.dumps({"message": details})
    try:
        return json.dumps(details)
    except TypeError as e:
        # Fallback to string
        return json.dumps({"message": str(details)})


def log_admin_action(admin_id: int | None, action: LogAction, details: dict | str | None = None) -> tuple[bool, str | None]:
    """
    Create a structured log entry for an action performed by an administrator.
    """
    if not isinstance(action, LogAction):
        return (False, "Invalid log action; must be a LogAction enum value.")

    try:
        ca_db_helper.log_admin_action(
            admin_id=admin_id,
            action=action.value,
            details=_to_json(details),
        )
        return (True, None)
    except Exception as e:
        return (False, f"Failed to write admin log: {e}")


def log_user_action(user_id: int | None, action: LogAction, details: dict | str | None = None) -> tuple[bool, str | None]:
    """
    Create a structured log entry tied to a user (e.g., email verification events).
    """
    if not isinstance(action, LogAction):
        return (False, "Invalid log action; must be a LogAction enum value.")

    try:
        ca_db_helper.log_user_action(
            user_id=user_id,
            action=action.value,
            details=_to_json(details),
        )
        return (True, None)
    except Exception as e:
        return (False, f"Failed to write user log: {e}")


def get_all_logs() -> list[dict]:
    """
    Retrieve and format all logs from the database.
    The DB helper already parses JSON in details.
    """
    try:
        return ca_db_helper.get_logs()
    except Exception as e:
        print(f"[ERROR] Failed to retrieve logs from database: {e}")
        return []
