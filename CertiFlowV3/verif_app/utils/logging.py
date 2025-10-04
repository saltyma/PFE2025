# Logging helper for the verifier app (optional).
# verif_app/utils/logging_handler.py

"""
Verifier Logging Handler
-------------------------
- Provides a standardized LogAction Enum for the Verifier app
- Wraps calls to ver_db_helper.log_action()
- Ensures all logs are consistent and easy to query in DB

Tables used: local_logs (see create_db.py)
"""

import json
from enum import Enum
from datetime import datetime, timezone

# Import the verifier DB helper
from ver_db_helper import log_action as db_log_action


class LogAction(Enum):
    """
    Defines standardized actions for the Verifier app.
    """
    VERIFICATION_SUCCESS = "VERIFICATION_SUCCESS"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    TRUST_REFRESH = "TRUST_REFRESH"
    APP_START = "APP_START"
    APP_EXIT = "APP_EXIT"
    ERROR = "VERIFIER_ERROR"


def log(action: LogAction, details: dict | None = None) -> tuple[bool, str | None]:
    """
    Creates a structured log entry.

    Args:
        action (LogAction): the standardized log action
        details (dict | None): optional dict with extra info

    Returns:
        (success: bool, error_message: str | None)
    """
    if not isinstance(action, LogAction):
        return (False, "Invalid log action (must be LogAction enum)")

    try:
        details_json = json.dumps(details) if details else "{}"
    except TypeError as e:
        return (False, f"Failed to serialize log details to JSON: {e}")

    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        db_log_action(action=action.value, timestamp_utc=timestamp, details_json=details_json)
        return (True, None)
    except Exception as e:
        return (False, f"Failed to write verifier log: {e}")
