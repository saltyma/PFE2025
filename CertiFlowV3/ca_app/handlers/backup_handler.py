# Implements database backup and restore functionality.
# ca_app/handlers/backup_handler.py

import os
import shutil
from datetime import datetime
from typing import Tuple

# --- Path setup to find the database and handlers ---
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app import ca_db_helper
from ca_app.handlers import log_handler
from ca_app.handlers.log_handler import LogAction

# --- Constants ---
SOURCE_DB_PATH = ca_db_helper.DB_PATH

# --- Core Backup and Restore Functions ---

def create_backup(backup_directory: str, performing_admin_id: int) -> Tuple[bool, str]:
    """
    Creates a timestamped backup of the main CA database file.
    """
    if not os.path.exists(SOURCE_DB_PATH):
        # No need to log this as it's a pre-condition failure, not a failed action
        return False, f"Backup failed: Source database not found at '{SOURCE_DB_PATH}'."

    try:
        os.makedirs(backup_directory, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_filename = f"ca_backup_{timestamp}.sqlite"
        destination_path = os.path.join(backup_directory, backup_filename)

        shutil.copy2(SOURCE_DB_PATH, destination_path)

        # --- LOG SUCCESS ---
        log_handler.log_admin_action(
            performing_admin_id,
            LogAction.SYSTEM_BACKUP_SUCCESS,
            details={"backup_path": destination_path}
        )
        return True, f"Backup successful. Saved to: {destination_path}"
    except Exception as e:
        # --- LOG FAILURE ---
        log_handler.log_admin_action(
            performing_admin_id,
            LogAction.SYSTEM_BACKUP_FAILURE,
            details={"error": str(e)}
        )
        return False, f"Backup failed: An error occurred while copying the file. Error: {e}"


def restore_from_backup(backup_file_path: str, performing_admin_id: int) -> Tuple[bool, str]:
    """
    Restores the CA database from a specified backup file.
    """
    if not os.path.exists(backup_file_path):
        return False, f"Restore failed: Backup file not found at '{backup_file_path}'."

    try:
        shutil.copy2(backup_file_path, SOURCE_DB_PATH)
        # --- LOG SUCCESS ---
        log_handler.log_admin_action(
            performing_admin_id,
            LogAction.SYSTEM_RESTORE_SUCCESS,
            details={"restored_from": backup_file_path}
        )
        return True, "Database successfully restored from backup."
    except Exception as e:
        # --- LOG FAILURE ---
        log_handler.log_admin_action(
            performing_admin_id,
            LogAction.SYSTEM_RESTORE_FAILURE,
            details={"backup_path": backup_file_path, "error": str(e)}
        )
        return False, f"Restore failed: An error occurred while copying the file. Error: {e}"
