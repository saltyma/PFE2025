# ca_app/handlers/auth_handler.py

import os
import sys
import json
from typing import Tuple, Dict, Optional

# --- Path setup to import other modules ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app import ca_db_helper
from ca_app.handlers import log_handler
from ca_app.handlers.log_handler import LogAction

# --- Import Cryptography libraries ---
from cryptography.hazmat.primitives import serialization
from cryptography import x509

# --- Constants for files expected on the HSM ---
HSM_CONFIG_FILE = "config.json"
HSM_KEYSTORE_FILE = "ca_keystore.enc"
HSM_CERT_FILE = "ca.cert.pem"


def _pubkeys_match(private_key, cert_obj) -> bool:
    """Return True if private_key.public_key() equals cert public key."""
    try:
        pk_from_key = private_key.public_key()
        pk_from_cert = cert_obj.public_key()
        return getattr(pk_from_key, "public_numbers")() == getattr(pk_from_cert, "public_numbers")()
    except Exception:
        return False


def check_first_run() -> bool:
    try:
        return not ca_db_helper.get_all_admins()
    except Exception:
        return True


def admin_login(email: str, hsm_path: str, hsm_password: str) -> Tuple[bool, str, Optional[Dict]]:
    admin = ca_db_helper.get_admin(email)
    if not admin:
        return False, f"Login Failed: No administrator found with the email '{email}'.", None

    admin_id = admin['id']
    expected_hsm_id = admin['hsm_id']

    if not os.path.isdir(hsm_path):
        return False, f"Login Failed: The selected path '{hsm_path}' is not a valid directory.", None

    config_path = os.path.join(hsm_path, HSM_CONFIG_FILE)
    if not os.path.exists(config_path):
        return False, f"Login Failed: The selected drive is not a valid CA HSM (missing '{HSM_CONFIG_FILE}').", None

    try:
        with open(config_path, 'r') as f:
            hsm_config = json.load(f)

        hsm_id_on_drive = hsm_config.get('hsm_id')
        if hsm_id_on_drive != expected_hsm_id:
            log_handler.log_admin_action(admin_id, LogAction.ADMIN_LOGIN_FAILURE, {"reason": "HSM ID Mismatch"})
            return False, "Login Failed: HSM ID mismatch. This is not the correct USB drive for this admin account.", None

    except (json.JSONDecodeError, KeyError):
        return False, f"Login Failed: The HSM config file '{HSM_CONFIG_FILE}' is corrupted or invalid.", None

    keystore_path = os.path.join(hsm_path, HSM_KEYSTORE_FILE)
    if not os.path.exists(keystore_path):
        return False, f"Login Failed: The HSM is missing its encrypted keystore ('{HSM_KEYSTORE_FILE}').", None

    cert_path = os.path.join(hsm_path, HSM_CERT_FILE)
    if not os.path.exists(cert_path):
        return False, f"Login Failed: Missing public CA certificate ('{HSM_CERT_FILE}') on the HSM.", None

    try:
        # Decrypt private key
        with open(keystore_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=hsm_password.encode('utf-8')
            )

        # Load certificate and verify match
        with open(cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        if not _pubkeys_match(private_key, ca_cert):
            log_handler.log_admin_action(admin_id, LogAction.ADMIN_LOGIN_FAILURE, {"reason": "Key-Cert Mismatch"})
            return False, "Login Failed: CA private key does not match the CA certificate on the HSM.", None

        log_handler.log_admin_action(admin_id, LogAction.ADMIN_LOGIN_SUCCESS)
        return True, "Login successful.", admin

    except (ValueError, TypeError):
        log_handler.log_admin_action(admin_id, LogAction.ADMIN_LOGIN_FAILURE, {"reason": "Incorrect Password"})
        return False, "Login Failed: Incorrect password.", None
    except Exception as e:
        log_handler.log_admin_action(admin_id, LogAction.ADMIN_LOGIN_FAILURE, {"reason": f"Keystore Decryption Error: {e}"})
        return False, f"Login Failed: An unexpected error occurred while reading the keystore: {e}", None


def change_admin_password(admin_id: int, hsm_path: str, old_password: str, new_password: str) -> Tuple[bool, str]:
    """
    Re-encrypt the keystore with a new password, but only after verifying
    the key ↔ cert match on the HSM to avoid re-encrypting a wrong key.
    """
    keystore_path = os.path.join(hsm_path, HSM_KEYSTORE_FILE)
    cert_path = os.path.join(hsm_path, HSM_CERT_FILE)

    if not os.path.exists(keystore_path):
        return False, "Password change failed: Keystore file not found on the HSM."
    if not os.path.exists(cert_path):
        return False, "Password change failed: Public CA certificate not found on the HSM."

    try:
        # 1) Decrypt current private key using old password
        with open(keystore_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=old_password.encode('utf-8')
            )

        # 2) Verify key ↔ cert match before re-encryption
        from cryptography import x509
        with open(cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        if not _pubkeys_match(private_key, ca_cert):
            return False, "Password change failed: CA private key does not match the CA certificate on this HSM."

        # 3) Re-encrypt with the new password
        new_encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(new_password.encode('utf-8'))
        )

        with open(keystore_path, "wb") as f:
            f.write(new_encrypted_pem)

        # 4) Log success
        admin_user = ca_db_helper.get_admin_by_id(admin_id)
        log_handler.log_admin_action(
            admin_id,
            LogAction.ADMIN_PASSWORD_CHANGED,
            details={"admin_email": admin_user.get('email', 'N/A')}
        )
        return True, "Password changed successfully."

    except (ValueError, TypeError):
        return False, "Password change failed: The 'Current Password' is incorrect."
    except Exception as e:
        return False, f"An unexpected error occurred: {e}"
