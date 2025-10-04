# ca_app/handlers/admin_management_handler.py

import os
import sys
import json
import uuid
import shutil
from datetime import datetime, timezone
from typing import List, Dict, Tuple

# --- Path setup to import other modules ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app import ca_db_helper
from ca_app.handlers import log_handler
from ca_app.handlers.log_handler import LogAction

# --- Import cryptography for key/cert handling ---
from cryptography.hazmat.primitives import serialization
from cryptography import x509

# --- Constants for HSM files ---
HSM_KEYSTORE_FILE = "ca_keystore.enc"
PUBLIC_CERT_FILE = "ca.cert.pem"
HSM_CONFIG_FILE = "config.json"


def _pubkeys_match(private_key, cert_obj) -> bool:
    try:
        pk_from_key = private_key.public_key()
        pk_from_cert = cert_obj.public_key()
        return getattr(pk_from_key, "public_numbers")() == getattr(pk_from_cert, "public_numbers")()
    except Exception:
        return False


def get_all_admins() -> List[Dict]:
    try:
        return ca_db_helper.get_all_admins()
    except Exception as e:
        print(f"[ERROR] Failed to fetch administrators: {e}")
        return []


def provision_new_admin_hsm(
    root_hsm_path: str,
    root_hsm_password: str,
    new_admin_email: str,
    new_admin_password: str,
    new_hsm_path: str,
    performing_admin_id: int
) -> Tuple[bool, str]:
    """
    Provision a new admin USB by re-encrypting the root CA private key for the new admin.
    Adds explicit verification that the key matches the public CA certificate both
    before copy and on the newly provisioned drive.
    """

    # 1. Inputs and basic checks
    if not all([root_hsm_path, root_hsm_password, new_admin_email, new_admin_password, new_hsm_path]):
        return False, "All fields are required."
    if root_hsm_path == new_hsm_path:
        return False, "The new admin's drive cannot be the same as the root admin's drive."
    if not os.path.isdir(new_hsm_path):
        return False, f"The selected path for the new admin's drive is not a valid directory: {new_hsm_path}"
    if ca_db_helper.get_admin(new_admin_email):
        return False, f"An admin with the email '{new_admin_email}' already exists."

    root_keystore_path = os.path.join(root_hsm_path, HSM_KEYSTORE_FILE)
    root_cert_path = os.path.join(root_hsm_path, PUBLIC_CERT_FILE)
    if not os.path.exists(root_keystore_path):
        return False, "Critical Error: Root CA keystore not found on the specified drive."
    if not os.path.exists(root_cert_path):
        return False, "Critical Error: Root CA certificate not found on the specified drive."

    try:
        # 2. Load and decrypt the root CA private key
        with open(root_keystore_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=root_hsm_password.encode('utf-8')
            )

        # 3. Verify key ↔ cert match BEFORE copy
        with open(root_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        if not _pubkeys_match(private_key, ca_cert):
            return False, "Provisioning failed: Root CA private key does not match the CA certificate on the root HSM."

        # 4. Re-encrypt the key for the new admin
        new_encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(new_admin_password.encode('utf-8'))
        )

        # 5. Write to the new admin drive
        new_keystore_path = os.path.join(new_hsm_path, HSM_KEYSTORE_FILE)
        with open(new_keystore_path, "wb") as f:
            f.write(new_encrypted_pem)

        # Copy the public certificate alongside
        shutil.copy2(root_cert_path, os.path.join(new_hsm_path, PUBLIC_CERT_FILE))

        # Create config with a unique HSM ID
        new_hsm_id = f"CA-HSM-SEC-{uuid.uuid4().hex[:12].upper()}"
        config_data = {
            "hsm_id": new_hsm_id,
            "type": "CA_OWNER",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        with open(os.path.join(new_hsm_path, HSM_CONFIG_FILE), "w") as f:
            json.dump(config_data, f, indent=4)

        # 6. FINAL VERIFICATION ON THE NEW DRIVE
        #    Decrypt with the new password and check it matches the copied cert.
        with open(new_keystore_path, "rb") as f:
            new_priv = serialization.load_pem_private_key(
                f.read(),
                password=new_admin_password.encode('utf-8')
            )
        with open(os.path.join(new_hsm_path, PUBLIC_CERT_FILE), "rb") as f:
            new_cert = x509.load_pem_x509_certificate(f.read())

        if not _pubkeys_match(new_priv, new_cert):
            # Clean up the key file to avoid leaving a broken device around
            try:
                os.remove(new_keystore_path)
            except Exception:
                pass
            return False, "Provisioning failed: New keystore does not match the CA certificate on the new HSM."

        # 7. Update DB and log
        ca_db_helper.add_admin(new_admin_email, new_hsm_id, is_root=False)
        log_handler.log_admin_action(
            admin_id=performing_admin_id,
            action=LogAction.NEW_ADMIN_ADDED,
            details={"new_admin_email": new_admin_email, "new_admin_hsm_id": new_hsm_id}
        )
        return True, f"Successfully provisioned HSM and added new administrator '{new_admin_email}'."

    except (ValueError, TypeError):
        return False, "Provisioning failed: Incorrect password for the root admin's HSM."
    except Exception as e:
        return False, f"An unexpected error occurred during provisioning: {e}"


def remove_admin(admin_id_to_remove: int, performing_admin_id: int) -> Tuple[bool, str]:
    if admin_id_to_remove == performing_admin_id:
        return False, "Cannot remove your own administrator account."

    admin_to_remove = ca_db_helper.get_admin_by_id(admin_id_to_remove)
    if not admin_to_remove:
        return False, "The specified administrator does not exist."

    try:
        ca_db_helper.delete_admin(admin_id_to_remove)
        log_handler.log_admin_action(
            admin_id=performing_admin_id,
            action=LogAction.ADMIN_REMOVED,
            details={"removed_admin_email": admin_to_remove['email'], "removed_admin_id": admin_id_to_remove}
        )
        return True, f"Successfully removed administrator '{admin_to_remove['email']}'."
    except Exception as e:
        return False, f"A database error occurred while removing the admin: {e}"
