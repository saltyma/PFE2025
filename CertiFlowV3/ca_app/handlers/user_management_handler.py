# ca_app/handlers/user_management_handler.py

from typing import List, Dict, Tuple
from datetime import datetime, timezone, timedelta

# --- Path setup to import other modules ---
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app import ca_db_helper
from ca_app.handlers import log_handler
from ca_app.handlers.log_handler import LogAction

# --- Core Handler Functions ---

def get_all_users_with_certificate_info() -> List[Dict]:
    """
    Retrieves all users and their certificate details using a single,
    efficient database call. This function is now a simple wrapper.
    """
    try:
        # This call to your new helper function does all the heavy lifting.
        return ca_db_helper.get_all_users_with_certs()
    except Exception as e:
        print(f"[ERROR] Failed to fetch users with certificate info: {e}")
        return []

def revoke_certificate(user_email: str, cert_serial: str, admin_id: int, reason: str) -> Tuple[bool, str]:
    """
    Revokes a user's certificate. The handler is now only responsible for
    calling the database helper and then logging the action.

    Args:
        user_email: The email of the user being revoked (for logging).
        cert_serial: The serial number of the certificate to revoke.
        admin_id: The ID of the administrator performing the action.
        reason: The reason for revocation, provided by the admin.

    Returns:
        A tuple (success, message).
    """
    if not reason or not reason.strip():
        return False, "A reason for revocation is required."

    try:
        # 1. Let the database helper handle the complex transaction
        # of updating the CRL and the user's status.
        ca_db_helper.revoke_certificate(cert_serial, reason)

        # 2. The handler's job is to log the completed action.
        log_handler.log_admin_action(
            admin_id,
            LogAction.USER_CERT_REVOKED,
            details={
                "revoked_user_email": user_email,
                "certificate_serial": cert_serial,
                "reason": reason
            }
        )

        return True, f"Successfully revoked certificate for {user_email}."
    except Exception as e:
        return False, f"An unexpected error occurred during revocation: {e}"

# --- Standalone Test Execution ---
if __name__ == "__main__":
    print("--- CA User Management Handler Test (using final db_helper) ---")

    # Dummy data for testing
    TEST_USER_EMAIL = "revoked.user@certiflow.app"
    TEST_HSM_ID = "hsm-revoke-test-456"
    TEST_ADMIN_EMAIL = "test.admin@certiflow.ca"
    
    try:
        # --- Test Setup ---
        print("\n[SETUP] Ensuring a clean test user and an active certificate...")
        
        # Ensure test admin exists
        admin = ca_db_helper.get_admin(TEST_ADMIN_EMAIL)
        if not admin:
            ca_db_helper.add_admin(TEST_ADMIN_EMAIL, "HSM_ADMIN_123")
            admin = ca_db_helper.get_admin(TEST_ADMIN_EMAIL)
        admin_id = admin['id']

        # Ensure test user exists with 'active' status
        ca_db_helper.add_user(TEST_USER_EMAIL, TEST_HSM_ID, status="verified")
        user = ca_db_helper.get_user(TEST_USER_EMAIL)
        user_id = user['id']
        
        # Add a dummy certificate to be revoked
        dummy_serial = f"TEST_REVOKE_SERIAL_{int(datetime.now().timestamp())}"
        dummy_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
        valid_from = datetime.now(timezone.utc) - timedelta(days=10)
        valid_to = datetime.now(timezone.utc) + timedelta(days=355)
        ca_db_helper.add_certificate(user_id, dummy_serial, dummy_pem, valid_from, valid_to)
        print(f"   ✅ Created active user '{TEST_USER_EMAIL}' with cert serial '{dummy_serial}'.")

        print("\n[1] Fetching all users and their certificate info...")
        all_users = get_all_users_with_certificate_info()
        if all_users:
            print(f"   ✅ Found {len(all_users)} user(s).")
        else:
            raise Exception("Failed to fetch users.")

        print(f"\n[2] Revoking certificate '{dummy_serial}' for user '{TEST_USER_EMAIL}'...")
        revocation_reason = "Compromised key."
        success, message = revoke_certificate(
            user_email=TEST_USER_EMAIL, 
            cert_serial=dummy_serial, 
            admin_id=admin_id, 
            reason=revocation_reason
        )
        if success:
            print(f"   ✅ {message}")
        else:
            raise Exception(f"Revocation failed: {message}")

        print("\n[3] Verifying user status and CRL entry post-revocation...")
        revoked_user = ca_db_helper.get_user(TEST_USER_EMAIL)
        is_revoked = ca_db_helper.is_certificate_revoked(dummy_serial)
        
        if revoked_user and revoked_user['status'] == 'revoked' and is_revoked:
            print(f"   ✅ User status is correctly set to '{revoked_user['status']}'.")
            print(f"   ✅ Certificate serial '{dummy_serial}' is correctly listed as revoked.")
        else:
            raise Exception("Verification failed: User status or CRL not updated correctly.")

    except Exception as e:
        print(f"\n--- A TEST FAILED ---")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[4] Cleaning up test environment...")
        print("   ✅ Cleanup complete (manual cleanup may be needed in DB).")