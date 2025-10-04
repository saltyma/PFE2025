# ca_app/handlers/setup_handler.py

import os
import sys
import json
import uuid
from datetime import datetime, timezone, timedelta

# --- Path setup ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app import ca_db_helper
from ca_app.handlers import log_handler
from ca_app.handlers.log_handler import LogAction

# --- Cryptography Imports ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
# MODIFIED: Import ec for Elliptic Curve, remove rsa
from cryptography.hazmat.primitives.asymmetric import ec

# --- Constants ---
HSM_KEYSTORE_FILE = "ca_keystore.enc"
HSM_CONFIG_FILE = "config.json"
PUBLIC_CERT_FILE = "ca.cert.pem"

# --- HEAVILY MODIFIED FUNCTION ---
def initialize_root_ca(email: str, password: str, hsm_path: str) -> tuple[bool, str]:
    """
    Performs the one-time setup for the root CA using ECC.
    Generates an ECC key, creates the root cert, encrypts the key to the HSM,
    and creates the first root admin account.
    """
    try:
        # 1. Generate a new ECC private key using the SECP256R1 curve (P-256)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # 2. Create the self-signed root certificate
        # Using a distinguished name for the CA.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"MA"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Rabat-Sale-Kenitra"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kenitra"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Ibn Tofail University"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"CertiFlow Root CA v3"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365 * 10) # 10-year validity
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256()) # Sign the certificate with its own private key

        # 3. Encrypt and save the private key to the HSM path
        encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )
        with open(os.path.join(hsm_path, HSM_KEYSTORE_FILE), "wb") as f:
            f.write(encrypted_pem)

        # 4. Save the public certificate to the HSM and the app directory
        public_cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(os.path.join(hsm_path, PUBLIC_CERT_FILE), "wb") as f:
            f.write(public_cert_pem)
        
        app_cert_path = os.path.join(os.path.dirname(__file__), '..', PUBLIC_CERT_FILE)
        with open(app_cert_path, "wb") as f:
            f.write(public_cert_pem)

        # 5. Create the HSM config file
        hsm_id = f"CA-HSM-{uuid.uuid4().hex[:12].upper()}"
        config_data = {
            "hsm_id": hsm_id,
            "type": "CA_OWNER",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        with open(os.path.join(hsm_path, HSM_CONFIG_FILE), "w") as f:
            json.dump(config_data, f, indent=4)

        # 6. Add the root admin to the database
        ca_db_helper.add_admin(email, hsm_id, is_root=True)
        admin = ca_db_helper.get_admin(email)

        # 7. Log this critical event
        if admin:
            log_handler.log_admin_action(
                admin_id=admin['id'],
                action=LogAction.ROOT_CA_GENERATED,
                details={"admin_email": email, "hsm_id": hsm_id}
            )

        return True, "Root CA and administrator account created successfully."

    except Exception as e:
        import traceback
        traceback.print_exc()
        return False, f"Setup failed: {e}"

# --- Standalone Smoke Test ---
if __name__ == "__main__":
    import argparse
    
    # Check if this is the first run. If not, the test shouldn't proceed.
    if not ca_db_helper.get_all_admins():
        print("--- Setup Handler Smoke Test ---")
        
        parser = argparse.ArgumentParser(description="Initialize the Root CA.")
        parser.add_argument("email", type=str, help="Email for the root administrator.")
        parser.add_argument("password", type=str, help="Password to encrypt the new CA private key.")
        parser.add_argument("hsm_path", type=str, help="Path to a directory (e.g., a USB drive) to store the CA keystore.")
        
        args = parser.parse_args()

        if not os.path.isdir(args.hsm_path):
            print(f"Error: The provided HSM path '{args.hsm_path}' is not a valid directory.")
            sys.exit(1)

        print(f"\n[TEST] Initializing Root CA for '{args.email}'...")
        print(f"       HSM Keystore will be saved to: '{args.hsm_path}'")
        
        success, message = initialize_root_ca(args.email, args.password, args.hsm_path)
        
        if success:
            print(f"\n   ✅ SUCCESS: {message}")
            admin = ca_db_helper.get_admin(args.email)
            print("   --- Verification ---")
            print(f"   Admin Email: {admin.get('email')}")
            print(f"   Admin HSM ID: {admin.get('hsm_id')}")
            print(f"   Is Root: {admin.get('is_root')}")
            print(f"   Keystore created at: {os.path.join(args.hsm_path, HSM_KEYSTORE_FILE)}")

        else:
            print(f"\n   ❌ FAILURE: {message}")
            
        print("\n--- TEST COMPLETED ---")

    else:
        print("--- Setup Handler Smoke Test ---")
        print("INFO: A root administrator already exists in the database.")
        print("      To re-run initialization, please delete the ca_database.sqlite file.")
        print("---------------------------------")
