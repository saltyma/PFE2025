# ca_app/handlers/request_handler.py

import sys
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Tuple

# --- Path setup to import other modules ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app import ca_db_helper
from ca_app.handlers import log_handler, email_handler
from ca_app.handlers.log_handler import LogAction

# --- Cryptography (ECC) ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# --- Constants ---
CA_CERT_PATH = os.path.join(os.path.dirname(__file__), "..", "ca.cert.pem")
DEFAULT_VALIDITY_DAYS = 365


def create_pending_request(email: str, hsm_id: str, csr_pem: str) -> Tuple[bool, str]:
    """
    Create a pending request for the given email + CSR + HSM.
    - Ensures we don't duplicate users/HSM ownership.
    - Persists CSR pinned to the specific HSM (via hsm_id_hash/hsm_id_enc).
    - Tries to send a verification email (does NOT hard-fail the request if email send fails).
    """
    try:
        # Reject if a user already exists (prevents duplicates/hijack)
        existing = ca_db_helper.get_user(email)
        if existing:
            return False, "A user with this email already exists."

        # Reject if this HSM is already tied to some user
        if hsm_id and ca_db_helper.get_user_by_hsm_id(hsm_id):
            return False, "A user with this HSM ID already exists."

        # Create user
        ca_db_helper.add_user(email=email, status="pending")
        user = ca_db_helper.get_user(email)
        if not user:
            return False, "Failed to create user record."

        # Queue CSR pinned to the exact HSM
        if not ca_db_helper.add_pending_request(user['id'], email, csr_pem, hsm_id):
            return False, "Failed to queue CSR. Please check if a request already exists."


        # Send verification (use signed, DB-backed handler). Don't hard-fail CSR if email fails.
        email_sent = False
        msg = ""
        try:
            email_sent, msg = email_handler.send_verification_email(email)
        except Exception as ex:
            msg = str(ex)

        if not email_sent:
            log_handler.log_admin_action(
                admin_id=None,
                action=LogAction.APPLICATION_ERROR,
                details={"error": f"Failed to send verification email to {email}: {msg}"}
            )
            return True, "Request created, but verification email could not be sent. Try resending later."

        return True, "Request created and verification email sent."

    except Exception as e:
        return False, f"Unexpected error: {e}"


def get_pending_requests() -> List[Dict]:
    """Return all pending requests with verification flags for the dashboard."""
    try:
        return ca_db_helper.get_pending_requests()
    except Exception as e:
        print(f"[ERROR] Failed to fetch pending requests: {e}")
        return []


def _issuer_sanity_check(ca_private_key, ca_cert) -> Tuple[bool, str]:
    """
    Verify that the loaded CA private key matches the CA certificate's public key
    and that the certificate is actually a CA cert.
    """
    try:
        pk_from_key = ca_private_key.public_key()
        pk_from_cert = ca_cert.public_key()

        # Both should be EC keys
        if not isinstance(pk_from_key, ec.EllipticCurvePublicKey) or not isinstance(pk_from_cert, ec.EllipticCurvePublicKey):
            return False, "Issuer sanity check failed: Non-EC key detected."

        if pk_from_key.public_numbers() != pk_from_cert.public_numbers():
            return False, "Issuer sanity check failed: CA key does not match CA certificate."

        # BasicConstraints: CA must be true
        try:
            bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                return False, "Issuer sanity check failed: CA certificate is not marked as a CA."
        except x509.ExtensionNotFound:
            return False, "Issuer sanity check failed: Missing BasicConstraints on CA certificate."

        return True, "OK"
    except Exception as ex:
        return False, f"Issuer sanity check failed: {str(ex)}"


def approve_request(request_id: int, admin_id: int, admin_hsm_path: str, admin_hsm_password: str) -> Tuple[bool, str]:
    """
    Approve a pending request and issue an ECC certificate.
    Enforces the three checks (on the exact device tied to the request):
      - HSM bound to user's email
      - HSM activated
      - Email verified
    Also performs issuer sanity check and logs issuance.
    NOTE: This function no longer deletes the pending request; caller should do that after success.
    """
    # Load exactly one pending request with its HSM context
    pending_request = ca_db_helper.get_pending_request_by_id(request_id)
    if not pending_request:
        return False, "Request not found or no longer pending."

    status = pending_request.get('verification_status', {})
    if not status.get('hsm_bound'):
        return False, "Approval failed: HSM is not bound to the user's email."
    if not status.get('hsm_activated'):
        return False, "Approval failed: HSM has not been activated with the provided code."
    if not status.get('email_verified'):
        return False, "Approval failed: User's email address is not verified."

    user_id = pending_request['user_id']
    user = ca_db_helper.get_user_by_id(user_id)
    if not user:
        return False, f"User with ID {user_id} not found."

    user_email = user['email']
    csr_pem = pending_request['csr_pem']
    hsm_id_plain = pending_request.get('hsm_id')  # may be None if KMS key not configured

    try:
        # Load CA private key from admin's HSM folder and the CA certificate
        keystore_path = os.path.join(admin_hsm_path, "ca_keystore.enc")
        if not os.path.exists(keystore_path):
            return False, "CA keystore not found on the provided HSM path."

        with open(keystore_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=admin_hsm_password.encode()
            )

        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Issuer sanity check
        ok, why = _issuer_sanity_check(ca_private_key, ca_cert)
        if not ok:
            return False, why

        # Load CSR and verify its signature
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            return False, "CSR signature is invalid."

        # Build certificate
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=DEFAULT_VALIDITY_DAYS))
        )
        # Copy CSR extensions
        for extension in csr.extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)

        # Sign with CA private key (ECDSA with SHA-256)
        new_cert = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
        new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # `cryptography` compatibility for validity timestamps
        valid_from = getattr(new_cert, "not_valid_before_utc", new_cert.not_valid_before)
        valid_to   = getattr(new_cert, "not_valid_after_utc",  new_cert.not_valid_after)

        # Persist certificate, pinning it to this HSM
        ca_db_helper.add_certificate(
            user_id=user_id,
            cert_serial=str(new_cert.serial_number),
            cert_pem=new_cert_pem,
            valid_from=valid_from,
            valid_to=valid_to,
            email=user_email,
            hsm_id=hsm_id_plain
        )

        # Update user status; DO NOT delete pending request here (caller/API does that)
        ca_db_helper.update_user_status(user_id, "verified")

        # Log issuance details
        log_handler.log_admin_action(
            admin_id=admin_id,
            action=LogAction.USER_REQUEST_APPROVED,
            details={
                "approved_user_email": user_email,
                "cert_serial": str(new_cert.serial_number),
                "valid_from": valid_from.isoformat() if hasattr(valid_from, "isoformat") else str(valid_from),
                "valid_to": valid_to.isoformat() if hasattr(valid_to, "isoformat") else str(valid_to),
            },
        )

        return True, f"Certificate issued successfully for {user_email}."

    except (ValueError, TypeError):
        # Likely incorrect HSM password or wrong keystore file
        return False, "Approval failed: could not unlock the CA private key with the provided password."
    except Exception as e:
        return False, f"Failed to approve request: {e}"


def reject_request(request_id: int, admin_id: int, reason: str) -> Tuple[bool, str]:
    """Reject a pending request and log the action with a reason."""
    pending_request = ca_db_helper.get_pending_request_by_id(request_id)
    if not pending_request:
        return False, "Request not found or no longer pending."

    user_email = pending_request['email']
    user_id = pending_request['user_id']

    try:
        ca_db_helper.delete_pending_request(request_id)
        ca_db_helper.update_user_status(user_id, "rejected")
        log_handler.log_admin_action(
            admin_id=admin_id,
            action=LogAction.USER_REQUEST_REJECTED,
            details={"rejected_user_email": user_email, "reason": reason},
        )
        return True, f"Request for {user_email} rejected."
    except Exception as e:
        return False, f"Error rejecting request: {e}"


def create_renewal_request(email: str, csr_pem: str, hsm_id: str = "") -> Tuple[bool, str]:
    """
    Create a renewal request. Keeps the CSR pipeline identical, but without a new HSM binding.
    """
    user = ca_db_helper.get_user(email)
    if not user:
        return False, "User not found."
    ca_db_helper.update_user_status(user['id'], "pending_renewal")
    # Renewal does not enforce a new HSM here; pass only CSR
    if not ca_db_helper.add_pending_request(user['id'], email, csr_pem, hsm_id, is_renewal=True):
        return False, "Failed to queue renewal request. Please try again."

    return True, "Renewal request created and is awaiting approval."


# --- Standalone Smoke Test ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Request Handler Smoke Test")
    parser.add_argument("test_name", choices=['create', 'approve', 'reject'], help="Function to test.")
    parser.add_argument("--email", type=str, default="test.approve@certiflow.app")
    parser.add_argument("--hsm_id", type=str, default="hsm-test-approve-123")
    args = parser.parse_args()

    print("--- Request Handler Smoke Test ---")

    # Create a dummy ECC CSR
    user_priv_key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Test User"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, args.email),
    ]))
    dummy_csr_pem = builder.sign(user_priv_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    if args.test_name == 'create':
        ok, msg = create_pending_request(args.email, args.hsm_id, dummy_csr_pem)
        print(("SUCCESS: " if ok else "FAIL: ") + msg)

    elif args.test_name == 'reject':
        user = ca_db_helper.get_user(args.email)
        if not user or user.get('status') not in ('pending', 'pending_renewal'):
            create_pending_request(args.email, args.hsm_id, dummy_csr_pem)
        reqs = ca_db_helper.get_pending_requests()
        test_req = next((r for r in reqs if r['email'] == args.email), None)
        if not test_req:
            print("FAIL: No pending request to reject.")
        else:
            ok, msg = reject_request(test_req['id'], 1, "Test rejection")
            print(("SUCCESS: " if ok else "FAIL: ") + msg)

    elif args.test_name == 'approve':
        print("INFO: approval requires a real keystore and password; expect unlock errors in a dry run.")
        print("Create request first, then run approve to observe checks and error messages.")
