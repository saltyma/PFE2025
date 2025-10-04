# CertiFlow V3 — Registration flow (COM HSM + activation code + ECC CSR)

from __future__ import annotations

from typing import Tuple, Optional, Callable
import time

import db_helper
from utils import email_verifier, ca_sync_handler, certificate, logging_handler, hsm_handler
from utils.logging_handler import LogAction


# ------------------------------
# Internal helpers
# ------------------------------

def _sign_with_hsm_sha256(hsm: hsm_handler.HSMClient) -> Callable[[bytes], bytes]:
    """
    Returns a callback that signs a SHA-256 digest with the connected HSM and
    returns a DER-encoded ECDSA signature as bytes.
    """
    def _cb(digest: bytes) -> bytes:
        try:
            return hsm.sign_sha256_bytes(digest)
        except ValueError as exc:
            raise ValueError(str(exc))
    return _cb


def _detect_and_connect_hsm(
    expected_hsm_id: Optional[str] = None,
    stop_flag: Optional[Callable[[], bool]] = None,
) -> Tuple[Optional[hsm_handler.HSMClient], Optional[str], Optional[str]]:
    """
    Detect an HSM on COM ports and connect to it.
    Returns (client, hsm_id, error).
    """
    if stop_flag and stop_flag():
        return None, None, "__cancelled__"
    client = hsm_handler.HSMClient()
    hsm_id, err = client.detect_and_connect(expected_hsm_id=expected_hsm_id, stop_flag=stop_flag)
    if stop_flag and stop_flag():
        client.close()
        return None, None, "__cancelled__"
    if err:
        client.close()
        return None, None, f"No HSM detected: {err}"
    return client, hsm_id, None


# ------------------------------
# Public API
# ------------------------------

def register_new_user(
    email: str,
    full_name: str,
    activation_code: str,
    pin: str,
    expected_hsm_id: Optional[str] = None,
    stop_flag: Optional[Callable[[], bool]] = None,
) -> Tuple[bool, str]:
    """
    V3 registration funnel:
      1) Detect COM HSM and read HSMID
      2) Activate device with CA using activation_code
      3) UNLOCK <pin> (first-time NEWPIN), KEYGEN EC P256 if needed, PUBKEY
      4) Build CSR (SAN=email, OID=HSMID), submit to CA
      5) Cache user locally and return next-step instructions
    """

    # Step 0: validate inputs
    def _cancelled() -> bool:
        return bool(stop_flag and stop_flag())

    logging_handler.log(LogAction.REGISTRATION_STARTED, {"email": email, "name": full_name})

    if _cancelled():
        return False, "__cancelled__"
    is_valid, msg = email_verifier.is_valid_institutional_email(email)
    if not is_valid:
        logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"Invalid email: {msg}"})
        return False, msg

    activation_code = (activation_code or "").strip()
    pin = (pin or "").strip()
    if not activation_code or not pin:
        return False, "Activation code and HSM PIN are required."

    # Detect and connect HSM
    hsm, hsm_id, err = _detect_and_connect_hsm(expected_hsm_id, stop_flag=stop_flag)
    if err:
        if err != "__cancelled__":
            logging_handler.log(LogAction.HSM_NOT_FOUND, {"reason": err})
        return False, err

    try:
        if _cancelled():
            return False, "__cancelled__"

        # Step 1: Activate the device on CA (retry once on transient failure)
        ok, msg = ca_sync_handler.activate_device(hsm_id, activation_code)
        if _cancelled():
            return False, "__cancelled__"
        activation_synced = bool(ok)
        if not ok:
            time.sleep(0.5)
            ok2, msg2 = ca_sync_handler.activate_device(hsm_id, activation_code)
            ok = ok2
            msg = msg2 if msg2 else msg
            activation_synced = bool(ok)
            if _cancelled():
                return False, "__cancelled__"
        if not ok:
            error_message = msg or "Activation failed."
            logging_handler.log(
                LogAction.APPLICATION_ERROR,
                {"reason": f"Activation failed: {error_message}", "hsm_id": hsm_id},
            )
            return False, f"Activation failed: {error_message}"

        # Mirror basic flags locally after activation attempt
        db_helper.add_or_update_user(email, hsm_id)
        db_helper.set_verification_flags(
            email,
            activation_consumed=1 if activation_synced else 0,
            device_bound=1 if activation_synced else 0,
        )

        # Step 2: Unlock session with PIN (first unlock sets the PIN: NEWPIN)
        if _cancelled():
            return False, "__cancelled__"

        mode, err = hsm.unlock(pin)
        if err:
            logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"HSM unlock failed: {err}", "hsm_id": hsm_id})
            return False, f"HSM unlock failed: {err}"
        logging_handler.log(LogAction.HSM_UNLOCKED, {"mode": mode, "hsm_id": hsm_id})

        # Step 3: Ensure EC key exists
        if _cancelled():
            return False, "__cancelled__"
        mode, err = hsm.keygen_ec_p256()
        if err:
            logging_handler.log(LogAction.KEY_PAIR_LOAD_FAILURE, {"reason": err, "hsm_id": hsm_id})
            return False, f"Failed to prepare key on HSM: {err}"
        logging_handler.log(LogAction.KEY_PAIR_GENERATED, {"mode": mode, "hsm_id": hsm_id})

        # Step 4: Fetch SPKI (base64 DER)
        if _cancelled():
            return False, "__cancelled__"
        spki_b64, err = hsm.pubkey_spki_b64()
        if err or not spki_b64:
            logging_handler.log(LogAction.KEY_PAIR_LOAD_FAILURE, {"reason": err or "No PUBKEY", "hsm_id": hsm_id})
            return False, f"Failed to fetch public key from HSM: {err or 'unknown error'}"

        # Step 5: Build CSR (SAN=email + custom OID with HSMID) and sign via HSM
        if _cancelled():
            return False, "__cancelled__"
        sign_cb = _sign_with_hsm_sha256(hsm)
        csr_pem, err = certificate.build_csr_pem_with_hsm_sign(
            email=email,
            common_name=full_name,
            hsm_id=hsm_id,
            spki_b64=spki_b64,
            sign_digest_cb=sign_cb,
        )
        if err or not csr_pem:
            logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"CSR build failed: {err}", "hsm_id": hsm_id})
            msg = err or "unknown error"
            if msg.startswith("Signing error:"):
                return False, msg
            return False, f"CSR build failed: {msg}"

        logging_handler.log(LogAction.CSR_CREATED, {"email": email, "hsm_id": hsm_id})

        # Step 6: Submit CSR to CA
        if _cancelled():
            return False, "__cancelled__"
        ok, msg = ca_sync_handler.submit_csr(email=email, hsm_id=hsm_id, csr_pem=csr_pem)
        if not ok:
            logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"CSR submit failed: {msg}", "hsm_id": hsm_id})
            return False, f"Failed to submit CSR: {msg}"

        logging_handler.log(LogAction.CERT_REQUEST_SENT, {"email": email, "hsm_id": hsm_id})

        # Cache user locally; leave email_verified to be flipped after user clicks email link
        if _cancelled():
            return False, "__cancelled__"
        db_helper.add_or_update_user(email, hsm_id)

        # Final guidance
        if _cancelled():
            return False, "__cancelled__"
        return True, (
            "Registration submitted. Please check your inbox to verify your email, "
            "then wait for CA approval."
        )

    finally:
        hsm.close()


def resend_verification(email: str) -> Tuple[bool, str]:
    """
    Optional helper to explicitly trigger a verification email via CA.
    """
    is_valid, msg = email_verifier.is_valid_institutional_email(email)
    if not is_valid:
        return False, msg

    ok, message = ca_sync_handler.send_verification_email(email)
    if ok:
        logging_handler.log(LogAction.EMAIL_VERIFICATION_SENT, {"email": email})
    else:
        logging_handler.log(LogAction.NETWORK_ERROR, {"reason": message})
    return ok, message


# ------------------------------
# Smoke Test (run this module directly)
# ------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Registration Handler • Smoke Test (end-to-end)")
    parser.add_argument("--email", required=True, help="User email (will receive verification if SMTP configured)")
    parser.add_argument("--full-name", required=True, help="User full name for CSR subject CN")
    parser.add_argument("--pin", required=True, help="PIN to set or use on the HSM (emulator)")
    parser.add_argument("--activation-code", default="", help="Activation code issued by CA for this HSM")
    parser.add_argument("--hsm-id", default="", help="Expected HSM ID (optional but recommended)")
    args = parser.parse_args()

    print(f"[RegSmoke] Starting registration smoke test against CA: {ca_sync_handler.CA_API_URL}")
    print(f"[RegSmoke] Email: {args.email}")
    if args.hsm_id:
        print(f"[RegSmoke] HSM ID: {args.hsm_id}")
    if args.activation_code:
        print(f"[RegSmoke] Activation code provided: yes")

    # Run the real registration function (it performs activation itself)
    try:
        ok, msg = register_new_user(
            email=args.email,
            full_name=args.full_name,
            activation_code=args.activation_code,
            pin=args.pin,
            expected_hsm_id=(args.hsm_id or None),
        )
        print(f"[RegSmoke] register_new_user: {'OK' if ok else 'FAIL'} - {msg}")
    except Exception as ex:
        print(f"[RegSmoke] register_new_user: EXCEPTION - {ex}")
