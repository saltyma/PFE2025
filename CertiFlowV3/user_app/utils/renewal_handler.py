# user_app/utils/renewal_handler.py
# CertiFlow V3 — Certificate renewal with same on-device key (COM HSM + PIN)

from __future__ import annotations

from typing import Tuple, Optional
import base64
import binascii

# --- App Imports ---
import db_helper
from utils import hsm_handler, certificate, ca_sync_handler, logging_handler
from utils.logging_handler import LogAction


def _connect_and_unlock(email: str, pin: str) -> tuple[hsm_handler.HSMClient | None, str | None, str | None]:
    """
    Locate the user's expected HSM by email, connect over COM, and unlock with PIN.
    Returns (client, hsm_id, error). Caller must close the client.
    """
    if not pin:
        return None, None, "HSM PIN is required."

    user = db_helper.get_user(email)
    if not user or not user.get("hsm_id"):
        return None, None, "No local HSM record for this user. Please log in again."

    expected_hsm_id = user["hsm_id"]
    client = hsm_handler.HSMClient()
    hsm_id, err = client.detect_and_connect(expected_hsm_id=expected_hsm_id)
    if err or not hsm_id:
        client.close()
        return None, None, "The required HSM device is not connected."

    mode, unlock_err = client.unlock(pin)
    if unlock_err:
        client.close()
        return None, None, f"HSM unlock failed: {unlock_err}"

    logging_handler.log(LogAction.HSM_UNLOCKED, {"mode": mode, "hsm_id": hsm_id, "email": email})
    return client, hsm_id, None


def request_certificate_renewal(user_data: dict, hsm_password: str) -> Tuple[bool, str]:
    """
    Renew the user's certificate using the same ECC P-256 key stored on the HSM.

    Steps:
      1) UNLOCK the HSM with the user's PIN
      2) Fetch SPKI via PUBKEY (same key)
      3) Build PKCS#10 CSR with SAN=email and custom HSMID OID
      4) Submit renewal CSR to CA
    """
    email = user_data.get("email")
    # Prefer CN from current certificate details; fallback to email if missing
    full_name = (
        user_data.get("certificate_details", {})
        .get("subject", {})
        .get("commonName")
        or email
        or "User"
    )

    if not email:
        return False, "Missing user email."

    logging_handler.log(LogAction.CERT_RENEWAL_REQUESTED, {"email": email, "name": full_name})

    # 1) Connect and unlock
    client, hsm_id, err = _connect_and_unlock(email, hsm_password)
    if err:
        logging_handler.log(LogAction.HSM_REMOVED, {"reason": err, "email": email})
        return False, err

    try:
        # 2) Ensure key exists (if device was reset, KEYGEN will recreate)
        mode, keygen_err = client.keygen_ec_p256()
        if keygen_err:
            logging_handler.log(LogAction.KEY_PAIR_LOAD_FAILURE, {"reason": keygen_err, "email": email})
            return False, f"Failed to prepare key on HSM: {keygen_err}"
        if mode == "KEYGEN":
            logging_handler.log(LogAction.KEY_PAIR_GENERATED, {"email": email, "hsm_id": hsm_id})
        else:
            logging_handler.log(LogAction.KEY_PAIR_LOADED, {"email": email, "hsm_id": hsm_id})

        # 3) Fetch SPKI (base64 DER) of the existing key
        spki_b64, pk_err = client.pubkey_spki_b64()
        if pk_err or not spki_b64:
            logging_handler.log(LogAction.KEY_PAIR_LOAD_FAILURE, {"reason": pk_err or "No PUBKEY", "email": email})
            return False, f"Failed to fetch public key from HSM: {pk_err or 'unknown error'}"

        # 4) Build CSR with SAN=email and custom HSMID OID, sign via HSM
        def _sign_cb(digest: bytes):
            if not digest or len(digest) != 32:
                return None, "Invalid digest length for SHA-256."
            hex_digest = binascii.hexlify(digest).decode("ascii")
            sig_b64, sig_err = client.sign_sha256_hex(hex_digest)
            if sig_err:
                return None, sig_err
            try:
                return base64.b64decode(sig_b64), None
            except Exception as e:
                return None, f"Failed to decode HSM signature: {e}"

        csr_pem, csr_err = certificate.build_csr_pem_with_hsm_sign(
            email=email,
            common_name=full_name,
            hsm_id=hsm_id or "",
            spki_b64=spki_b64,
            sign_digest_cb=_sign_cb,
        )
        if csr_err or not csr_pem:
            logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"CSR build failed: {csr_err}", "email": email})
            return False, f"CSR build failed: {csr_err}"

        logging_handler.log(LogAction.CSR_CREATED, {"reason": "Renewal", "email": email})

        # 5) Submit renewal request to CA (legacy endpoint kept server-side)
        ok, msg = ca_sync_handler.request_renewal(email, csr_pem, hsm_id=hsm_id)
        if not ok:
            logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"CA sync for renewal failed: {msg}", "email": email})
            return False, f"Failed to submit renewal request to CA: {msg}"

        logging_handler.log(LogAction.CERT_REQUEST_SENT, {"reason": "Renewal", "email": email})
        return True, "Renewal request submitted. Please wait for CA approval."

    finally:
        try:
            client.logout()
        except Exception:
            pass
        client.close()
